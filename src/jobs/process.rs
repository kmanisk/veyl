//! Process identity and signaling for a single runner's owned children.

use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fd::AsFd;
use rustix::io::Errno;
use rustix::process::{self, Pid, PidfdFlags, Signal, WaitId, WaitIdOptions, WaitOptions, waitid};
use serde::{Deserialize, Serialize};

use super::invalid;

pub(super) const TICK: Duration = Duration::from_millis(15);
pub(super) const TERM_GRACE: Duration = Duration::from_millis(150);
pub(super) const KILL_GRACE: Duration = Duration::from_millis(500);
const OBSERVE_EXIT: WaitIdOptions = WaitIdOptions::EXITED
    .union(WaitIdOptions::NOHANG)
    .union(WaitIdOptions::NOWAIT);

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Identity {
    pid: u32,
    start_ticks: u64,
    namespace: [u64; 2],
    boot_id: String,
}

#[derive(PartialEq, Eq)]
pub(super) enum Presence {
    Present,
    Absent,
    Unknown,
}

impl Identity {
    pub fn capture(pid: u32) -> io::Result<Self> {
        let (start_ticks, _) = proc_stat(pid)?;
        let (namespace, boot_id) = observation_domain()?;
        Ok(Self {
            pid,
            start_ticks,
            namespace,
            boot_id,
        })
    }

    pub fn presence(&self) -> Presence {
        let Ok((namespace, boot_id)) = observation_domain() else {
            return Presence::Unknown;
        };
        if self.boot_id != boot_id {
            return Presence::Absent;
        }
        if self.namespace != namespace {
            return Presence::Unknown;
        }
        match proc_stat(self.pid) {
            Ok((ticks, state)) if ticks == self.start_ticks && state != "Z" && state != "X" => {
                Presence::Present
            }
            Ok(_) => Presence::Absent,
            Err(error) if error.kind() == ErrorKind::NotFound => Presence::Absent,
            Err(_) => Presence::Unknown,
        }
    }
}

fn observation_domain() -> io::Result<([u64; 2], String)> {
    let ns = fs::metadata("/proc/self/ns/pid")?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    Ok(([ns.dev(), ns.ino()], boot_id.trim().to_owned()))
}

fn proc_stat(pid: u32) -> io::Result<(u64, String)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // comm can contain spaces and parentheses. The final ')' ends comm.
    let (_, fields) = stat.rsplit_once(')').ok_or_else(invalid)?;
    let mut fields = fields.split_whitespace();
    let state = fields.next().ok_or_else(invalid)?;
    let ticks = fields
        .nth(18)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    Ok((ticks, state.to_owned()))
}

pub(super) struct OwnedProcess {
    child: Child,
    group: Pid,
    reaped: bool,
}

impl OwnedProcess {
    pub fn new(child: Child) -> Self {
        let group = Pid::from_child(&child);
        Self {
            child,
            group,
            reaped: false,
        }
    }

    pub fn leader_exited(&self) -> io::Result<bool> {
        Ok(waitid(WaitId::Pid(self.group), OBSERVE_EXIT)?.is_some())
    }

    pub fn signal_group(&self, signal: Signal) -> io::Result<()> {
        // WNOWAIT verifies direct parentage and keeps the leader's numeric
        // PID reserved even when it is a zombie. Only this runner reaps it.
        self.leader_exited()?;
        match process::kill_process_group(self.group, signal) {
            Ok(()) | Err(Errno::SRCH) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn reap(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        self.reaped = status.is_some();
        Ok(status)
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.reaped && self.signal_group(Signal::KILL).is_ok() {
            let deadline = Instant::now() + KILL_GRACE;
            while Instant::now() < deadline && matches!(self.reap(), Ok(None)) {
                thread::sleep(TICK);
            }
        }
        if self.reaped {
            let _ = clean_adopted_children();
        }
    }
}

pub(super) fn prepare_worker() -> io::Result<()> {
    // SIG_IGN for SIGCHLD survives exec on Linux and would let the kernel
    // reap a child before we finished signaling its group.
    let status = fs::read_to_string("/proc/self/status")?;
    let ignored = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
        .ok_or_else(invalid)?;
    if ignored & (1_u64 << (Signal::CHILD.as_raw() - 1)) != 0 {
        return Err(invalid());
    }
    process::setsid()?;
    process::set_child_subreaper(Some(process::getpid()))?;
    process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    Ok(())
}

/// After the group leader has been reaped, collect descendants reparented
/// to this subreaper, including children that made their own process group.
pub(super) fn clean_adopted_children() -> io::Result<()> {
    let deadline = Instant::now() + KILL_GRACE;
    loop {
        match process::wait(WaitOptions::NOHANG) {
            Err(Errno::CHILD) => return Ok(()),
            Err(Errno::INTR) | Ok(Some(_)) => (),
            Err(error) => return Err(error.into()),
            Ok(None) => {
                signal_adopted(Signal::KILL)?;
                thread::sleep(TICK);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "job children not reaped",
            ));
        }
    }
}

fn signal_adopted(signal: Signal) -> io::Result<()> {
    let children = fs::read_to_string("/proc/thread-self/children")?;
    for field in children.split_whitespace() {
        let pid = field
            .parse()
            .ok()
            .and_then(Pid::from_raw)
            .ok_or_else(invalid)?;
        let pidfd = match process::pidfd_open(pid, PidfdFlags::empty()) {
            Ok(fd) => fd,
            Err(Errno::SRCH) => continue,
            Err(error) => return Err(error.into()),
        };
        match waitid(WaitId::PidFd(pidfd.as_fd()), OBSERVE_EXIT) {
            Ok(None) => match process::pidfd_send_signal(&pidfd, signal) {
                Ok(()) | Err(Errno::SRCH) => (),
                Err(error) => return Err(error.into()),
            },
            Ok(Some(_)) | Err(Errno::CHILD) => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity_rejects_pid_reuse_and_changed_boot() {
        let mut identity = Identity::capture(std::process::id()).unwrap();
        assert!(identity.presence() == Presence::Present);
        identity.start_ticks += 1;
        assert!(identity.presence() == Presence::Absent);
        identity.namespace[1] ^= 1;
        assert!(identity.presence() == Presence::Unknown);
        identity.boot_id.push('!');
        assert!(identity.presence() == Presence::Absent);
    }
}
