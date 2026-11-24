//! Bounded synchronous execution of a fixed, locally chosen program.

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    process::{Pid, Signal, kill_process_group},
};
use std::{
    io::{self, Read},
    os::unix::process::CommandExt,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) fn capture(
    command: &mut Command,
    limit: usize,
    timeout: Duration,
) -> io::Result<(ExitStatus, Vec<u8>)> {
    let deadline = Instant::now() + timeout;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let mut pipe = child.stdout.take().expect("piped stdout");
    let result = (|| {
        fcntl_setfl(&pipe, fcntl_getfl(&pipe)? | OFlags::NONBLOCK)?;
        let mut output = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) if n > limit.saturating_sub(output.len()) => {
                    return Err(io::Error::other("Command output exceeded limit"));
                }
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut fds = [PollFd::new(&pipe, PollFlags::IN)];
                    poll(
                        &mut fds,
                        Some(&Timespec {
                            tv_sec: remaining.as_secs() as i64,
                            tv_nsec: remaining.subsec_nanos().into(),
                        }),
                    )?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error),
            }
        }
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok((status, output));
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        if let Some(pid) = Pid::from_raw(child.id() as i32) {
            let _ = kill_process_group(pid, Signal::KILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

