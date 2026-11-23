//! Detached, one-shot runner. It is the only process that signals a job.

use std::io::{self, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::Signal;
use serde::{Deserialize, Serialize};

use mcp_gateway::security::audit::{AuditAction, AuditLimits, AuditPhase, AuditSink};

use super::config::{Profile, RootIdentity, restrict_child_privileges};
use super::logs::{Log, nonblocking};
use super::process::{self, Identity, OwnedProcess, TERM_GRACE, TICK};
use super::receipt::{Receipt, State};
use super::store::{JobDir, Store};
use super::{invalid, record};

pub(super) const WIRE_LIMIT: u64 = 65_536;
const CANCEL_POLL: Duration = Duration::from_millis(40);

#[derive(Deserialize, Serialize)]
pub(super) struct Launch {
    pub store: PathBuf,
    pub audit: PathBuf,
    pub audit_limits: AuditLimits,
    pub audit_id: [u64; 4],
    pub root: RootIdentity,
    pub profile: Profile,
    pub job_id: String,
    pub nonce: String,
    pub scoped: bool,
    pub yolo: bool,
    pub isolated: bool,
    pub broad: Option<super::broad::Broad>,
    pub sandbox_roots: Vec<RootIdentity>,
}

pub(crate) fn run_worker() -> io::Result<()> {
    super::sandbox::check_inherited_fds()?;
    process::prepare_worker()?;
    restrict_child_privileges()?;
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(WIRE_LIMIT + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > WIRE_LIMIT {
        return Err(invalid());
    }
    let launch: Launch = serde_json::from_slice(&input)?;
    launch.profile.check_limits()?;
    let store = Store::open(&launch.store, false)?;
    let job = store.job(&launch.job_id)?;
    job.check_worker_lease(io::stdout())?;
    let mut audit = AuditSink::open_with_limits(&launch.audit, launch.audit_limits)?;
    if audit.identity()? != launch.audit_id {
        return Err(invalid());
    }

    let (mut stdout_log, mut stderr_log, spawned) = {
        let _transaction = store.lock(false)?;
        let mut receipt = job.read()?;
        if receipt.state != State::Starting
            || receipt.runner.is_some()
            || receipt.launch_nonce != launch.nonce
            || receipt.root != launch.root.path()
            || receipt.cwd != launch.root.path()
            || receipt.argv_sha256 != launch.profile.argv_hash()
            || receipt.timeout_seconds != launch.profile.timeout_seconds
            || receipt.max_output_bytes != launch.profile.max_output_bytes
            || receipt.yolo != launch.yolo
            || receipt.isolated != launch.isolated
            || receipt.broad != launch.broad
            || receipt.sandbox_roots != launch.sandbox_roots
        {
            return Err(invalid());
        }
        if receipt.cancel_requested {
            return finish(&job, &mut audit, receipt, State::Cancelled);
        }
        if launch.scoped && super::resources::verify(&launch.job_id).is_err() {
            return finish(&job, &mut audit, receipt, State::Failed);
        }

        let cwd = launch.root.handle()?;
        // This is a one-job process. Changing its own cwd by handle lets the
        // workload inherit the checked directory without resolving its path.
        rustix::process::fchdir(&cwd)?;
        let stdout = Log::open(&job, "stdout.log", receipt.max_output_bytes)?;
        let stderr = Log::open(&job, "stderr.log", receipt.max_output_bytes)?;
        receipt.runner = Some(Identity::capture(std::process::id())?);
        receipt.resource_ceilings_enforced = launch.scoped;
        job.save(&receipt)?;
        audit.check_binding()?;

        let start = Instant::now();
        let mut sandbox;
        let mut standard;
        let command = if let Some(broad) = &launch.broad {
            if !launch.isolated || receipt.full {
                return finish(&job, &mut audit, receipt, State::Failed);
            }
            sandbox = match broad.command(
                launch.root.path(),
                &launch.profile.executable,
                &launch.profile.args,
                true,
            ) {
                Ok(sandbox) => sandbox,
                Err(_) => return finish(&job, &mut audit, receipt, State::Failed),
            };
            &mut sandbox.command
        } else if launch.isolated {
            sandbox = match super::sandbox::Sandbox::for_job(
                &launch.root,
                &cwd,
                &launch.sandbox_roots,
                &launch.profile.executable,
                &launch.profile.args,
            ) {
                Ok(sandbox) => sandbox,
                Err(_) => return finish(&job, &mut audit, receipt, State::Failed),
            };
            &mut sandbox.command
        } else {
            standard = Command::new(&launch.profile.executable);
            standard
                .args(&launch.profile.args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LC_ALL", "C");
            &mut standard
        };
        let mut child = match command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return finish(&job, &mut audit, receipt, State::Failed),
        };
        let pid = child.id();
        let stdout_pipe = child.stdout.take().expect("runner requested stdout pipe");
        let stderr_pipe = child.stderr.take().expect("runner requested stderr pipe");
        let process = OwnedProcess::new(child);
        receipt.child = Some(Identity::capture(pid)?);
        receipt.state = State::Running;
        job.save(&receipt)?;
        (stdout, stderr, (process, stdout_pipe, stderr_pipe, start))
    };

    let (mut process, mut stdout, mut stderr, start) = spawned;
    let outcome = supervise(
        &job,
        &audit,
        &mut process,
        (&mut stdout_log, &mut stdout),
        (&mut stderr_log, &mut stderr),
        start + Duration::from_secs(launch.profile.timeout_seconds),
    );
    drop(process);
    let stdout_synced = stdout_log.sync();
    let stderr_synced = stderr_log.sync();
    let _transaction = store.lock(false)?;
    let mut receipt = job.read()?;
    let state = match outcome {
        Ok((state, status)) if stdout_synced.is_ok() && stderr_synced.is_ok() => {
            receipt.exit_code = status.code();
            receipt.signal = status.signal();
            state
        }
        _ => State::Uncertain,
    };
    receipt.stdout_truncated = stdout_log.truncated;
    receipt.stderr_truncated = stderr_log.truncated;
    receipt.stdout_bytes = stdout_log.retained_bytes(receipt.max_output_bytes);
    receipt.stderr_bytes = stderr_log.retained_bytes(receipt.max_output_bytes);
    finish(&job, &mut audit, receipt, state)
}

fn supervise(
    job: &JobDir<'_>,
    audit: &AuditSink,
    child: &mut OwnedProcess,
    (stdout_log, stdout): (&mut Log, &mut std::process::ChildStdout),
    (stderr_log, stderr): (&mut Log, &mut std::process::ChildStderr),
    deadline: Instant,
) -> io::Result<(State, std::process::ExitStatus)> {
    nonblocking(&*stdout)?;
    nonblocking(&*stderr)?;
    let mut cancel_poll = Instant::now();
    let mut stop = None;
    let mut killed = false;
    let mut status = None;
    loop {
        let stdout_progress = stdout_log.drain(stdout)?;
        let stderr_progress = stderr_log.drain(stderr)?;
        let now = Instant::now();
        if stop.is_none() {
            let check_cancel = now >= cancel_poll;
            let state = if check_cancel && job.read()?.cancel_requested {
                Some(State::Cancelled)
            } else if now >= deadline {
                Some(State::TimedOut)
            } else if child.leader_exited()? {
                Some(State::Exited)
            } else {
                None
            };
            if check_cancel {
                audit.check_binding()?;
                cancel_poll = now + CANCEL_POLL;
            }
            if let Some(state) = state {
                // Clean up descendants even when the main process exits on its own.
                child.signal_group(Signal::TERM)?;
                stop = Some((state, now + TERM_GRACE));
            }
        }
        if let Some((state, kill_at)) = stop
            && now >= kill_at
        {
            if !killed {
                child.signal_group(Signal::KILL)?;
                killed = true;
            }
            if status.is_none() {
                status = child.reap()?;
                if status.is_some() {
                    process::clean_adopted_children()?;
                }
            }
            if let Some(status) = status
                && stdout_log.ended
                && stderr_log.ended
            {
                return Ok((state, status));
            }
            if now >= kill_at + process::KILL_GRACE {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "job group did not close",
                ));
            }
        }
        if !stdout_progress && !stderr_progress {
            thread::sleep(TICK);
        }
    }
}

fn finish(
    job: &JobDir<'_>,
    audit: &mut AuditSink,
    mut receipt: Receipt,
    state: State,
) -> io::Result<()> {
    if receipt.cancel_requested {
        let phase = if state == State::Cancelled {
            AuditPhase::Success
        } else {
            AuditPhase::Uncertain
        };
        record(audit, &receipt, AuditAction::JobCancel, phase)?;
    }
    let phase = match state {
        State::Exited if receipt.exit_code == Some(0) => AuditPhase::Success,
        State::Uncertain => AuditPhase::Uncertain,
        _ => AuditPhase::Failure,
    };
    receipt.state = state;
    record(audit, &receipt, AuditAction::JobStart, phase)?;
    job.save(&receipt)
}
