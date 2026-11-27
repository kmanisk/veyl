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
use super::session::{
    Binding,
    channel::{Channel, Input},
    terminal::{SETSID, Terminal},
};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<super::session::OAuthBinding>,
    pub scoped: bool,
    #[serde(default)]
    pub native_home: Option<PathBuf>,
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
        launch.profile.check_limits(receipt.full)?;
        if receipt.state != State::Starting
            || receipt.runner.is_some()
            || receipt.launch_nonce != launch.nonce
            || receipt.session != launch.session
            || receipt.oauth != launch.oauth
            || launch.session.is_some() != launch.profile.interactive
            || launch.session.as_ref().is_some_and(|session| {
                session.pty != launch.profile.pty || session.root != launch.root
            })
            || (launch.session.is_some() && !receipt.full && (!launch.isolated || !launch.scoped))
            || if receipt.ephemeral_worktree {
                receipt.worktree_path.as_deref() != Some(launch.root.path())
                    || receipt.worktree_repo.is_none()
                    || receipt.worktree_cleaned != Some(false)
            } else {
                receipt.root != launch.root.path() || receipt.cwd != launch.root.path()
            }
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
        if (!receipt.full && (launch.profile.timeout_seconds == 0
            || launch.profile.cpu_percent == 0 || launch.profile.memory_bytes == 0
            || launch.profile.timeout_seconds > super::config::SHORT_RUNTIME_MAX && !launch.scoped))
            || (receipt.full && ((launch.profile.cpu_percent != 0 || launch.profile.memory_bytes != 0) && !launch.scoped))
        {
            return Err(invalid());
        }
        if receipt.cancel_requested {
            return finish(&job, &mut audit, receipt, State::Cancelled);
        }
        if launch.scoped
            && super::resources::verify(
                &launch.job_id,
                launch.profile.cpu_percent,
                launch.profile.memory_bytes,
            )
            .is_err()
        {
            return finish(&job, &mut audit, receipt, State::Failed);
        }

        let cwd = launch.root.handle()?;
        if receipt.oauth_bounded_workspace && (!receipt.oauth_family
            || mcp_gateway::security::linux_fs::bounded_oauth_workspace(launch.root.path()).is_err())
        {
            return finish(&job, &mut audit, receipt, State::Failed);
        }
        if receipt.oauth_family {
            let oauth_yolo = receipt.full
                && !receipt.oauth_bounded_workspace
                && launch.oauth.is_some();
            let oauth_standard = !receipt.full && !launch.yolo && launch.broad.is_none();
            let interactive_valid = launch.profile.interactive
                && launch
                    .session
                    .as_ref()
                    .and_then(|session| session.oauth.as_ref())
                    .is_some_and(|oauth| {
                        super::session::verify_oauth_grant_mode(oauth, oauth_yolo).is_ok()
                    });
            if !super::oauth_owner(&receipt.client_id)
                || (!oauth_yolo && (!launch.isolated || !launch.scoped))
                || !(oauth_yolo || oauth_standard)
                || !launch.sandbox_roots.is_empty()
                || (!oauth_yolo && (launch.profile.extended_runtime
                    || launch.profile.timeout_seconds > super::config::SHORT_RUNTIME_MAX
                    || launch.profile.cpu_percent > 100
                    || launch.profile.memory_bytes > super::config::default_memory()
                    || launch.profile.max_output_bytes > super::config::MAX_OUTPUT))
                || (!interactive_valid
                    && (launch.profile.interactive
                        || launch.profile.pty
                        || launch.session.is_some()))
                || (!oauth_yolo && super::sandbox::verify_oauth_workspace(&cwd).is_err())
                || (oauth_yolo
                    && launch.oauth.as_ref().is_none_or(|oauth| {
                        super::session::verify_oauth_grant_mode(oauth, true).is_err()
                    }))
            {
                return finish(&job, &mut audit, receipt, State::Failed);
            }
        } else if launch
            .session
            .as_ref()
            .is_some_and(|session| session.oauth.is_some())
            || launch.oauth.is_some()
        {
            return finish(&job, &mut audit, receipt, State::Failed);
        }
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
        receipt.elapsed_clock = process::ElapsedClock::capture();
        let pty_args;
        let (executable, args) = if launch.profile.pty {
            pty_args = ["--ctty", "--wait", "--", &launch.profile.executable]
                .into_iter()
                .map(str::to_owned)
                .chain(launch.profile.args.iter().cloned())
                .collect::<Vec<_>>();
            (SETSID, &pty_args)
        } else {
            (launch.profile.executable.as_str(), &launch.profile.args)
        };
        let mut sandbox;
        let mut standard;
        let command = if let Some(broad) = &launch.broad {
            if !launch.isolated || receipt.full {
                return finish(&job, &mut audit, receipt, State::Failed);
            }
            let workspace = rustix::fs::fstat(&cwd)?;
            sandbox = match broad.command(
                launch.root.path(),
                [workspace.st_dev, workspace.st_ino],
                executable,
                args,
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
                executable,
                args,
            ) {
                Ok(sandbox) => sandbox,
                Err(_) => return finish(&job, &mut audit, receipt, State::Failed),
            };
            &mut sandbox.command
        } else {
            standard = Command::new(executable);
            standard
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LC_ALL", "C");
            if let Some(home) = launch.native_home.as_ref().filter(|_| receipt.full) {
                standard.env("HOME", home).env("PATH", format!("{}/.local/bin:{}/.cargo/bin:/usr/local/bin:/usr/bin:/bin", home.display(), home.display()));
            }
            &mut standard
        };
        let terminal = if launch.profile.pty {
            match Terminal::attach(command) {
                Ok(terminal) => Some(terminal),
                Err(_) => return finish(&job, &mut audit, receipt, State::Failed),
            }
        } else {
            command
                .stdin(if launch.session.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            None
        };
        // Revalidate the original signed admission immediately before spawning.
        // Hold the native policy lock through spawn so cooperating local policy
        // changes cannot race this boundary. The durable OAuth shared guard
        // also stays held through spawn, ordering admission before revocation.
        let launch_guards = if receipt.oauth_family && launch.profile.interactive {
            let Some(binding) = launch.session.as_ref() else {
                return finish(&job, &mut audit, receipt, State::Failed);
            };
            let Some(authority) = receipt.oauth_launch.as_ref() else {
                return finish(&job, &mut audit, receipt, State::Failed);
            };
            let Ok(guard) = authority.policy_guard(&binding.config) else {
                return finish(&job, &mut audit, receipt, State::Failed);
            };
            let Some(oauth) = binding.oauth.as_ref() else {
                return finish(&job, &mut audit, receipt, State::Failed);
            };
            let Ok(grant_guard) = super::session::verify_oauth_grant_mode(oauth, receipt.full) else {
                return finish(&job, &mut audit, receipt, State::Failed);
            };
            // The durable read can take time; check the original deadline again.
            if authority.expired() {
                return finish(&job, &mut audit, receipt, State::Failed);
            }
            Some((Some(guard), grant_guard))
        } else if receipt.oauth_family && receipt.full {
            if receipt.oauth_launch.is_some() {
                return finish(&job, &mut audit, receipt, State::Failed);
            }
            let Some(oauth) = launch.oauth.as_ref() else {
                return finish(&job, &mut audit, receipt, State::Failed);
            };
            let Ok(grant_guard) = super::session::verify_oauth_grant_mode(oauth, true) else {
                return finish(&job, &mut audit, receipt, State::Failed);
            };
            Some((None, grant_guard))
        } else {
            if receipt.oauth_launch.is_some() {
                return finish(&job, &mut audit, receipt, State::Failed);
            }
            None
        };
        let native_guard = if let Some(authority) = receipt.native_authority.as_ref() {
            match authority.guard(&receipt.client_id) {
                Ok(guard) => Some(guard),
                Err(_) => return finish(&job, &mut audit, receipt, State::Failed),
            }
        } else {
            None
        };
        let mut child = match command.process_group(0).spawn() {
            Ok(child) => child,
            Err(_) => return finish(&job, &mut audit, receipt, State::Failed),
        };
        drop((launch_guards, native_guard));
        let pid = child.id();
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let stdin = terminal
            .map(Input::Pty)
            .or_else(|| child.stdin.take().map(Input::Pipe));
        let process = OwnedProcess::new(child);
        let channel = match stdin {
            Some(stdin) => Some(Channel::open(store.input_key(&receipt), stdin)?),
            None => None,
        };
        receipt.child = Some(Identity::capture(pid)?);
        receipt.state = State::Running;
        job.save(&receipt)?;
        (
            stdout,
            stderr,
            (process, stdout_pipe, stderr_pipe, start, channel, receipt),
        )
    };

    let (mut process, mut stdout, mut stderr, start, channel, admitted) = spawned;
    let outcome = supervise(
        &job,
        &audit,
        &mut process,
        (&mut stdout_log, &mut stdout),
        (&mut stderr_log, &mut stderr),
        (launch.profile.timeout_seconds != 0).then(|| start + Duration::from_secs(launch.profile.timeout_seconds)),
        channel.zip(launch.session.as_ref()),
        || admitted.native_authority.as_ref().is_none_or(|authority| authority.guard(&admitted.client_id).is_ok())
            && (!admitted.full || !admitted.oauth_family || admitted.oauth.as_ref()
                .is_some_and(|oauth| super::session::verify_oauth_grant_mode(oauth, true).is_ok())),

    );
    let supervision_ms = start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    drop(process);
    let stdout_synced = stdout_log.sync();
    let stderr_synced = stderr_log.sync();
    let _transaction = store.lock(false)?;
    let mut receipt = job.read()?;
    let state = match outcome {
        Ok((state, status)) if stdout_synced.is_ok() && stderr_synced.is_ok() => {
            receipt.execution_duration_ms = Some(supervision_ms);
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

#[allow(clippy::too_many_arguments)]
fn supervise(
    job: &JobDir<'_>,
    audit: &AuditSink,
    child: &mut OwnedProcess,
    (stdout_log, stdout): (&mut Log, &mut Option<std::process::ChildStdout>),
    (stderr_log, stderr): (&mut Log, &mut Option<std::process::ChildStderr>),
    deadline: Option<Instant>,
    mut input: Option<(Channel, &super::session::Binding)>,
    authorized: impl Fn() -> bool,
) -> io::Result<(State, std::process::ExitStatus)> {
    if let Some(pipe) = stdout.as_ref() {
        nonblocking(pipe)?;
    }
    if let Some(pipe) = stderr.as_ref() {
        nonblocking(pipe)?;
    } else {
        stderr_log.ended = true;
    }
    let mut cancel_poll = Instant::now();
    let mut authorization_poll = cancel_poll + Duration::from_secs(1);
    let mut consecutive_denials = 0;
    let mut stop = None;
    let mut killed = false;
    let mut status = None;
    loop {
        let stdout_progress = if let Some(pipe) = stdout {
            stdout_log.drain(pipe)?
        } else {
            input
                .as_mut()
                .ok_or_else(invalid)?
                .0
                .drain_terminal(stdout_log)?
        };
        let stderr_progress = if let Some(pipe) = stderr {
            stderr_log.drain(pipe)?
        } else {
            false
        };
        let now = Instant::now();
        if stop.is_none() {
            let check_cancel = now >= cancel_poll;
            let revoked = now >= authorization_poll && {
                authorization_poll = now + Duration::from_secs(1);
                // A local writer can temporarily hold the policy lock. Retry
                // at the next bounded check before stopping an existing job.
                consecutive_denials = if authorized() { 0 } else { consecutive_denials + 1 };
                consecutive_denials >= 2
            };
            let state = if revoked || check_cancel && job.read()?.cancel_requested {
                Some(State::Cancelled)
            } else if deadline.is_some_and(|deadline| now >= deadline) {
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
        if stop.is_none()
            && let Some((channel, session)) = &mut input
        {
            channel.step(&session.config, session.oauth.as_ref())?;
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
