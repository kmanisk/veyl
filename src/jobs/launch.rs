//! Serializes job admission and hands a signed starting record to the runner.

use std::io::{self, ErrorKind, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use mcp_gateway::security::audit::{AuditAction, AuditPhase};

use super::config::Profile;
use super::receipt::{Receipt, State};
use super::resources::Scopes;
use super::runner::{Launch, WIRE_LIMIT};
use super::store::HISTORY_LIMIT;
use super::{JobPolicy, JobRoot, Jobs, invalid, logs, now, process, random_hex, record};

const GLOBAL_JOBS: usize = 8;
const CLIENT_JOBS: usize = 5;

impl Jobs {
    pub(super) fn start(
        &self,
        owner: &str,
        root: &JobRoot,
        name: String,
        profile: Profile,
        policy: JobPolicy<'_>,
    ) -> io::Result<Receipt> {
        super::sandbox::check_inherited_fds()?;
        let sandbox_roots = policy
            .workspace_mounts
            .unwrap_or_default()
            .iter()
            .map(|root| root.identity().clone())
            .collect::<Vec<_>>();
        for root in &sandbox_roots {
            root.handle()?;
        }
        if policy.workspace_mounts.is_some() {
            super::sandbox::probe()?;
            super::sandbox::validate_executable(&profile.executable)?;
        }
        let root = root.identity();
        root.handle()?;
        let _transaction = self.store.lock(false)?;
        let ids = self.store.jobs()?;
        if ids.len() >= HISTORY_LIMIT {
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        let mut global = 0;
        let mut owned = 0;
        for id in ids {
            if let Some(receipt) = self.read_if_published(&self.store.job(&id)?)?
                && (receipt.state.active() || receipt.state == State::Uncertain)
            {
                global += 1;
                owned += usize::from(receipt.client_id == owner);
            }
        }
        if global >= GLOBAL_JOBS || owned >= CLIENT_JOBS {
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }

        let job_id = random_hex()?;
        let receipt = Receipt {
            job_id,
            client_id: owner.to_owned(),
            profile: name,
            argv_sha256: profile.argv_hash(),
            root: root.path().to_owned(),
            cwd: root.path().to_owned(),
            timeout_seconds: profile.timeout_seconds,
            max_output_bytes: profile.max_output_bytes,
            state: State::Starting,
            created_at: now(),
            launch_nonce: random_hex()?,
            runner: None,
            child: None,
            cancel_requested: false,
            exit_code: None,
            signal: None,
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_bytes: 0,
            stderr_bytes: 0,
            resource_ceilings_enforced: false,
            yolo: policy.yolo,
            full: policy.full,
            isolated: policy.workspace_mounts.is_some(),
            sandbox_roots: sandbox_roots.clone(),
        };
        let job = self.store.create(&receipt.job_id)?;
        let lease = job.init_files()?;
        let audit_id = {
            let mut audit = self.audit.lock().map_err(|_| invalid())?;
            let id = audit.identity()?;
            record(
                &mut audit,
                &receipt,
                AuditAction::JobStart,
                AuditPhase::Intent,
            )?;
            id
        };
        job.save(&receipt)?;

        let launch = Launch {
            store: self.store.path().to_owned(),
            audit: self.audit_path.clone(),
            audit_limits: self.audit_limits,
            audit_id,
            root: root.clone(),
            profile,
            job_id: receipt.job_id.clone(),
            nonce: receipt.launch_nonce.clone(),
            scoped: self.scopes.is_some(),
            yolo: receipt.yolo,
            isolated: receipt.isolated,
            sandbox_roots,
        };
        if start_runner(launch, lease, self.scopes.as_ref()).is_err() {
            let mut failed = receipt;
            self.reconcile(&job, &mut failed)?;
            return Err(invalid());
        }
        Ok(receipt)
    }
}

fn start_runner(launch: Launch, lease: std::fs::File, scopes: Option<&Scopes>) -> io::Result<()> {
    let message = serde_json::to_vec(&launch)?;
    if message.len() as u64 > WIRE_LIMIT {
        return Err(invalid());
    }
    let mut command = match scopes {
        Some(scopes) => scopes.command(
            &launch.job_id,
            "--job-runner",
            launch.profile.timeout_seconds,
        ),
        None => {
            let mut command = Command::new("/proc/self/exe");
            command.env_clear().arg("--job-runner");
            command
        }
    };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(lease)
        .stderr(Stdio::null())
        .spawn()?;
    drop(command);
    let message_sent = child
        .stdin
        .take()
        .ok_or_else(invalid)
        .and_then(|pipe| send_launch(pipe, &message));
    // Each waiter is tied to one direct, detached runner and ends with it.
    tokio::task::spawn_blocking(move || {
        let _ = child.wait();
    });
    message_sent
}

fn send_launch(mut pipe: std::process::ChildStdin, mut message: &[u8]) -> io::Result<()> {
    logs::nonblocking(&pipe)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    while !message.is_empty() {
        match pipe.write(message) {
            Ok(0) => return Err(io::Error::from(ErrorKind::WriteZero)),
            Ok(written) => message = &message[written..],
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(process::TICK);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted && Instant::now() < deadline => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
