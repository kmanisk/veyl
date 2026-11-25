//! Serializes job admission and hands a signed starting record to the runner.

use std::io::{self, ErrorKind, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use mcp_gateway::security::audit::{AuditAction, AuditPhase};
use sha2::{Digest, Sha256};

use super::config::Profile;
use super::receipt::{Receipt, State};
use super::resources::Scopes;
use super::runner::{Launch, WIRE_LIMIT};
use super::store::HISTORY_LIMIT;
use super::{JobPolicy, JobRoot, Jobs, invalid, logs, now, process, random_hex, record};

const GLOBAL_JOBS: usize = 8;
const CLIENT_JOBS: usize = 5;

impl Jobs {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn start(
        &self,
        owner: &str,
        root: &JobRoot,
        name: String,
        profile: Profile,
        policy: JobPolicy<'_>,
        request_id: Option<&str>,
        worktree_repo: Option<&std::path::Path>,
    ) -> io::Result<(Receipt, bool)> {
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
        if policy.broad.is_some() || policy.workspace_mounts.is_some() {
            super::sandbox::validate_executable(&profile.executable)?;
        }
        let root = root.identity();
        root.handle()?;
        let session = if profile.interactive {
            if self.scopes.is_none()
                || policy.full
                || (policy.broad.is_none() && policy.workspace_mounts.is_none())
            {
                return Err(io::Error::from(ErrorKind::Unsupported));
            }
            Some(super::session::Binding::new(
                policy.session.ok_or_else(invalid)?,
                root,
                profile.pty,
            ))
        } else {
            None
        };
        if let Some(plan) = policy.broad {
            plan.validate()?;
        } else if policy.workspace_mounts.is_some() {
            super::sandbox::probe()?;
        }
        let _transaction = self.store.lock(false)?;
        let ids = self.store.jobs()?;
        let mut history_count = ids.len();
        // Old unsigned mappings cannot prove the admitted request fingerprint.
        // Refuse reuse rather than accidentally launching the old action twice.
        if let Some(id) = request_id
            && self.store.get_request_id(id)?.is_some()
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Legacy request ID cannot be safely replayed; inspect the original job",
            ));
        }
        let request_key = request_id.map(|id| {
            let mut hash = Sha256::new();
            hash.update(owner.as_bytes());
            hash.update([0]);
            hash.update(id.as_bytes());
            format!("{:x}", hash.finalize())
        });
        let mut global = 0;
        let mut owned = 0;
        let mut finalized = Vec::new();
        for id in ids {
            if let Some(receipt) = self.read_if_published(&self.store.job(&id)?)? {
                if request_key.is_some() && receipt.request_key == request_key {
                    if receipt.client_id != owner
                        || receipt.ephemeral_worktree != worktree_repo.is_some()
                        || receipt.profile != name
                        || receipt.argv_sha256 != profile.argv_hash()
                        || receipt.cwd != root.path()
                        || receipt.session != session
                        || receipt.timeout_seconds != profile.timeout_seconds
                        || receipt.max_output_bytes != profile.max_output_bytes
                        || receipt.cpu_percent != profile.cpu_percent
                        || receipt.memory_bytes != profile.memory_bytes
                        || receipt.yolo != policy.yolo
                        || receipt.full != policy.full
                        || receipt.broad.as_ref() != policy.broad
                        || receipt.isolated
                            != (policy.workspace_mounts.is_some() || policy.broad.is_some())
                        || receipt.sandbox_roots != sandbox_roots
                    {
                        return Err(io::Error::new(
                            ErrorKind::InvalidInput,
                            "Request ID already belongs to a different admitted operation",
                        ));
                    }
                    return Ok((receipt, true));
                }
                if receipt.state.active() || receipt.state == State::Uncertain {
                    global += 1;
                    owned += usize::from(receipt.client_id == owner);
                } else if receipt.client_id == owner {
                    finalized.push((receipt.created_at, receipt.job_id));
                }
            }
        }
        if let Some(limit) = policy.job_retention_count {
            finalized.sort_unstable();
            let excess = finalized.len().saturating_sub(limit);
            for (_, id) in finalized.into_iter().take(excess) {
                self.store.remove_finalized(&id)?;
                history_count -= 1;
            }
        }
        if profile.timeout_seconds > policy.job_runtime_limit_seconds {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Requested job exceeds the locally configured client runtime limit",
            ));
        }
        // Longer unattended work needs a manager-side time and resource backstop.
        if profile.timeout_seconds > super::config::SHORT_RUNTIME_MAX
            && (self.scopes.is_none()
                || (!policy.full && policy.broad.is_none() && policy.workspace_mounts.is_none()))
        {
            return Err(io::Error::from(ErrorKind::Unsupported));
        }
        if history_count >= HISTORY_LIMIT || global >= GLOBAL_JOBS || owned >= CLIENT_JOBS {
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }

        let job_id = random_hex()?;
        let mut worktree = worktree_repo
            .map(|repo| super::worktree::Worktree::create(repo, &job_id))
            .transpose()?;
        let worktree_root = worktree
            .as_ref()
            .map(|wt| JobRoot::open(&wt.path).map_err(io::Error::other))
            .transpose()?;
        let execution_root = worktree_root.as_ref().map_or(root, JobRoot::identity);
        let receipt = Receipt {
            job_id,
            client_id: owner.to_owned(),
            profile: name,
            argv_sha256: profile.argv_hash(),
            executable: Some(profile.executable.clone()),
            ephemeral_worktree: worktree.is_some(),
            worktree_repo: worktree.as_ref().map(|wt| wt.repo.clone()),
            worktree_path: worktree.as_ref().map(|wt| wt.path.clone()),
            worktree_cleaned: worktree.as_ref().map(|_| false),
            root: root.path().to_owned(),
            session,
            cwd: root.path().to_owned(),
            timeout_seconds: profile.timeout_seconds,
            max_output_bytes: profile.max_output_bytes,
            cpu_percent: profile.cpu_percent,
            memory_bytes: profile.memory_bytes,
            state: State::Starting,
            created_at: now(),
            execution_duration_ms: None,
            elapsed_clock: None,
            launch_nonce: random_hex()?,
            request_key,
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
            isolated: policy.workspace_mounts.is_some() || policy.broad.is_some(),
            broad: policy.broad.cloned(),
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
        if let Some(wt) = &mut worktree {
            wt.disarm();
        }

        let launch = Launch {
            store: self.store.path().to_owned(),
            audit: self.audit_path.clone(),
            audit_limits: self.audit_limits,
            audit_id,
            root: execution_root.clone(),
            profile,
            job_id: receipt.job_id.clone(),
            nonce: receipt.launch_nonce.clone(),
            session: receipt.session.clone(),
            scoped: self.scopes.is_some(),
            yolo: receipt.yolo,
            isolated: receipt.isolated,
            broad: receipt.broad.clone(),
            sandbox_roots,
        };
        if start_runner(launch, lease, self.scopes.as_ref()).is_err() {
            let mut failed = receipt;
            self.reconcile(&job, &mut failed)?;
            return Err(invalid());
        }
        Ok((receipt, false))
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
            launch.profile.cpu_percent,
            launch.profile.memory_bytes,
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
