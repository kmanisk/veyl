//! Validates tool inputs and returns owner-scoped, bounded responses.

use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use mcp_gateway::security::audit::{AuditAction, AuditPhase, JobAuditInfo};

use crate::tools::registry::{Tool, tool_text};

use super::receipt::Receipt;
use super::store::{JobDir, valid_id};
use super::{
    JobPolicy, JobRoot, Jobs, SHORT_TIMEOUT, invalid, logs, now, process, random_hex, record,
};

const PAGE_SIZE: usize = 40;

impl Jobs {
    pub(crate) fn call(
        &self,
        tool: Tool,
        args: Option<&Value>,
        owner: &str,
        root: &JobRoot,
        policy: JobPolicy<'_>,
    ) -> Value {
        if !self.available() {
            return tool_text(true, "Job audit unavailable");
        }
        let empty = serde_json::Map::new();
        let args = match args {
            None if tool == Tool::ListJobs => &empty,
            Some(Value::Object(args)) => args,
            _ => return tool_text(true, "Expected a job arguments object"),
        };
        let result = match tool {
            Tool::StartJob | Tool::JobStart | Tool::RunCommand => {
                let req_id = args.get("request_id").and_then(Value::as_str);
                if let Some(req_id) = req_id
                    && let Ok(Some(existing_id)) = self.store.get_request_id(req_id)
                    && let Ok(job) = self.store.job(&existing_id)
                    && let Ok(receipt) = self.owned_receipt(&job, owner)
                {
                    let mut status = receipt.status();
                    status["idempotent_replay"] = json!(true);
                    return tool_text(false, &status.to_string());
                }
                let short = tool == Tool::RunCommand;
                let selected = match args.len() {
                    _ if args.contains_key("profile") => {
                        args["profile"].as_str().and_then(|name| {
                            self.profiles
                                .named(name)
                                .map(|profile| (name.to_owned(), profile))
                        })
                    }
                    _ if short && args.contains_key("argv") => {
                        self.profiles.matching(&args["argv"])
                    }
                    _ => return tool_text(true, "Expected exactly one configured job profile"),
                };
                let Some((name, mut profile)) = selected else {
                    return tool_text(true, "Unknown or invalid job profile");
                };
                if short {
                    profile.timeout_seconds = profile.timeout_seconds.min(SHORT_TIMEOUT);
                }
                self.start(owner, root, name, profile, policy)
                    .and_then(|receipt| {
                        if let Some(req_id) = req_id {
                            let _ = self.store.set_request_id(req_id, &receipt.job_id);
                        }
                        if short {
                            self.wait_short(owner, &receipt.job_id)
                        } else {
                            Ok(receipt.status())
                        }
                    })
            }
            Tool::ListJobs => match args.get("cursor") {
                None if args.is_empty() => self.list(owner, ""),
                Some(Value::String(id)) if args.len() == 1 && valid_id(id) => self.list(owner, id),
                _ => return tool_text(true, "Expected an optional job cursor"),
            },
            Tool::JobStatus | Tool::JobLogs | Tool::CancelJob | Tool::JobCancel | Tool::JobWait => {
                let Some(id) = args
                    .get("job_id")
                    .and_then(Value::as_str)
                    .filter(|id| valid_id(id))
                else {
                    return tool_text(true, "Expected exactly one job identifier");
                };
                self.owned_tool(tool, id, owner, args)
            }
            Tool::ExecCommand => {
                let command = args.get("command").and_then(Value::as_str);
                let argv = args.get("argv").and_then(Value::as_array);
                let cwd = args.get("cwd").and_then(Value::as_str);
                let timeout = args
                    .get("timeout_seconds")
                    .and_then(Value::as_u64)
                    .unwrap_or(30)
                    .min(300);
                self.exec_command(owner, root, command, argv, cwd, timeout, policy)
            }
            Tool::TaskRun => {
                let command = args.get("command").and_then(Value::as_str);
                let argv = args.get("argv").and_then(Value::as_array);
                let req_id = args.get("request_id").and_then(Value::as_str);
                let cwd = args.get("cwd").and_then(Value::as_str);
                let ephemeral_worktree = args
                    .get("ephemeral_worktree")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let wait = args
                    .get("wait_seconds")
                    .and_then(Value::as_u64)
                    .unwrap_or(15)
                    .min(60);
                let timeout = args
                    .get("timeout_seconds")
                    .and_then(Value::as_u64)
                    .unwrap_or(120)
                    .min(600);
                self.task_run(
                    owner,
                    root,
                    command,
                    argv,
                    req_id,
                    cwd,
                    ephemeral_worktree,
                    wait,
                    timeout,
                    policy,
                )
            }
            _ => return tool_text(true, "Invalid job tool"),
        };
        match result {
            Ok(value) => tool_text(false, &value.to_string()),
            Err(error) if error.kind() == ErrorKind::NotFound => tool_text(true, "Job not found"),
            Err(error) if error.kind() == ErrorKind::Unsupported => {
                tool_text(true, "Required Linux execution isolation unavailable")
            }
            Err(error) if error.kind() == ErrorKind::PermissionDenied => tool_text(
                true,
                "Job execution denied; verify inherited descriptors and workspace permissions",
            ),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                tool_text(true, "Job capacity reached")
            }
            Err(error) if error.kind() == ErrorKind::TimedOut => {
                tool_text(true, "Execution timed out")
            }
            Err(error) if error.kind() == ErrorKind::InvalidInput => {
                tool_text(true, &format!("Invalid arguments: {error}"))
            }
            Err(_) => tool_text(true, "Job operation unavailable or uncertain"),
        }
    }

    fn wait_short(&self, owner: &str, id: &str) -> io::Result<Value> {
        let receipt = self.wait_for_end(owner, id, Duration::from_secs(SHORT_TIMEOUT + 2))?;
        if receipt.state.active() {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        let mut status = receipt.status();
        status["logs"] = logs::excerpts(&self.store.job(id)?, &receipt)?;
        Ok(status)
    }

    pub(crate) fn owned_tool(
        &self,
        tool: Tool,
        id: &str,
        owner: &str,
        args: &serde_json::Map<String, Value>,
    ) -> io::Result<Value> {
        let _transaction = self.store.lock(false)?;
        let job = self.store.job(id)?;
        let mut receipt = self.owned_receipt(&job, owner)?;
        match tool {
            Tool::JobStatus => Ok(self.present_status(&receipt)),
            Tool::JobLogs => {
                let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let max_bytes = args
                    .get("max_bytes")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize)
                    .unwrap_or(4096);
                if offset > 0 || args.contains_key("max_bytes") {
                    logs::excerpts_offset(&job, &receipt, offset, max_bytes)
                } else {
                    logs::excerpts(&job, &receipt)
                }
            }
            Tool::JobWait => {
                let timeout_secs = args
                    .get("timeout_seconds")
                    .and_then(Value::as_u64)
                    .unwrap_or(10)
                    .min(60);
                drop(_transaction);
                let final_receipt =
                    self.wait_for_end(owner, id, Duration::from_secs(timeout_secs))?;
                Ok(self.present_status(&final_receipt))
            }
            Tool::CancelJob | Tool::JobCancel => {
                if receipt.state.active() && !receipt.cancel_requested {
                    let mut audit = self.audit.lock().map_err(|_| invalid())?;
                    record(
                        &mut audit,
                        &receipt,
                        AuditAction::JobCancel,
                        AuditPhase::Intent,
                    )?;
                    receipt.cancel_requested = true;
                    job.save(&receipt)?;
                }
                if receipt.state.active() {
                    drop(_transaction);
                    return Ok(self
                        .wait_for_end(owner, id, Duration::from_secs(2))?
                        .status());
                }
                Ok(self.present_status(&receipt))
            }
            _ => Err(invalid()),
        }
    }

    fn wait_for_end(&self, owner: &str, id: &str, timeout: Duration) -> io::Result<Receipt> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let _transaction = self.store.lock(false)?;
                let job = self.store.job(id)?;
                let receipt = self.owned_receipt(&job, owner)?;
                if !receipt.state.active() || Instant::now() >= deadline {
                    return Ok(receipt);
                }
            }
            thread::sleep(process::TICK);
        }
    }

    pub(crate) fn list(&self, owner: &str, cursor: &str) -> io::Result<Value> {
        self.list_page(owner, cursor, false)
    }

    pub(crate) fn list_admin(&self, owner: &str, cursor: &str) -> io::Result<Value> {
        self.list_page(owner, cursor, true)
    }

    fn list_page(&self, owner: &str, cursor: &str, admin: bool) -> io::Result<Value> {
        let _transaction = self.store.lock(false)?;
        let mut receipts = Vec::new();
        let mut next = None;
        for id in self
            .store
            .jobs()?
            .into_iter()
            .filter(|id| id.as_str() > cursor)
        {
            let job = self.store.job(&id)?;
            let Some(receipt) = self.read_if_published(&job)? else {
                continue;
            };
            if receipt.client_id != owner {
                continue;
            }
            if receipts.len() == PAGE_SIZE {
                next = receipts
                    .last()
                    .and_then(|receipt: &Value| receipt.get("job_id"))
                    .cloned();
                break;
            }
            let mut status = self.present_status(&receipt);
            if admin {
                status["created_at"] = json!(receipt.created_at);
                status["cwd"] = json!(receipt.cwd);
                status["profile"] = json!(receipt.profile);
                status["client"] = json!(receipt.client_id);
                status["executable"] = json!(receipt.executable);
                status["argv_sha256"] = json!(receipt.argv_sha256);
                status["timeout_seconds"] = json!(receipt.timeout_seconds);
                status["max_output_bytes"] = json!(receipt.max_output_bytes);
            }
            receipts.push(status);
        }
        Ok(json!({"jobs":receipts,"next_cursor":next}))
    }

    fn owned_receipt(&self, job: &JobDir<'_>, owner: &str) -> io::Result<Receipt> {
        let mut receipt = job.read()?;
        if receipt.client_id != owner {
            return Err(io::Error::from(ErrorKind::NotFound));
        }
        self.reconcile(job, &mut receipt)?;
        Ok(receipt)
    }

    /// A detached runner remains responsible for finishing the job after an
    /// HTTP restart. The new HTTP instance must not assert a fresh RUNNING
    /// observation for a job it did not launch. This is a presentation-only
    /// uncertainty marker: the signed receipt stays RUNNING, concurrency
    /// limits still count it, and the runner can publish its real final state.
    fn present_status(&self, receipt: &Receipt) -> Value {
        let mut status = receipt.status();
        if receipt.state.active() && self.recovered.contains(&receipt.job_id) {
            status["state"] = json!("uncertain");
            status["recovery"] =
                json!("detached runner may still be active; awaiting final receipt");
        }
        status
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn exec_command(
        &self,
        owner: &str,
        root: &JobRoot,
        command: Option<&str>,
        argv: Option<&Vec<Value>>,
        cwd: Option<&str>,
        timeout_seconds: u64,
        policy: JobPolicy<'_>,
    ) -> io::Result<Value> {
        let canonical_cwd = resolve_cwd(root, cwd, policy)?;
        let mut cmd = if let Some(argv) = argv {
            let args_str: Vec<String> = argv
                .iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect();
            if args_str.is_empty() {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "argv must not be empty",
                ));
            }
            let mut c = Command::new(&args_str[0]);
            c.args(&args_str[1..]);
            c
        } else if let Some(cmd_str) = command {
            let mut c = Command::new("sh");
            c.arg("-c").arg(cmd_str);
            c
        } else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "command or argv required",
            ));
        };

        cmd.current_dir(&canonical_cwd);

        let argv_repr = format!("{:?}{:?}", command, argv);
        let mut hasher = Sha256::new();
        hasher.update(argv_repr.as_bytes());
        let argv_hash = format!("{:x}", hasher.finalize());

        let eff_mode = if policy.full {
            "full"
        } else if policy.broad.is_some() {
            "broad_yolo"
        } else if policy.yolo {
            "legacy_scoped_yolo"
        } else {
            "standard"
        };

        let max_output = 1024 * 1024;
        let job_id = random_hex().unwrap_or_else(|_| "exec0000000000000000000000000000".into());

        if let Ok(mut audit) = self.audit.lock() {
            let _ = audit.record_job(
                owner,
                AuditAction::JobStart,
                AuditPhase::Intent,
                now(),
                JobAuditInfo {
                    job_id: &job_id,
                    argv_sha256: &argv_hash,
                    cwd: &canonical_cwd,
                    timeout_seconds,
                    max_output_bytes: max_output,
                    state: "intent",
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    yolo: policy.yolo,
                    effective_mode: eff_mode,
                },
            );
        }

        let start = Instant::now();
        let (status, stdout, stderr) = crate::linux_command::capture_both(
            &mut cmd,
            max_output,
            Duration::from_secs(timeout_seconds),
        )?;
        let duration_ms = start.elapsed().as_millis() as u64;

        if let Ok(mut audit) = self.audit.lock() {
            let _ = audit.record_job(
                owner,
                AuditAction::JobStart,
                if status.success() {
                    AuditPhase::Success
                } else {
                    AuditPhase::Failure
                },
                now(),
                JobAuditInfo {
                    job_id: &job_id,
                    argv_sha256: &argv_hash,
                    cwd: &canonical_cwd,
                    timeout_seconds,
                    max_output_bytes: max_output,
                    state: if status.success() {
                        "completed"
                    } else {
                        "failed"
                    },
                    stdout_bytes: stdout.len(),
                    stderr_bytes: stderr.len(),
                    yolo: policy.yolo,
                    effective_mode: eff_mode,
                },
            );
        }

        Ok(json!({
            "exit_code": status.code(),
            "stdout": String::from_utf8_lossy(&stdout),
            "stderr": String::from_utf8_lossy(&stderr),
            "duration_ms": duration_ms,
            "truncated": stdout.len() >= max_output || stderr.len() >= max_output
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn task_run(
        &self,
        owner: &str,
        root: &JobRoot,
        command: Option<&str>,
        argv: Option<&Vec<Value>>,
        req_id: Option<&str>,
        cwd: Option<&str>,
        ephemeral_worktree: bool,
        wait_seconds: u64,
        timeout_seconds: u64,
        policy: JobPolicy<'_>,
    ) -> io::Result<Value> {
        if let Some(req_id) = req_id
            && let Ok(Some(existing_id)) = self.store.get_request_id(req_id)
        {
            return Ok(json!({
                "task_id": existing_id,
                "idempotent_replay": true,
                "status": "replayed"
            }));
        }

        let canonical_cwd = resolve_cwd(root, cwd, policy)?;
        let task_id = random_hex()?;
        let nonce = &task_id[..8];

        let worktree_info = if ephemeral_worktree {
            let branch = format!("veyl-task-{}", nonce);
            let wt_path = canonical_cwd.join(format!(".veyl-wt-{}", nonce));
            let mut git_cmd = Command::new("git");
            git_cmd
                .arg("worktree")
                .arg("add")
                .arg("-b")
                .arg(&branch)
                .arg(&wt_path)
                .arg("HEAD");
            git_cmd.current_dir(&canonical_cwd);
            match git_cmd.status() {
                Ok(status) if status.success() => Some((branch, wt_path)),
                _ => None,
            }
        } else {
            None
        };

        let effective_cwd = if let Some((_, ref wt_path)) = worktree_info {
            wt_path.clone()
        } else {
            canonical_cwd.clone()
        };

        let mut cmd = if let Some(argv) = argv {
            let args_str: Vec<String> = argv
                .iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect();
            if args_str.is_empty() {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "argv must not be empty",
                ));
            }
            let mut c = Command::new(&args_str[0]);
            c.args(&args_str[1..]);
            c
        } else if let Some(cmd_str) = command {
            let mut c = Command::new("sh");
            c.arg("-c").arg(cmd_str);
            c
        } else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "command or argv required",
            ));
        };

        cmd.current_dir(&effective_cwd);

        let argv_repr = format!("{:?}{:?}", command, argv);
        let mut hasher = Sha256::new();
        hasher.update(argv_repr.as_bytes());
        let argv_hash = format!("{:x}", hasher.finalize());

        let eff_mode = if policy.full {
            "full"
        } else if policy.broad.is_some() {
            "broad_yolo"
        } else if policy.yolo {
            "legacy_scoped_yolo"
        } else {
            "standard"
        };

        let max_output = 2 * 1024 * 1024;
        let execution_timeout = wait_seconds.min(timeout_seconds);

        if let Ok(mut audit) = self.audit.lock() {
            let _ = audit.record_job(
                owner,
                AuditAction::JobStart,
                AuditPhase::Intent,
                now(),
                JobAuditInfo {
                    job_id: &task_id,
                    argv_sha256: &argv_hash,
                    cwd: &effective_cwd,
                    timeout_seconds: execution_timeout,
                    max_output_bytes: max_output,
                    state: "intent",
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    yolo: policy.yolo,
                    effective_mode: eff_mode,
                },
            );
        }

        let start = Instant::now();
        let (status, stdout, stderr) = crate::linux_command::capture_both(
            &mut cmd,
            max_output,
            Duration::from_secs(execution_timeout),
        )?;
        let duration_ms = start.elapsed().as_millis() as u64;

        let mut checkpoint_created = false;
        if let Some((ref branch, ref wt_path)) = worktree_info {
            if status.success() {
                let mut add = Command::new("git");
                add.arg("add").arg("-A").current_dir(wt_path);
                let _ = add.status();
                let mut commit = Command::new("git");
                commit
                    .arg("commit")
                    .arg("-m")
                    .arg(format!("checkpoint: task {}", task_id))
                    .current_dir(wt_path);
                if let Ok(c_status) = commit.status() {
                    checkpoint_created = c_status.success();
                }
            }
            let mut remove = Command::new("git");
            remove
                .arg("worktree")
                .arg("remove")
                .arg("--force")
                .arg(wt_path)
                .current_dir(&canonical_cwd);
            let _ = remove.status();
            let _ = std::fs::remove_dir_all(wt_path);
            if !checkpoint_created {
                let mut branch_del = Command::new("git");
                branch_del
                    .arg("branch")
                    .arg("-D")
                    .arg(branch)
                    .current_dir(&canonical_cwd);
                let _ = branch_del.status();
            }
        }

        if let Ok(mut audit) = self.audit.lock() {
            let _ = audit.record_job(
                owner,
                AuditAction::JobStart,
                if status.success() {
                    AuditPhase::Success
                } else {
                    AuditPhase::Failure
                },
                now(),
                JobAuditInfo {
                    job_id: &task_id,
                    argv_sha256: &argv_hash,
                    cwd: &effective_cwd,
                    timeout_seconds: execution_timeout,
                    max_output_bytes: max_output,
                    state: if status.success() {
                        "completed"
                    } else {
                        "failed"
                    },
                    stdout_bytes: stdout.len(),
                    stderr_bytes: stderr.len(),
                    yolo: policy.yolo,
                    effective_mode: eff_mode,
                },
            );
        }

        if let Some(req_id) = req_id {
            let _ = self.store.set_request_id(req_id, &task_id);
        }

        Ok(json!({
            "task_id": task_id,
            "exit_code": status.code(),
            "stdout": String::from_utf8_lossy(&stdout),
            "stderr": String::from_utf8_lossy(&stderr),
            "duration_ms": duration_ms,
            "ephemeral_worktree": ephemeral_worktree,
            "checkpoint": checkpoint_created,
            "truncated": stdout.len() >= max_output || stderr.len() >= max_output
        }))
    }
}

fn resolve_cwd(
    root: &JobRoot,
    cwd_arg: Option<&str>,
    policy: JobPolicy<'_>,
) -> io::Result<PathBuf> {
    let target = match cwd_arg {
        Some(s) if !s.trim().is_empty() => {
            let p = Path::new(s);
            if p.is_relative() {
                root.path().join(p)
            } else {
                p.to_path_buf()
            }
        }
        _ => root.path().to_owned(),
    };
    let canonical = std::fs::canonicalize(&target).or_else(|_| {
        if target.exists() {
            Ok(target)
        } else {
            Err(io::Error::from(ErrorKind::NotFound))
        }
    })?;

    if policy.full {
        return Ok(canonical);
    }
    if let Some(broad) = policy.broad {
        if broad.is_masked(&canonical) {
            return Err(io::Error::from(ErrorKind::PermissionDenied));
        }
        return Ok(canonical);
    }
    if policy.yolo {
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            for def in crate::protected_paths::OPTIONAL_DEFAULTS {
                if canonical.starts_with(home.join(def)) {
                    return Err(io::Error::from(ErrorKind::PermissionDenied));
                }
            }
        }
        return Ok(canonical);
    }
    let mut allowed = vec![root.path()];
    if let Some(mounts) = policy.workspace_mounts {
        for m in mounts {
            allowed.push(m.path());
        }
    }
    if !allowed
        .iter()
        .any(|allowed_root| canonical.starts_with(allowed_root))
    {
        return Err(io::Error::from(ErrorKind::PermissionDenied));
    }
    Ok(canonical)
}
