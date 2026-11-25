//! Validates tool inputs and returns owner-scoped, bounded responses.

use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use mcp_gateway::security::audit::{AuditAction, AuditPhase};

use crate::tools::registry::{Tool, tool_text};

use super::config::{MAX_OUTPUT, Profile, SHORT_RUNTIME_MAX};
use super::receipt::Receipt;
use super::store::{JobDir, valid_id};
use super::{JobPolicy, JobRoot, Jobs, SHORT_TIMEOUT, invalid, logs, process, record};

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
                let short = tool == Tool::RunCommand;
                if args.keys().any(|key| {
                    !matches!(key.as_str(), "profile" | "request_id") && !(short && key == "argv")
                }) || args.contains_key("profile") == args.contains_key("argv")
                {
                    return tool_text(
                        true,
                        "Expected exactly one configured job profile or permitted argv, with no unexpected arguments",
                    );
                }
                let req_id = match request_id(args) {
                    Ok(value) => value,
                    Err(_) => return tool_text(true, "Invalid request_id"),
                };
                let selected = match args.len() {
                    _ if args.contains_key("profile") => {
                        args["profile"].as_str().and_then(|name| {
                            self.profiles
                                .named(name)
                                .filter(|profile| !profile.interactive)
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
                self.start(owner, root, name, profile, policy, req_id)
                    .and_then(|(receipt, replay)| {
                        let mut result = if short {
                            self.wait_short(owner, &receipt.job_id)?
                        } else {
                            self.present_status(&receipt)
                        };
                        if replay {
                            result["idempotent_replay"] = json!(true);
                        }
                        Ok(result)
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
            Tool::ProcessStart | Tool::ProcessInput | Tool::ShellReset => {
                self.session_call(tool, args, owner, root, policy)
            }
            Tool::ExecCommand | Tool::TaskRun => {
                self.dynamic_command(tool, owner, root, args, policy)
            }
            _ => return tool_text(true, "Invalid job tool"),
        };
        match result {
            Ok(value) => tool_text(false, &value.to_string()),
            Err(error) if tool == Tool::ProcessInput && error.kind() == ErrorKind::Other => {
                tool_text(true, "Session input unavailable or delivery uncertain. Query with job_id before sending more input.")
            }
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
                let number = |key: &str, default: usize| -> io::Result<usize> {
                    match args.get(key) {
                        None => Ok(default),
                        Some(value) => value
                            .as_u64()
                            .and_then(|n| usize::try_from(n).ok())
                            .filter(|n| *n <= i64::MAX as usize)
                            .ok_or_else(|| {
                                io::Error::new(
                                    ErrorKind::InvalidInput,
                                    "Expected a nonnegative byte offset or limit",
                                )
                            }),
                    }
                };
                let max_bytes = number("max_bytes", 4096)?.min(65536);
                let separate =
                    args.contains_key("stdout_offset") || args.contains_key("stderr_offset");
                if separate {
                    if args.contains_key("offset") {
                        return Err(io::Error::new(
                            ErrorKind::InvalidInput,
                            "Use either offset or independent stream offsets",
                        ));
                    }
                    logs::excerpts_streams(
                        &job,
                        &receipt,
                        number("stdout_offset", 0)?,
                        number("stderr_offset", 0)?,
                        max_bytes,
                    )
                } else if args.contains_key("offset") || args.contains_key("max_bytes") {
                    logs::excerpts_offset(&job, &receipt, number("offset", 0)?, max_bytes)
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

    pub(super) fn owned_receipt(&self, job: &JobDir<'_>, owner: &str) -> io::Result<Receipt> {
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
    pub(super) fn present_status(&self, receipt: &Receipt) -> Value {
        let mut status = receipt.status();
        if receipt.state.active() && self.recovered.contains(&receipt.job_id) {
            status["state"] = json!("uncertain");
            if let Some(fields) = status.as_object_mut() {
                fields.remove("live_elapsed_ms");
            }
            status["recovery"] =
                json!("detached runner may still be active; awaiting final receipt");
        }
        status
    }

    /// Ad-hoc commands use the same signed, supervised runner as profiles.
    /// Never launch a caller-selected program or Git operation in the gateway.
    fn dynamic_command(
        &self,
        tool: Tool,
        owner: &str,
        root: &JobRoot,
        args: &serde_json::Map<String, Value>,
        policy: JobPolicy<'_>,
    ) -> io::Result<Value> {
        let task = tool == Tool::TaskRun;
        if args.keys().any(|key| {
            !matches!(
                key.as_str(),
                "command" | "argv" | "cwd" | "timeout_seconds" | "request_id"
            ) && !(task && matches!(key.as_str(), "wait_seconds" | "ephemeral_worktree"))
        }) {
            return Err(argument_error("Unexpected command argument"));
        }
        if !policy.full && policy.broad.is_none() && policy.workspace_mounts.is_none() {
            return Err(io::Error::from(ErrorKind::Unsupported));
        }
        if let Some(value) = args.get("ephemeral_worktree")
            && value.as_bool() != Some(false)
        {
            return Err(argument_error(
                "Automatic worktree creation is unavailable; use an explicitly approved workspace",
            ));
        }
        let req = request_id(args)?;
        let number = |key: &str, default: u64, min: u64, max: u64| -> io::Result<u64> {
            match args.get(key) {
                None => Ok(default),
                Some(value) => value
                    .as_u64()
                    .filter(|n| *n >= min && *n <= max)
                    .ok_or_else(|| argument_error("Invalid command time budget")),
            }
        };
        let timeout = number(
            "timeout_seconds",
            if task { 120 } else { 30 },
            1,
            if task {
                policy.job_runtime_limit_seconds
            } else {
                SHORT_RUNTIME_MAX
            },
        )?;
        let wait = if task {
            number("wait_seconds", 15, 0, 60)?.min(20)
        } else {
            timeout.saturating_add(2).min(20)
        };
        let cwd = match args.get("cwd") {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| argument_error("Invalid working directory"))?,
            ),
        };
        let (executable, argv) = match (args.get("command"), args.get("argv")) {
            (Some(Value::String(command)), None) if !command.trim().is_empty() => (
                "/usr/bin/sh".to_owned(),
                vec!["-c".to_owned(), command.clone()],
            ),
            (None, Some(Value::Array(values))) if !values.is_empty() => {
                let strings = values
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| argument_error("argv must contain only strings"))
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                let program = &strings[0];
                let executable = if Path::new(program).is_absolute() {
                    program.clone()
                } else if !program.is_empty()
                    && !program.contains('/')
                    && program != "."
                    && program != ".."
                {
                    format!("/usr/bin/{program}")
                } else {
                    return Err(argument_error(
                        "Use an absolute executable or a name in /usr/bin",
                    ));
                };
                (executable, strings[1..].to_vec())
            }
            _ => {
                return Err(argument_error(
                    "Specify exactly one nonempty command or argv",
                ));
            }
        };
        let mut profile = Profile {
            interactive: false,
            pty: false,
            executable,
            args: argv,
            timeout_seconds: timeout,
            extended_runtime: task && timeout > SHORT_RUNTIME_MAX,
            max_output_bytes: MAX_OUTPUT,
        };
        profile.validate()?;
        // Revalidate original approved handles before resolving a nested cwd.
        root.identity().handle()?;
        for mount in policy.workspace_mounts.unwrap_or_default() {
            mount.identity().handle()?;
        }
        let canonical = resolve_cwd(root, cwd, policy)?;
        let effective_root = JobRoot::open(&canonical).map_err(io::Error::other)?;
        if canonical == root.path() && effective_root.identity() != root.identity() {
            return Err(invalid());
        }
        let mut mounts = Vec::new();
        if let Some(approved) = policy.workspace_mounts {
            for source in std::iter::once(root).chain(approved.iter()) {
                if source.path() == canonical
                    || mounts
                        .iter()
                        .any(|item: &JobRoot| item.path() == source.path())
                {
                    continue;
                }
                let copy = JobRoot::open(source.path()).map_err(io::Error::other)?;
                if copy.identity() != source.identity() {
                    return Err(invalid());
                }
                mounts.push(copy);
            }
        }
        let effective_policy = JobPolicy {
            workspace_mounts: policy.workspace_mounts.map(|_| mounts.as_slice()),
            ..policy
        };
        let (receipt, replay) = self.start(
            owner,
            &effective_root,
            if task {
                "task_run".into()
            } else {
                "exec_command".into()
            },
            profile,
            effective_policy,
            req,
        )?;
        let receipt = if wait > 0 && receipt.state.active() {
            self.wait_for_end(owner, &receipt.job_id, Duration::from_secs(wait))?
        } else {
            receipt
        };
        let logs = logs::excerpts(&self.store.job(&receipt.job_id)?, &receipt)?;
        let mut result = self.present_status(&receipt);
        result["stdout"] = logs["stdout"].clone();
        result["stderr"] = logs["stderr"].clone();
        result["truncated"] =
            json!(logs["stdout_truncated"] == true || logs["stderr_truncated"] == true);
        if let Some(ms) = receipt.execution_duration_ms {
            result["duration_ms"] = json!(ms);
        }
        if replay {
            result["idempotent_replay"] = json!(true);
        }
        if task {
            result["task_id"] = json!(receipt.job_id);
            result["ephemeral_worktree"] = json!(false);
            result["checkpoint"] = json!(false);
        }
        Ok(result)
    }
}

pub(super) fn argument_error(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}

pub(super) fn request_id(args: &serde_json::Map<String, Value>) -> io::Result<Option<&str>> {
    match args.get("request_id") {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|id| {
                !id.is_empty()
                    && id.len() <= 64
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            })
            .map(Some)
            .ok_or_else(|| argument_error("Invalid request_id")),
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
    let canonical = std::fs::canonicalize(&target)?;

    if policy.full {
        return Ok(canonical);
    }
    if let Some(broad) = policy.broad {
        if broad.is_masked(&canonical) {
            return Err(io::Error::from(ErrorKind::PermissionDenied));
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
