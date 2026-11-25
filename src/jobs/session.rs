//! Explicitly granted sessions on the signed durable runner.

pub(super) mod channel;
pub(super) mod terminal;

use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::tools::registry::Tool;

use super::api::{argument_error, request_id};
use super::config::{Profile, RootIdentity};
use super::process::Presence;
use super::receipt::{Receipt, State};
use super::{JobPolicy, JobRoot, Jobs, invalid, store::valid_id};
use channel::Operation;

#[derive(Clone, Copy)]
pub(crate) struct Authorization<'a> {
    pub config: &'a Path,
    pub digest: &'a [u8; 32],
    pub expires_at: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Binding {
    pub config: PathBuf,
    pub root: RootIdentity,
    pub pty: bool,
}

impl Binding {
    pub(super) fn new(auth: Authorization<'_>, root: &RootIdentity, pty: bool) -> Self {
        Self {
            config: auth.config.to_owned(),
            root: root.clone(),
            pty,
        }
    }

    pub(super) fn transport(&self) -> &'static str {
        if self.pty { "pty" } else { "pipe" }
    }
}

impl Jobs {
    pub(crate) fn sessions_available(&self) -> bool {
        self.scopes.is_some() && self.profiles.has_interactive() && self.available()
    }

    pub(super) fn session_call(
        &self,
        tool: Tool,
        args: &Map<String, Value>,
        owner: &str,
        root: &JobRoot,
        policy: JobPolicy<'_>,
    ) -> io::Result<Value> {
        let auth = policy.session.ok_or_else(invalid)?;
        if tool == Tool::ProcessStart {
            if args
                .keys()
                .any(|key| !matches!(key.as_str(), "profile" | "request_id" | "timeout_seconds"))
            {
                return Err(argument_error("Unexpected process start argument"));
            }
            let name = args
                .get("profile")
                .and_then(Value::as_str)
                .ok_or_else(|| argument_error("Expected an approved interactive profile"))?;
            let mut profile = self.interactive_profile(name)?;
            if let Some(timeout) = args.get("timeout_seconds") {
                profile.timeout_seconds = timeout
                    .as_u64()
                    .filter(|limit| (1..=profile.timeout_seconds).contains(limit))
                    .ok_or_else(|| {
                        argument_error("Timeout must fit the approved profile budget")
                    })?;
            }
            return self.start_session(name, profile, request_id(args)?, owner, root, policy);
        }

        if tool == Tool::ShellStatus {
            return self.shell_status(args, owner, root, policy, auth);
        }

        let id = args
            .get("job_id")
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .ok_or_else(|| argument_error("Expected a job identifier"))?;
        if tool == Tool::ShellReset {
            if args.len() != 1 {
                return Err(argument_error("Expected only job_id"));
            }
            let (receipt, profile) = {
                let _guard = self.store.lock(false)?;
                self.session_receipt(id, owner, root, policy, auth)?
            };
            let ended = self.owned_tool(Tool::JobCancel, id, owner, args)?;
            if !matches!(
                ended["state"].as_str(),
                Some("canceled" | "completed" | "failed" | "timed_out" | "interrupted")
            ) {
                return Err(io::Error::other("Session teardown uncertain"));
            }
            // The original signed job ID supplies one deterministic reset key.
            return self.start_session(
                &receipt.profile,
                profile,
                Some(&format!("reset/{id}")),
                owner,
                root,
                policy,
            );
        }

        let operation = if tool == Tool::ProcessResize {
            if args.len() != 3 {
                return Err(argument_error("Expected job_id, rows and cols"));
            }
            let dimension = |key: &str| -> io::Result<u16> {
                args.get(key)
                    .and_then(Value::as_u64)
                    .filter(|n| (1..=512).contains(n))
                    .map(|n| n as u16)
                    .ok_or_else(|| argument_error("Rows and cols must be integers from 1 to 512"))
            };
            Operation::Resize(dimension("rows")?, dimension("cols")?)
        } else if args.len() == 1 {
            Operation::Query
        } else {
            let sequence = args
                .get("sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| argument_error("Expected a nonnegative input sequence"))?;
            match (args.len(), args.get("data"), args.get("eof")) {
                (3, Some(Value::String(input)), None)
                    if (1..=channel::MAX_INPUT).contains(&input.len()) =>
                {
                    Operation::Write(sequence, input.as_bytes())
                }
                (3, None, Some(Value::Bool(true))) => Operation::Eof(sequence),
                _ => {
                    return Err(argument_error(
                        "Expected data of 1 to 4096 UTF-8 bytes or eof=true",
                    ));
                }
            }
        };
        let _guard = self.store.lock(false)?;
        let (receipt, _) = self.session_receipt(id, owner, root, policy, auth)?;
        if receipt.state != State::Running
            || receipt.cancel_requested
            || receipt
                .runner
                .as_ref()
                .is_none_or(|runner| runner.presence() != Presence::Present)
        {
            return Err(io::Error::other("Session is not accepting input"));
        }
        let mut result = channel::exchange(
            &self.store.input_key(&receipt),
            auth.digest,
            auth.expires_at,
            operation,
        )
        .map_err(|error| {
            if matches!(
                error.kind(),
                ErrorKind::PermissionDenied | ErrorKind::InvalidInput
            ) {
                error
            } else {
                io::Error::other("Input delivery uncertain")
            }
        })?;
        if tool == Tool::ProcessResize {
            if result["status"] != "accepted" {
                return Err(io::Error::other("Resize unavailable"));
            }
            return Ok(
                json!({"job_id": id, "resized": true, "pty": true, "rows": result["rows"], "cols": result["cols"]}),
            );
        }
        result["job_id"] = json!(id);
        result["transport"] = json!(receipt.session.as_ref().ok_or_else(invalid)?.transport());
        Ok(result)
    }

    fn shell_status(
        &self,
        args: &Map<String, Value>,
        owner: &str,
        root: &JobRoot,
        policy: JobPolicy<'_>,
        auth: Authorization<'_>,
    ) -> io::Result<Value> {
        if args.keys().any(|key| key != "job_id") {
            return Err(argument_error("Unexpected shell status argument"));
        }
        let _guard = self.store.lock(false)?;
        if let Some(value) = args.get("job_id") {
            let id = value
                .as_str()
                .filter(|id| valid_id(id))
                .ok_or_else(|| argument_error("Expected a job identifier"))?;
            let receipt = self.owned_receipt(&self.store.job(id)?, owner)?;
            return self.session_status(receipt, owner, root, policy, auth);
        }
        let mut sessions = Vec::new();
        let mut truncated = false;
        for id in self.store.jobs()? {
            let job = self.store.job(&id)?;
            let Some(receipt) = self.read_if_published(&job)? else {
                continue;
            };
            if receipt.client_id != owner || receipt.session.is_none() {
                continue;
            }
            if sessions.len() == 40 {
                truncated = true;
                break;
            }
            let receipt = self.owned_receipt(&job, owner)?;
            sessions.push(self.session_status(receipt, owner, root, policy, auth)?);
        }
        Ok(json!({"count": sessions.len(), "sessions": sessions, "truncated": truncated}))
    }

    fn session_status(
        &self,
        receipt: Receipt,
        owner: &str,
        root: &JobRoot,
        policy: JobPolicy<'_>,
        auth: Authorization<'_>,
    ) -> io::Result<Value> {
        let binding = receipt
            .session
            .as_ref()
            .ok_or_else(|| argument_error("Job is not a persistent process session"))?;
        let mut status = self.present_status(&receipt);
        status["transport"] = json!(binding.transport());
        status["pty"] = json!(binding.pty);
        status["rows"] = Value::Null;
        status["cols"] = Value::Null;
        status["sequence"] = Value::Null;
        status["stdin_closed"] = Value::Null;
        if receipt.state.active() && !self.recovered.contains(&receipt.job_id) {
            self.session_receipt(&receipt.job_id, owner, root, policy, auth)?;
            let live = channel::exchange(
                &self.store.input_key(&receipt),
                auth.digest,
                auth.expires_at,
                Operation::Query,
            )?;
            status["rows"] = live["rows"].clone();
            status["cols"] = live["cols"].clone();
            status["sequence"] = live["next_sequence"].clone();
            status["stdin_closed"] = live["stdin_closed"].clone();
        }
        Ok(status)
    }

    fn interactive_profile(&self, name: &str) -> io::Result<Profile> {
        self.profiles
            .named(name)
            .filter(|profile| profile.interactive)
            .ok_or_else(|| argument_error("Unknown or noninteractive profile"))
    }

    fn session_receipt(
        &self,
        id: &str,
        owner: &str,
        root: &JobRoot,
        policy: JobPolicy<'_>,
        auth: Authorization<'_>,
    ) -> io::Result<(Receipt, Profile)> {
        let receipt = self.owned_receipt(&self.store.job(id)?, owner)?;
        root.identity().handle()?;
        let profile = self.interactive_profile(&receipt.profile)?;
        let mounts = policy.workspace_mounts.unwrap_or_default();
        for mount in mounts {
            mount.identity().handle()?;
        }
        if receipt.session.as_ref() != Some(&Binding::new(auth, root.identity(), profile.pty))
            || !receipt.isolated
            || receipt.full
            || receipt.yolo != policy.yolo
            || receipt.broad.as_ref() != policy.broad
            || !receipt
                .sandbox_roots
                .iter()
                .eq(mounts.iter().map(JobRoot::identity))
            || receipt.argv_sha256 != profile.argv_hash()
            || receipt.timeout_seconds
                > profile
                    .timeout_seconds
                    .min(policy.job_runtime_limit_seconds)
            || receipt.max_output_bytes != profile.max_output_bytes
        {
            return Err(io::Error::from(ErrorKind::PermissionDenied));
        }
        let mut profile = profile;
        profile.timeout_seconds = receipt.timeout_seconds;
        Ok((receipt, profile))
    }

    fn start_session(
        &self,
        name: &str,
        profile: Profile,
        request: Option<&str>,
        owner: &str,
        root: &JobRoot,
        policy: JobPolicy<'_>,
    ) -> io::Result<Value> {
        let (receipt, replay) =
            self.start(owner, root, name.to_owned(), profile, policy, request, None)?;
        let mut status = self.present_status(&receipt);
        if replay {
            status["idempotent_replay"] = json!(true);
        }
        Ok(status)
    }
}
