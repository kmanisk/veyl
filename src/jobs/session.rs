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
        Self { config: auth.config.to_owned(), root: root.clone(), pty }
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
            if args.keys().any(|key| !matches!(key.as_str(), "profile" | "request_id" | "timeout_seconds")) {
                return Err(argument_error("Unexpected process start argument"));
            }
            let name = args.get("profile").and_then(Value::as_str)
                .ok_or_else(|| argument_error("Expected an approved interactive profile"))?;
            let mut profile = self.interactive_profile(name)?;
            if let Some(timeout) = args.get("timeout_seconds") {
                profile.timeout_seconds = timeout.as_u64()
                    .filter(|limit| (1..=profile.timeout_seconds).contains(limit))
                    .ok_or_else(|| argument_error("Timeout must fit the approved profile budget"))?;
            }
            return self.start_session(name, profile, request_id(args)?, owner, root, policy);
        }

        let id = args.get("job_id").and_then(Value::as_str).filter(|id| valid_id(id))
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
            if !matches!(ended["state"].as_str(), Some("canceled" | "completed" | "failed" | "timed_out" | "interrupted")) {
                return Err(io::Error::other("Session teardown uncertain"));
            }
            // The original signed job ID supplies one deterministic reset key.
            return self.start_session(
                &receipt.profile, profile, Some(&format!("reset/{id}")), owner, root, policy,
            );
        }

        let operation = if args.len() == 1 {
            Operation::Query
        } else {
            let sequence = args.get("sequence").and_then(Value::as_u64)
                .ok_or_else(|| argument_error("Expected a nonnegative input sequence"))?;
            match (args.len(), args.get("data"), args.get("eof")) {
                (3, Some(Value::String(input)), None) if (1..=channel::MAX_INPUT).contains(&input.len()) => {
                    Operation::Write(sequence, input.as_bytes())
                }
                (3, None, Some(Value::Bool(true))) => Operation::Eof(sequence),
                _ => return Err(argument_error("Expected data of 1 to 4096 UTF-8 bytes or eof=true")),
            }
        };
        let _guard = self.store.lock(false)?;
        let (receipt, _) = self.session_receipt(id, owner, root, policy, auth)?;
        if receipt.state != State::Running || receipt.cancel_requested
            || receipt.runner.as_ref().is_none_or(|runner| runner.presence() != Presence::Present)
        {
            return Err(io::Error::other("Session is not accepting input"));
        }
        let mut result = channel::exchange(
            &self.store.input_key(&receipt), auth.digest, auth.expires_at, operation,
        ).map_err(|error| {
            if error.kind() == ErrorKind::PermissionDenied {
                error
            } else {
                io::Error::other("Input delivery uncertain")
            }
        })?;
        result["job_id"] = json!(id);
        result["transport"] = json!(receipt.session.as_ref().ok_or_else(invalid)?.transport());
        Ok(result)
    }

    fn interactive_profile(&self, name: &str) -> io::Result<Profile> {
        self.profiles.named(name).filter(|profile| profile.interactive)
            .ok_or_else(|| argument_error("Unknown or noninteractive profile"))
    }

    fn session_receipt(
        &self, id: &str, owner: &str, root: &JobRoot, policy: JobPolicy<'_>,
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
            || !receipt.isolated || receipt.full || receipt.yolo != policy.yolo
            || receipt.broad.as_ref() != policy.broad
            || !receipt.sandbox_roots.iter().eq(mounts.iter().map(JobRoot::identity))
            || receipt.argv_sha256 != profile.argv_hash()
            || receipt.timeout_seconds > profile.timeout_seconds.min(policy.job_runtime_limit_seconds)
            || receipt.max_output_bytes != profile.max_output_bytes
        {
            return Err(io::Error::from(ErrorKind::PermissionDenied));
        }
        let mut profile = profile;
        profile.timeout_seconds = receipt.timeout_seconds;
        Ok((receipt, profile))
    }

    fn start_session(
        &self, name: &str, profile: Profile, request: Option<&str>, owner: &str,
        root: &JobRoot, policy: JobPolicy<'_>,
    ) -> io::Result<Value> {
        let (receipt, replay) = self.start(owner, root, name.to_owned(), profile, policy, request)?;
        let mut status = self.present_status(&receipt);
        if replay {
            status["idempotent_replay"] = json!(true);
        }
        Ok(status)
    }
}
