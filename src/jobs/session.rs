//! Explicitly granted sessions on the signed durable runner.

pub(super) mod channel;
pub(super) mod terminal;

use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
pub(crate) struct OAuthAuthorization<'a> {
    pub state_dir: &'a Path,
    pub oauth_client: &'a str,
    pub local_client: &'a str,
    pub family: &'a [u8; 32],
}

#[derive(Clone, Copy)]
pub(crate) struct Authorization<'a> {
    pub config: &'a Path,
    pub digest: &'a [u8; 32],
    pub expires_at: u64,
    pub oauth: Option<OAuthAuthorization<'a>>,
}

/// Immutable authorization for the original launch, not the lifetime identity
/// of a session. Subsequent input uses a fresh authenticated request instead.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchAuthority {
    revision: [u8; 32],
    expires_at: u64,
}

impl LaunchAuthority {
    pub(super) fn new(auth: Authorization<'_>) -> Option<Self> {
        auth.oauth.map(|_| Self {
            revision: *auth.digest,
            expires_at: auth.expires_at,
        })
    }

    pub(super) fn expired(&self) -> bool {
        super::now() >= self.expires_at
    }

    pub(super) fn policy_guard(
        &self,
        config: &Path,
    ) -> io::Result<crate::http::operator::PolicyFile> {
        let guard = crate::http::operator::PolicyFile::input_snapshot(config, &self.revision)?;
        if self.expired() {
            return Err(io::Error::from(ErrorKind::PermissionDenied));
        }
        Ok(guard)
    }
}

/// Native permission authorizes this runner until its audited revision is
/// replaced or revoked. Unrelated policy edits leave the job running.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeAuthority {
    config: PathBuf,
    revision: String,
}

impl NativeAuthority {
    pub fn new((config, revision): (&Path, &str)) -> Self {
        Self { config: config.to_owned(), revision: revision.to_owned() }
    }

    pub fn guard(&self, owner: &str) -> Result<crate::http::operator::PolicyFile, String> {
        use crate::http::operator::{Mode, PolicyFile, parse_document};
        let policy = PolicyFile::try_read(&self.config).map_err(|_| "Native authorization policy unavailable")?;
        if policy.pending_client()?.is_some() {
            return Err("Policy update in progress".into());
        }
        let document = parse_document(&policy.bytes()?)?;
        let version = document["policy_version"].as_u64();
        let enabled = document["clients"].as_array().is_some_and(|clients| clients.iter().any(|entry| {
            entry["id"] == owner && entry["disabled"] != true
                && entry["yolo_revision"] == self.revision
                && entry["expires_at_unix_seconds"].as_u64().is_some_and(|expiry| expiry > super::now())
                && matches!(Mode::from_entry(entry, version), Ok(Mode::NativeYolo | Mode::Full))
        }));
        if !enabled { return Err("Native job authorization revoked".into()); }
        Ok(policy)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OAuthBinding {
    pub state_dir: PathBuf,
    pub oauth_client: String,
    pub local_client: String,
    pub family_code: String,
}

impl OAuthBinding {
    pub(super) fn from_auth(oauth: OAuthAuthorization<'_>) -> Self {
        Self {
            state_dir: oauth.state_dir.to_owned(),
            oauth_client: oauth.oauth_client.to_owned(),
            local_client: oauth.local_client.to_owned(),
            family_code: URL_SAFE_NO_PAD.encode(oauth.family),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Binding {
    pub config: PathBuf,
    pub root: RootIdentity,
    pub pty: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthBinding>,
}

impl Binding {
    pub(super) fn new(auth: Authorization<'_>, root: &RootIdentity, pty: bool) -> Self {
        Self {
            config: auth.config.to_owned(),
            root: root.clone(),
            pty,
            oauth: auth.oauth.map(OAuthBinding::from_auth),
        }
    }

    pub(super) fn transport(&self) -> &'static str {
        if self.pty { "pty" } else { "pipe" }
    }
}

pub(super) fn verify_oauth_grant(oauth: &OAuthBinding) -> io::Result<rustix::fd::OwnedFd> {
    verify_oauth_grant_mode(oauth, false)
}

pub(super) fn verify_oauth_grant_mode(
    oauth: &OAuthBinding,
    required_yolo: bool,
) -> io::Result<rustix::fd::OwnedFd> {
    mcp_gateway::http_common::oauth_http::active_family_guard_with_mode(
        &oauth.state_dir,
        &oauth.oauth_client,
        &oauth.local_client,
        &oauth.family_code,
        required_yolo,
    )
    .map_err(|_| io::Error::from(ErrorKind::PermissionDenied))
}

impl Jobs {
    pub(crate) fn sessions_available(&self, native: bool) -> bool {
        (native || self.scopes.is_some() && self.profiles.has_interactive()) && self.available()
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
            let mut profile = self.interactive_profile(name, policy)?;
            if let Some(timeout) = args.get("timeout_seconds") {
                profile.timeout_seconds = timeout
                    .as_u64()
                    .filter(|limit| (1..=if profile.timeout_seconds == 0 {
                            policy.job_runtime_limit_seconds
                        } else {
                            profile.timeout_seconds
                        }).contains(limit))
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

    fn interactive_profile(&self, name: &str, policy: JobPolicy<'_>) -> io::Result<Profile> {
        if let Some(profile) = self.profiles.named(name).filter(|profile| profile.interactive) {
            return Ok(profile);
        }
        if policy.full && matches!(name, "shell" | "pty") {
            let mut profile = Profile {
                executable: "/usr/bin/sh".into(),
                args: vec![if name == "pty" { "-i" } else { "-s" }.into()],
                interactive: true,
                pty: name == "pty",
                extended_runtime: true,
                timeout_seconds: policy.native_default_timeout.unwrap_or(0),
                max_output_bytes: policy.job_output_limit_bytes,
                cpu_percent: policy.job_cpu_percent_limit,
                memory_bytes: policy.job_memory_bytes_limit,
            };
            profile.validate(true)?;
            return Ok(profile);
        }
        Err(argument_error("Unknown or noninteractive profile"))
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
        let profile = self.interactive_profile(&receipt.profile, policy)?;
        let mounts = policy.workspace_mounts.unwrap_or_default();
        for mount in mounts {
            mount.identity().handle()?;
        }
        if receipt.session.as_ref() != Some(&Binding::new(auth, root.identity(), profile.pty))
            || receipt.oauth_family != policy.oauth_family
            || (!receipt.isolated && !policy.full)
            || receipt.full != policy.full
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
                    .max(if profile.timeout_seconds == 0 { policy.job_runtime_limit_seconds } else { 0 })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    #[test]
    fn oauth_launch_rejects_stale_policy_expired_deadline_and_busy_writer() {
        use sha2::{Digest, Sha256};
        let dir = std::env::temp_dir().join(format!(
            "veyl-launch-authority-{}-{}",
            std::process::id(),
            mcp_gateway::core::session::random_id::<8>().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("clients.json");
        let original = b"{\"clients\":[]}";
        std::fs::write(&path, original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let revision = Sha256::digest(original).into();
        let valid = LaunchAuthority {
            revision,
            expires_at: super::super::now() + 60,
        };
        let guard = valid.policy_guard(&path).expect("current admission");
        drop(guard);
        let expired = LaunchAuthority {
            revision,
            expires_at: super::super::now(),
        };
        assert!(expired.policy_guard(&path).is_err());
        let exclusive = crate::http::operator::PolicyFile::lock(&path, true).unwrap();
        assert!(valid.policy_guard(&path).is_err());
        exclusive.replace(b"{\"clients\":[],\"changed\":true}").unwrap();
        drop(exclusive);
        assert!(valid.policy_guard(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn binding_preserves_legacy_format_and_oauth_family_identity() {
        let dir = std::env::temp_dir().join(format!(
            "veyl-binding-test-{}-{}",
            std::process::id(),
            mcp_gateway::core::session::random_id::<8>().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = JobRoot::open(&dir).unwrap();
        let digest = [0x11u8; 32];
        let legacy = Binding::new(
            Authorization {
                config: Path::new("/tmp/clients.json"),
                digest: &digest,
                expires_at: 4294967295,
                oauth: None,
            },
            root.identity(),
            false,
        );
        let serialized = serde_json::to_value(&legacy).unwrap();
        assert!(serialized.get("oauth").is_none());
        let decoded: Binding = serde_json::from_value(serialized).unwrap();
        assert_eq!(decoded, legacy);

        let family_a = [0x22u8; 32];
        let family_b = [0x33u8; 32];
        let oa = Binding::new(
            Authorization {
                config: Path::new("/tmp/clients.json"),
                digest: &digest,
                expires_at: 1000,
                oauth: Some(OAuthAuthorization {
                    state_dir: &dir,
                    oauth_client: "client-1",
                    local_client: "oauth-preview",
                    family: &family_a,
                }),
            },
            root.identity(),
            true,
        );
        let ob = Binding::new(
            Authorization {
                config: Path::new("/tmp/clients.json"),
                digest: &digest,
                expires_at: 1000,
                oauth: Some(OAuthAuthorization {
                    state_dir: &dir,
                    oauth_client: "client-1",
                    local_client: "oauth-preview",
                    family: &family_b,
                }),
            },
            root.identity(),
            true,
        );
        assert_ne!(oa, ob);
        assert_eq!(oa.transport(), "pty");
        assert!(oa.oauth.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
