//! Protected local credential configuration and constant-time bearer lookup.
//! No raw bearer tokens are stored or displayed by the HTTP service.

use std::collections::HashSet;
#[cfg(not(target_os = "linux"))]
use std::fs;
use std::path::{Path, PathBuf};

use hyper::header::HeaderValue;
use mcp_gateway::core::credential::select_client;
pub(super) use mcp_gateway::core::credential::{decode_sha256, token_digest, token_shape};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[cfg(target_os = "linux")]
use crate::jobs::{JobRoot, Profiles};
#[cfg(target_os = "linux")]
use crate::tools::MutationRoot;
use crate::tools::registry::Tool;
use mcp_gateway::security::policy::{Action, ExecutionMode};

#[cfg(target_os = "linux")]
use super::operator::Mode;
#[cfg(target_os = "linux")]
use super::scope::{open_extra_roots, protected};

pub struct Client {
    pub id: String,
    digest: [u8; 32],
    pub expires_at: u64,
    pub root: PathBuf,
    pub actions: Vec<Action>,
    pub(crate) tools: HashSet<Tool>,
    pub native_tool_preset: bool,
    pub mode: ExecutionMode,
    pub disabled: bool,
    #[cfg(target_os = "linux")]
    pub explicit_extra_roots: bool,
    #[cfg(target_os = "linux")]
    pub(crate) skills: std::collections::BTreeSet<String>,
    #[cfg(target_os = "linux")]
    pub(crate) upstreams: crate::upstream::Grants,
    #[cfg(target_os = "linux")]
    pub yolo_revision: Option<String>,
    #[cfg(target_os = "linux")]
    pub(crate) approval_mode: Option<&'static str>,
    #[cfg(target_os = "linux")]
    pub extra_roots: Vec<MutationRoot>,
    #[cfg(target_os = "linux")]
    pub mutation_root: Option<MutationRoot>,
    #[cfg(target_os = "linux")]
    pub job_root: Option<JobRoot>,
    #[cfg(target_os = "linux")]
    pub job_runtime_limit_seconds: u64,
    #[cfg(target_os = "linux")]
    pub native_default_timeout: Option<u64>,
    #[cfg(target_os = "linux")]
    pub job_cpu_percent_limit: u64,
    #[cfg(target_os = "linux")]
    pub job_memory_bytes_limit: u64,
    #[cfg(target_os = "linux")]
    pub job_output_limit_bytes: usize,
    #[cfg(target_os = "linux")]
    pub job_retention_count: Option<usize>,
    #[cfg(target_os = "linux")]
    pub timeshift_retention_count: usize,
    #[cfg(target_os = "linux")]
    pub job_extra_roots: Vec<JobRoot>,
    #[cfg(target_os = "linux")]
    pub(crate) denied_actions: Vec<Action>,
}

impl Client {
    pub fn is_disabled(&self) -> bool {
        self.disabled || self.mode == ExecutionMode::Disabled
    }
}

#[cfg(target_os = "linux")]
impl Client {
    pub(super) fn has_digest(&self, value: &[u8; 32]) -> bool {
        bool::from(self.digest.ct_eq(value))
    }
    pub(super) fn credential_digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(super) fn oauth_yolo_override(
        &self,
        settings: &Configuration,
    ) -> Result<Self, &'static str> {
        if self.is_disabled() || !settings.managed || settings.jobs.is_none() {
            return Err("YOLO override unavailable for this policy");
        }
        let jobs = settings.jobs.is_some();
        let skills = settings.skills.is_some();
        let mut tools: HashSet<Tool> = Tool::ALL
            .into_iter()
            .filter(|tool| tool.in_yolo_preset(jobs, skills))
            .collect();
        tools.retain(|tool| !self.denied_actions.contains(&tool.action()));
        let mut actions = vec![Action::ListTools];
        for tool in &tools {
            let action = tool.action();
            if !actions.contains(&action) {
                actions.push(action);
            }
        }
        let mutation_root = Some(
            MutationRoot::open(&self.root)
                .map_err(|_| "Client root must be an existing symlink-free directory")?,
        );
        let job_root = if jobs {
            Some(JobRoot::open(&self.root).map_err(|_| "Job root unavailable")?)
        } else {
            None
        };
        Ok(Self {
            id: self.id.clone(),
            digest: self.digest,
            expires_at: self.expires_at,
            root: self.root.clone(),
            actions,
            tools,
            native_tool_preset: true,
            mode: ExecutionMode::Yolo,
            disabled: false,
            explicit_extra_roots: false,
            skills: self.skills.clone(),
            upstreams: settings.upstreams.native_grants(),
            yolo_revision: None,
            approval_mode: None,
            extra_roots: Vec::new(),
            mutation_root,
            job_runtime_limit_seconds: self.native_default_timeout.unwrap_or(crate::jobs::EXTENDED_RUNTIME_MAX),
            native_default_timeout: self.native_default_timeout,
            job_cpu_percent_limit: 0,
            job_memory_bytes_limit: 0,
            job_output_limit_bytes: self.job_output_limit_bytes,
            job_retention_count: self.job_retention_count,
            timeshift_retention_count: self.timeshift_retention_count,
            job_extra_roots: Vec::new(),
            job_root,
            denied_actions: self.denied_actions.clone(),
        })
    }

    pub(super) fn from_unified_oauth(
        id: String,
        root: PathBuf,
        actions: Vec<Action>,
        tools: HashSet<Tool>,
        yolo: bool,
        expires_at: u64,
        settings: &Configuration,
    ) -> Result<Self, &'static str> {
        let jobs = settings.jobs.is_some();
        if yolo && (!settings.managed || !jobs) {
            return Err("YOLO override unavailable for this policy");
        }
        let mutation_root = if yolo
            || actions.iter().any(|action| {
                matches!(
                    action,
                    Action::ReadFile
                        | Action::WriteFile
                        | Action::ApplyPatch
                        | Action::SearchFiles
                        | Action::GitInspect
                        | Action::GitStatus
                        | Action::GitDiff
                        | Action::GitLog
                        | Action::GitAdd
                        | Action::GitCommit
                        | Action::GitBranch
                        | Action::GitCheckout
                        | Action::GitRestore
                        | Action::GitStash
                        | Action::GitReset
                        | Action::GitPull
                        | Action::GitPush
                        | Action::SystemInfo
                        | Action::SystemInspect
                        | Action::ProjectContext
                        | Action::SystemContext
                        | Action::LoadPathRules
                        | Action::Remember
                        | Action::ChezmoiInspect
                        | Action::ListProjectSkills
                        | Action::LoadProjectSkill
                        | Action::SkillsValidate
                        | Action::ExtensionsInspect
                )
            }) {
            Some(
                MutationRoot::open(&root)
                    .map_err(|_| "Client root must be an existing symlink-free directory")?,
            )
        } else {
            None
        };
        let has_job_grant = actions.iter().any(|action| action.is_job());
        let job_root = if has_job_grant || yolo {
            Some(JobRoot::open(&root).map_err(|_| "Job root unavailable")?)
        } else {
            None
        };
        let upstreams = if yolo {
            settings.upstreams.native_grants()
        } else if actions.iter().any(|a| matches!(a, Action::ListUpstreams | Action::CallUpstream)) {
            let raw = settings.oauth.as_ref().and_then(|oauth| oauth.allowed_server_tools.as_ref())
                .ok_or("Unified OAuth requires exact upstream grants")?;
            settings.upstreams.unified_oauth_grants(raw).map_err(|_| "Unified OAuth upstream grants unavailable")?
        } else {
            crate::upstream::Grants::default()
        };
        Ok(Self {
            id,
            digest: [0u8; 32],
            expires_at,
            root,
            actions,
            tools,
            native_tool_preset: yolo,
            mode: if yolo {
                ExecutionMode::Yolo
            } else {
                ExecutionMode::Standard
            },
            disabled: false,
            explicit_extra_roots: false,
            skills: settings
                .skills
                .as_ref()
                .map(|s| s.enabled_names())
                .unwrap_or_default(),
            upstreams,
            yolo_revision: None,
            approval_mode: None,
            extra_roots: Vec::new(),
            mutation_root,
            job_runtime_limit_seconds: if yolo {
                crate::jobs::EXTENDED_RUNTIME_MAX
            } else {
                crate::jobs::SHORT_RUNTIME_MAX
            },
            native_default_timeout: yolo.then_some(crate::jobs::EXTENDED_RUNTIME_MAX),
            job_cpu_percent_limit: if yolo { 0 } else { 100 },
            job_memory_bytes_limit: if yolo { 0 } else { 256 * 1024 * 1024 },
            job_output_limit_bytes: 65_536,
            job_retention_count: Some(32),
            timeshift_retention_count: 64,
            job_extra_roots: Vec::new(),
            job_root,
            denied_actions: Vec::new(),
        })
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedOAuthSettings {
    pub enabled: bool,
    pub state_dir: PathBuf,
    pub local_client: String,
    pub workspace_edit: bool,
    pub workspace_tools: bool,
    pub workspace_jobs: bool,
    pub workspace_commands: bool,
    pub workspace_interactive: bool,
    pub workspace_upstreams: bool,
    pub allowed_server_tools: Option<Value>,
    pub funnel_advanced: bool,
}

#[cfg(target_os = "linux")]
impl UnifiedOAuthSettings {
    fn parse(value: &Value, policy_path: &Path, workspace: Option<&Path>, audit_log: Option<&Path>, job_state: Option<&Path>) -> Result<Self, String> {
        let obj = value
            .as_object()
            .ok_or("oauth configuration must be a JSON object")?;
        const KEYS: &[&str] = &[
            "enabled",
            "state_dir",
            "local_client",
            "workspace_edit",
            "workspace_tools",
            "workspace_jobs",
            "workspace_commands",
            "workspace_interactive",
            "workspace_upstreams",
            "allowed_server_tools",
            "funnel_advanced",
        ];
        if !obj.keys().all(|k| KEYS.contains(&k.as_str())) {
            return Err("Unknown field in oauth configuration".into());
        }
        let bool_field = |k: &str| -> Result<bool, String> {
            match obj.get(k) {
                None => Ok(false),
                Some(v) => v.as_bool().ok_or_else(|| format!("Invalid oauth.{k} flag")),
            }
        };
        let enabled = match obj.get("enabled") {
            None => true,
            Some(v) => v.as_bool().ok_or("Invalid oauth.enabled flag")?,
        };
        let raw_dir = obj
            .get("state_dir")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or("oauth.state_dir must be an absolute path")?;
        let state_dir = if raw_dir.exists() {
            raw_dir
                .canonicalize()
                .map_err(|_| "oauth.state_dir unavailable".to_owned())?
        } else {
            raw_dir
        };
        let overlaps = |a: &Path, b: &Path| a.starts_with(b) || b.starts_with(a);
        if workspace.is_some_and(|w| overlaps(&state_dir, w))
            || policy_path
                .canonicalize()
                .ok()
                .is_some_and(|cfg| overlaps(&state_dir, &cfg))
            || audit_log
                .and_then(Path::parent)
                .is_some_and(|a| overlaps(&state_dir, a))
            || job_state.is_some_and(|j| overlaps(&state_dir, j))
        {
            return Err("oauth.state_dir must remain separate from workspace, policy, audit, and jobs".into());
        }
        let local_client = match obj.get("local_client") {
            None => "veyl-oauth".to_owned(),
            Some(v) => v
                .as_str()
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= 64
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                })
                .ok_or("Invalid oauth.local_client")?
                .to_owned(),
        };
        let workspace_edit = bool_field("workspace_edit")?;
        let workspace_tools = bool_field("workspace_tools")?;
        let workspace_jobs = bool_field("workspace_jobs")?;
        let workspace_commands = bool_field("workspace_commands")?;
        let workspace_interactive = bool_field("workspace_interactive")?;
        let workspace_upstreams = bool_field("workspace_upstreams")?;
        let allowed_server_tools = obj.get("allowed_server_tools").cloned();
        if !workspace_upstreams && allowed_server_tools.is_some() {
            return Err("OAuth tool grants require oauth.workspace_upstreams".into());
        }
        let funnel_advanced = bool_field("funnel_advanced")?;
        if workspace_tools && !workspace_edit {
            return Err("oauth.workspace_tools requires oauth.workspace_edit".into());
        }
        if (workspace_commands || workspace_interactive) && !workspace_jobs {
            return Err("oauth interactive/command options require oauth.workspace_jobs".into());
        }
        Ok(Self {
            enabled,
            state_dir,
            local_client,
            workspace_edit,
            workspace_tools,
            workspace_jobs,
            workspace_commands,
            workspace_interactive,
            workspace_upstreams,
            allowed_server_tools,
            funnel_advanced,
        })
    }
}

#[cfg(target_os = "linux")]
fn canonical_credential_path(path: &Path) -> Result<PathBuf, &'static str> {
    match path.canonicalize() {
        Ok(canonical) => Ok(canonical),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !matches!(
                std::fs::symlink_metadata(path),
                Err(meta_err) if meta_err.kind() == std::io::ErrorKind::NotFound
            ) {
                return Err("Credential path unavailable");
            }
            let parent = path.parent().ok_or("Credential path unavailable")?;
            let name = path.file_name().ok_or("Credential path unavailable")?;
            Ok(parent
                .canonicalize()
                .map_err(|_| "Credential path unavailable")?
                .join(name))
        }
        Err(_) => Err("Credential path unavailable"),
    }
}

pub struct Configuration {
    #[cfg(target_os = "linux")]
    pub(crate) digest: [u8; 32],
    #[cfg(target_os = "linux")]
    pub(crate) oauth_binding_digest: [u8; 32],
    #[cfg(target_os = "linux")]
    pub audit_limits: mcp_gateway::security::audit::AuditLimits,
    pub clients: Vec<Client>,
    pub audit_log: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    pub(crate) admin_listen: Option<std::net::SocketAddr>,
    #[cfg(target_os = "linux")]
    pub(crate) tailnet: Option<crate::tailnet::Settings>,
    #[cfg(target_os = "linux")]
    pub(crate) cloudflare: Option<crate::cloudflare::Settings>,
    #[cfg(target_os = "linux")]
    pub runtime_settings: Value,
    #[cfg(target_os = "linux")]
    pub(crate) protected_paths: crate::protected_paths::Rules,
    #[cfg(target_os = "linux")]
    pub(crate) skills: Option<crate::skills::Skills>,
    #[cfg(target_os = "linux")]
    pub(crate) upstreams: crate::upstream::Catalog,
    #[cfg(target_os = "linux")]
    pub managed: bool,
    #[cfg(target_os = "linux")]
    pub policy_version: Option<u64>,
    #[cfg(target_os = "linux")]
    pub default_mode: mcp_gateway::core::oauth::ConnectionMode,
    #[cfg(target_os = "linux")]
    pub default_mode_configured: bool,
    #[cfg(target_os = "linux")]
    pub workspace: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    pub oauth: Option<UnifiedOAuthSettings>,
    #[cfg(target_os = "linux")]
    pub jobs: Option<(PathBuf, Profiles)>,
    #[cfg(target_os = "linux")]
    reserved_job_state: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
impl Configuration {
    pub(crate) fn job_state_path(&self) -> Option<&Path> {
        self.jobs
            .as_ref()
            .map(|(path, _)| path.as_path())
            .or(self.reserved_job_state.as_deref())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn load_clients(path: &Path) -> Result<Configuration, String> {
    parse_clients(path, &read_config(path)?)
}

pub(crate) fn parse_clients(path: &Path, bytes: &[u8]) -> Result<Configuration, String> {
    if !path.is_absolute() {
        return Err("credential config requires an absolute path".into());
    }
    let document = parse_document(bytes)?;
    #[cfg(target_os = "linux")]
    let upstreams = crate::upstream::Catalog::parse(&document)?;
    let audit_log = document
        .get("audit_log")
        .map(|value| {
            value
                .as_str()
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .ok_or("audit_log must be an absolute path")
        })
        .transpose()?;
    let has_job_profiles = document.get("job_profiles").is_some();
    #[cfg(target_os = "linux")]
    let reserved_job_state = if has_job_profiles {
        None
    } else {
        document
            .get("job_state_dir")
            .map(|value| {
                let state = value
                    .as_str()
                    .map(PathBuf::from)
                    .ok_or("Invalid job_state_dir")?;
                crate::protected_paths::validate_path(&state)?;
                Ok::<_, String>(state)
            })
            .transpose()?
    };
    #[cfg(target_os = "linux")]
    let jobs = if has_job_profiles {
        let (state, profiles) = crate::jobs::parse_settings(bytes)?;
        let audit = audit_log
            .as_ref()
            .ok_or("Job configuration requires audit_log")?;
        let credentials = canonical_credential_path(path)?;
        if state == *audit || audit.starts_with(&state) || credentials.starts_with(&state) {
            return Err("Job state must be separate from credentials and audit log".into());
        }
        Some((state, profiles))
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    if has_job_profiles || document.get("job_state_dir").is_some() {
        return Err("Job configuration is supported only on Linux".into());
    }
    #[cfg(target_os = "linux")]
    let job_state = jobs
        .as_ref()
        .map(|(state, _)| state.as_path())
        .or(reserved_job_state.as_deref());
    let entries = document
        .get("clients")
        .and_then(Value::as_array)
        .ok_or("credential config must contain a clients array")?;
    let unified_empty_allowed = document["policy_version"].as_u64() == Some(4)
        && (document.get("default_mode").is_some()
            || document.get("workspace").is_some()
            || document.get("oauth").is_some());
    if (entries.is_empty() && !unified_empty_allowed) || entries.len() > 256 {
        return Err("credential config client count is invalid".into());
    }

    let mut clients = Vec::with_capacity(entries.len());
    let mut identities = HashSet::new();
    let mut verifiers = HashSet::new();
    for entry in entries {
        let field = |key: &str| entry.get(key).and_then(Value::as_str);
        #[cfg(target_os = "linux")]
        let mode = Mode::from_entry(entry, document["policy_version"].as_u64())?;
        #[cfg(not(target_os = "linux"))]
        let mode = if entry.get("mode").is_none() {
            ExecutionMode::Standard
        } else {
            return Err("Persistent authorization requires Linux".into());
        };
        #[cfg(target_os = "linux")]
        let yolo_revision = match (mode, entry.get("yolo_revision")) {
            (Mode::ScopedYolo | Mode::BroadYolo | Mode::Full | Mode::NativeYolo, Some(value)) => Some(
                value
                    .as_str()
                    .filter(|id| {
                        id.len() == 32
                            && id
                                .bytes()
                                .all(|byte| matches!(byte, b'a'..=b'f' | b'0'..=b'9'))
                    })
                    .ok_or("Invalid YOLO policy revision")?
                    .to_owned(),
            ),
            (Mode::ScopedYolo | Mode::BroadYolo | Mode::Full | Mode::NativeYolo, None) => {
                return Err("Privileged mode requires a policy revision".into());
            }
            (_, Some(_)) => return Err("Inactive client has retained a YOLO revision".into()),
            (_, None) => None,
        };
        let id = field("id").ok_or("missing client identity")?;
        if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
            return Err("invalid client identity".into());
        }
        let digest = decode_sha256(field("token_sha256").ok_or("missing token verifier")?)?;
        if !identities.insert(id.to_string()) || !verifiers.insert(digest) {
            return Err("duplicate client identity or token verifier".into());
        }
        let expires_at = entry
            .get("expires_at_unix_seconds")
            .and_then(Value::as_u64)
            .ok_or("missing credential expiry")?;
        let configured_root = PathBuf::from(field("root").ok_or("missing client root")?);
        if !configured_root.is_absolute() {
            return Err("client root must be absolute".into());
        }
        let root = configured_root
            .canonicalize()
            .map_err(|_| "client root is unavailable".to_string())?;
        #[cfg(target_os = "linux")]
        if (audit_log.is_some() || job_state.is_some() || mode == Mode::ScopedYolo)
            && protected(path, audit_log.as_deref(), job_state, &root)
        {
            return Err("Client root overlaps protected gateway state".into());
        }
        if !root.is_dir() {
            return Err("client root must be an existing directory".into());
        }
        #[cfg(target_os = "linux")]
        let approval_mode = yolo_revision.as_ref().map(|_| {
            match (mode, entry["native_tool_preset"] == true) {
                (Mode::BroadYolo, true) => "yolo_native",
                (Mode::NativeYolo, true) => "native_yolo_preset",
                _ => mode.label(),
            }
        });
        let native_tool_preset = document["policy_version"] == 4 && entry["native_tool_preset"] == true;
        #[cfg(target_os = "linux")]
        let native_limits = mode == Mode::NativeYolo && native_tool_preset;
        #[cfg(target_os = "linux")]
        let native_execution = matches!(mode, Mode::Full | Mode::NativeYolo);
        let (names, actions, denied_actions) = effective_tools(
            entry,
            native_tool_preset,
            has_job_profiles && cfg!(target_os = "linux"),
            document.get("skills_dir").is_some() && cfg!(target_os = "linux"),
        )?;
        let has_job_grant = actions.iter().any(|action| action.is_job());
        #[cfg(target_os = "linux")]
        let mutation_root = if actions.iter().any(|action| {
            matches!(
                action,
                Action::ReadFile
                    | Action::WriteFile
                    | Action::ApplyPatch
                    | Action::SearchFiles
                    | Action::GitInspect
                    | Action::GitStatus
                    | Action::GitDiff
                    | Action::GitLog
                    | Action::GitAdd
                    | Action::GitCommit
                    | Action::GitBranch
                    | Action::GitCheckout
                    | Action::GitRestore
                    | Action::GitStash
                    | Action::GitReset
                    | Action::GitPull
                    | Action::GitPush
                    | Action::SystemInfo
                    | Action::SystemInspect
                    | Action::ProjectContext
                    | Action::SystemContext
                    | Action::LoadPathRules
                    | Action::Remember
                    | Action::ChezmoiInspect
                    | Action::ListProjectSkills
                    | Action::LoadProjectSkill
                    | Action::SkillsValidate
                    | Action::ExtensionsInspect
            )
        }) {
            Some(
                MutationRoot::open(&configured_root)
                    .map_err(|_| "Client root must be an existing symlink-free directory")?,
            )
        } else {
            None
        };
        #[cfg(target_os = "linux")]
        if let Some((state, profiles)) = &jobs {
            let credentials = canonical_credential_path(path)?;
            let audit = audit_log.as_ref().expect("job settings require audit log");
            if state.starts_with(&root)
                || root.starts_with(state)
                || credentials.starts_with(&root)
                || audit.starts_with(&root)
            {
                return Err(
                    "Job state, credentials and audit log must be outside client roots".into(),
                );
            }
            if mutation_root.is_some() {
                profiles.reject_mutable_executables(&root)?;
            }
        }
        #[cfg(target_os = "linux")]
        let extra_roots = open_extra_roots(
            &document,
            entry,
            &root,
            path,
            audit_log.as_deref(),
            job_state,
        )?;
        #[cfg(target_os = "linux")]
        let job_extra_roots =
            if has_job_grant && matches!(document["policy_version"].as_u64(), Some(3 | 4)) {
                let key = "extra_roots";
                let roots = super::scope::root_paths(entry, key)?;
                if let Some((_, profiles)) = &jobs {
                    for root in &roots {
                        profiles.reject_mutable_executables(root)?;
                    }
                }
                roots
                    .iter()
                    .map(|root| JobRoot::open(root))
                    .collect::<Result<_, _>>()?
            } else {
                Vec::new()
            };
        #[cfg(target_os = "linux")]
        let upstream_grants = {
            let explicit = crate::upstream::Grants::parse(entry, &upstreams)?;
            if native_tool_preset && explicit.servers.is_empty() {
                upstreams.native_grants()
            } else {
                explicit
            }
        };
        clients.push(Client {
            id: id.to_string(),
            digest,
            expires_at,
            root,
            actions,
            tools: names,
            native_tool_preset,
            mode: mode.into(),
            disabled: entry["disabled"].as_bool().unwrap_or(false),
            #[cfg(target_os = "linux")]
            explicit_extra_roots: matches!(document["policy_version"].as_u64(), Some(3 | 4))
                && mode == Mode::Standard,
            #[cfg(target_os = "linux")]
            skills: crate::skills::parse_names(entry.get("skills"))?,
            #[cfg(target_os = "linux")]
            upstreams: upstream_grants,
            #[cfg(target_os = "linux")]
            yolo_revision,
            #[cfg(target_os = "linux")]
            approval_mode,
            #[cfg(target_os = "linux")]
            extra_roots,
            #[cfg(target_os = "linux")]
            job_extra_roots,
            #[cfg(target_os = "linux")]
            mutation_root,
            #[cfg(target_os = "linux")]
            native_default_timeout: entry["job_runtime_limit_seconds"].as_u64(),
            #[cfg(target_os = "linux")]
            job_runtime_limit_seconds: entry
                .get("job_runtime_limit_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(if native_limits { crate::jobs::EXTENDED_RUNTIME_MAX } else { crate::jobs::SHORT_RUNTIME_MAX }),
            #[cfg(target_os = "linux")]
            job_cpu_percent_limit: entry
                .get("job_cpu_percent_limit")
                .and_then(Value::as_u64)
                .unwrap_or(if native_execution { 0 } else { 100 }),
            #[cfg(target_os = "linux")]
            job_memory_bytes_limit: entry
                .get("job_memory_bytes_limit")
                .and_then(Value::as_u64)
                .unwrap_or(if native_execution { 0 } else { 256 * 1024 * 1024 }),
            #[cfg(target_os = "linux")]
            job_output_limit_bytes: entry
                .get("job_output_limit_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(65_536) as usize,
            #[cfg(target_os = "linux")]
            timeshift_retention_count: entry
                .get("timeshift_retention_count")
                .and_then(Value::as_u64)
                .unwrap_or(64) as usize,
            #[cfg(target_os = "linux")]
            job_retention_count: entry
                .get("job_retention_count")
                .and_then(Value::as_u64)
                .map(|n| n as usize),
            #[cfg(target_os = "linux")]
            job_root: if has_job_grant {
                Some(JobRoot::open(&configured_root)?)
            } else {
                None
            },
            #[cfg(target_os = "linux")]
            denied_actions,
        });
    }
    #[cfg(target_os = "linux")]
    let (default_mode, default_mode_configured) = match document.get("default_mode") {
        None => (mcp_gateway::core::oauth::ConnectionMode::Standard, false),
        Some(raw) => (
            raw.as_str()
                .and_then(mcp_gateway::core::oauth::ConnectionMode::parse)
                .ok_or("Invalid default_mode")?,
            true,
        ),
    };
    #[cfg(target_os = "linux")]
    let workspace = document
        .get("workspace")
        .map(|value| {
            let raw = value
                .as_str()
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .ok_or("workspace must be an absolute path")?;
            let canonical = raw
                .canonicalize()
                .map_err(|_| "workspace directory is unavailable".to_owned())?;
            if !canonical.is_dir() {
                return Err("workspace must be an existing directory".to_owned());
            }
            if protected(path, audit_log.as_deref(), job_state, &canonical) {
                return Err("workspace overlaps protected gateway state".into());
            }
            Ok::<_, String>(canonical)
        })
        .transpose()?;
    #[cfg(target_os = "linux")]
    let oauth_settings = document
        .get("oauth")
        .map(|value| {
            UnifiedOAuthSettings::parse(
                value,
                path,
                workspace.as_deref(),
                audit_log.as_deref(),
                job_state,
            )
        })
        .transpose()?;
    #[cfg(target_os = "linux")]
    if let Some(map) = oauth_settings.as_ref().and_then(|oauth| oauth.allowed_server_tools.as_ref()) {
        upstreams.unified_oauth_grants(map)?;
    }
    #[cfg(target_os = "linux")]
    let cloudflare = document
        .get("cloudflare_tunnel")
        .map(crate::cloudflare::Settings::parse)
        .transpose()?;
    #[cfg(target_os = "linux")]
    let tailnet = document
        .get("tailscale_serve")
        .map(crate::tailnet::Settings::parse)
        .transpose()?;
    #[cfg(target_os = "linux")]
    if cloudflare.is_some() && tailnet.is_some() {
        return Err("Configure either tailscale_serve or cloudflare_tunnel, not both".into());
    }
    #[cfg(target_os = "linux")]
    let mut runtime_settings = document.clone();
    #[cfg(target_os = "linux")]
    {
        let static_fields = runtime_settings
            .as_object_mut()
            .ok_or("invalid credential configuration")?;
        static_fields.remove("clients");
        static_fields.remove("policy_version");
        static_fields.remove("protected_paths");
        static_fields.remove("skills_disabled");
        static_fields.remove("mcp_servers");
        static_fields.remove("default_mode");
        static_fields.remove("migrated_from");
        // Credential rotation is visible at the next admission.
        if let Some(funnel) = static_fields
            .get_mut("tailscale_serve")
            .and_then(|serve| serve.get_mut("funnel"))
            .and_then(Value::as_object_mut)
        {
            funnel.remove("token_sha256");
        }
    }
    #[cfg(target_os = "linux")]
    let oauth_binding_digest: [u8; 32] = {
        let mut stable = runtime_settings.clone();
        if let Some(obj) = stable.as_object_mut() {
            if let Some(protected_rules) = document.get("protected_paths") {
                obj.insert("protected_paths".into(), protected_rules.clone());
            }
            if let Some(servers) = document.get("mcp_servers") {
                obj.insert("mcp_servers".into(), servers.clone());
            }
        }
        Sha256::digest(stable.to_string().as_bytes()).into()
    };
    #[cfg(target_os = "linux")]
    let protected_paths = crate::protected_paths::Rules::parse(&document)?;
    #[allow(unused_mut)]
    let mut settings = Configuration {
        #[cfg(target_os = "linux")]
        digest: Sha256::digest(bytes).into(),
        #[cfg(target_os = "linux")]
        oauth_binding_digest,
        #[cfg(target_os = "linux")]
        audit_limits: mcp_gateway::security::audit::AuditLimits::from_config(&document)
            .map_err(|error| error.to_string())?,
        clients,
        audit_log,
        #[cfg(target_os = "linux")]
        tailnet,
        #[cfg(target_os = "linux")]
        cloudflare,
        #[cfg(target_os = "linux")]
        admin_listen: document
            .get("admin_listen")
            .map(super::dashboard::parse_listen)
            .transpose()?,
        #[cfg(target_os = "linux")]
        runtime_settings,
        #[cfg(target_os = "linux")]
        managed: document.get("policy_version").is_some(),
        #[cfg(target_os = "linux")]
        policy_version: document["policy_version"].as_u64(),
        #[cfg(target_os = "linux")]
        default_mode,
        #[cfg(target_os = "linux")]
        default_mode_configured,
        #[cfg(target_os = "linux")]
        workspace,
        #[cfg(target_os = "linux")]
        oauth: oauth_settings,
        #[cfg(target_os = "linux")]
        jobs,
        #[cfg(target_os = "linux")]
        reserved_job_state,
        #[cfg(target_os = "linux")]
        protected_paths,
        #[cfg(target_os = "linux")]
        skills: None,
        #[cfg(target_os = "linux")]
        upstreams,
    };
    #[cfg(target_os = "linux")]
    for kind in [
        crate::protected_paths::Kind::Optional,
        crate::protected_paths::Kind::ReadOnly,
    ] {
        for rule in settings.protected_paths.selected(kind) {
            crate::protected_paths::check_conflicts(path, &settings, &rule.path, kind)?;
        }
    }
    #[cfg(target_os = "linux")]
    {
        settings.skills = crate::skills::Skills::load(path, &document, &settings)?;
        for client in &settings.clients {
            client
                .upstreams
                .validate_workspaces(path, &settings, client)?;
        }
        if let Some(funnel) = settings
            .tailnet
            .as_ref()
            .and_then(|serve| serve.funnel.as_ref())
        {
            funnel.validate(&settings)?;
        }
    }
    Ok(settings)
}

type EffectiveTools = (HashSet<Tool>, Vec<Action>, Vec<Action>);

fn effective_tools(
    entry: &Value,
    preset: bool,
    jobs: bool,
    skills: bool,
) -> Result<EffectiveTools, String> {
    let allowed = entry["tools"]
        .as_array()
        .ok_or("client tools must be an array")?;
    let mut tools = HashSet::new();
    let mut seen_instruction_run = false;
    for grant in allowed {
        let name = grant.as_str().ok_or("unsupported tool grant")?;
        // Older skill manifests tolerated this reserved, non-executable name.
        if name == "skills_run" && skills && !seen_instruction_run {
            seen_instruction_run = true;
            continue;
        }
        let tool = Tool::parse(name).ok_or("unsupported tool grant")?;
        if matches!(tool, Tool::SkillsList | Tool::SkillsRead) && !skills {
            return Err("Skill tools require a configured Linux skills directory".into());
        }
        if tool.action().is_job() && !jobs {
            return Err("Job grants require private Linux job configuration".into());
        }
        if !tools.insert(tool) {
            return Err("duplicate tool grant".into());
        }
    }
    let mut denied = HashSet::new();
    if let Some(value) = entry.get("deny_tools") {
        for denial in value.as_array().ok_or("deny_tools must be an array")? {
            let tool = denial
                .as_str()
                .and_then(Tool::parse)
                .ok_or("unsupported tool denial")?;
            if !denied.insert(tool) {
                return Err("duplicate tool denial".into());
            }
        }
    }
    if preset {
        tools.extend(
            Tool::ALL
                .into_iter()
                .filter(|tool| tool.in_yolo_preset(jobs, skills)),
        );
    }
    // A denial covers every name that can perform the denied action.
    tools.retain(|tool| !denied.iter().any(|denial| denial.action() == tool.action()));
    let mut denied_actions = Vec::new();
    for tool in &denied {
        let action = tool.action();
        if !denied_actions.contains(&action) {
            denied_actions.push(action);
        }
    }
    let mut actions = Vec::new();
    for tool in Tool::ALL.into_iter().filter(|tool| tools.contains(tool)) {
        if !actions.contains(&tool.action()) {
            actions.push(tool.action());
        }
    }
    if !actions.is_empty() {
        actions.push(Action::ListTools);
    }
    Ok((tools, actions, denied_actions))
}

pub(crate) fn parse_document(bytes: &[u8]) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    return super::operator::parse_document(bytes);
    #[cfg(not(target_os = "linux"))]
    serde_json::from_slice(bytes).map_err(|_| "invalid credential configuration".into())
}

#[cfg(target_os = "linux")]
pub(crate) fn read_config(path: &Path) -> Result<Vec<u8>, String> {
    read_config_version(path).map(|(bytes, _)| bytes)
}

#[cfg(target_os = "linux")]
#[derive(Eq, PartialEq)]
pub(super) struct ConfigStamp {
    device: u64,
    inode: u64,
    changed: (i64, i64),
}

#[cfg(target_os = "linux")]
pub(super) fn read_config_version(path: &Path) -> Result<(Vec<u8>, ConfigStamp), String> {
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    use mcp_gateway::security::linux_fs::{open_operator_dir, reopen_regular};
    use rustix::fs::{self, Mode, OFlags};

    let parent = open_operator_dir(path.parent().ok_or("invalid credential path")?)
        .map_err(|_| "credential directory unavailable")?;
    let handle = fs::openat(
        &parent,
        path.file_name().ok_or("invalid credential path")?,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "credential config unavailable")?;
    let file = File::from(
        reopen_regular(handle, OFlags::RDONLY).map_err(|_| "credential config cannot be read")?,
    );
    let meta = file
        .metadata()
        .map_err(|_| "credential config unavailable")?;
    if meta.mode() & 0o7177 != 0
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.nlink() != 1
    {
        return Err("credential config must be private and owned by the gateway user".into());
    }
    let stamp = |meta: &std::fs::Metadata| ConfigStamp {
        device: meta.dev(),
        inode: meta.ino(),
        changed: (meta.ctime(), meta.ctime_nsec()),
    };
    let version = stamp(&meta);
    let mut bytes = Vec::new();
    (&file)
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "credential config cannot be read")?;
    if bytes.len() > 65_536 {
        return Err("credential config exceeds size limit".into());
    }
    let after = file
        .metadata()
        .map_err(|_| "credential config unavailable")?;
    if stamp(&after) != version {
        return Err("credential config changed while being read".into());
    }
    Ok((bytes, version))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_config(path: &Path) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "credential config is unavailable".to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("credential config must be an ordinary file, not a symlink".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("credential config is accessible to group or others".into());
        }
    }
    if metadata.len() > 65_536 {
        return Err("credential config exceeds size limit".into());
    }
    let bytes = fs::read(path).map_err(|_| "credential config cannot be read".to_string())?;
    if bytes.len() > 65_536 {
        return Err("credential config exceeds size limit".into());
    }
    Ok(bytes)
}

pub fn authenticate(clients: &[Client], header: Option<&HeaderValue>, now: u64) -> Option<usize> {
    let candidate = mcp_gateway::http_common::bearer(header?)?;
    select_client(
        &candidate,
        clients
            .iter()
            .map(|c| (c.digest, now < c.expires_at && !c.is_disabled())),
    )
}
