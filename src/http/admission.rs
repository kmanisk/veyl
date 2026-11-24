//! Protected local credential configuration and constant-time bearer lookup.
//! No raw bearer tokens are stored or displayed by the HTTP service.

use std::collections::HashSet;
#[cfg(not(target_os = "linux"))]
use std::fs;
use std::path::{Path, PathBuf};

use hyper::header::HeaderValue;
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
    pub extra_roots: Vec<MutationRoot>,
    #[cfg(target_os = "linux")]
    pub mutation_root: Option<MutationRoot>,
    #[cfg(target_os = "linux")]
    pub job_root: Option<JobRoot>,
    #[cfg(target_os = "linux")]
    pub job_extra_roots: Vec<JobRoot>,
}

#[cfg(target_os = "linux")]
impl Client {
    pub(super) fn has_digest(&self, value: &[u8; 32]) -> bool {
        bool::from(self.digest.ct_eq(value))
    }
}

pub struct Configuration {
    #[cfg(target_os = "linux")]
    pub audit_limits: mcp_gateway::security::audit::AuditLimits,
    pub clients: Vec<Client>,
    pub audit_log: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    pub(crate) admin_listen: Option<std::net::SocketAddr>,
    #[cfg(target_os = "linux")]
    pub(crate) tailnet: Option<crate::tailnet::Settings>,
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
        let credentials = path
            .canonicalize()
            .map_err(|_| "Credential path unavailable")?;
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
    if entries.is_empty() || entries.len() > 256 {
        return Err("credential config client count is invalid".into());
    }

    let mut clients = Vec::with_capacity(entries.len());
    let mut identities = HashSet::new();
    let mut verifiers = HashSet::new();
    for entry in entries {
        let field = |key: &str| entry.get(key).and_then(Value::as_str);
        #[cfg(target_os = "linux")]
        let mode = Mode::from_entry(entry)?;
        #[cfg(not(target_os = "linux"))]
        let mode = if entry.get("mode").is_none() {
            ExecutionMode::Standard
        } else {
            return Err("Persistent authorization requires Linux".into());
        };
        #[cfg(target_os = "linux")]
        let yolo_revision = match (mode, entry.get("yolo_revision")) {
            (Mode::ScopedYolo | Mode::BroadYolo | Mode::Full, Some(value)) => Some(
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
            (Mode::ScopedYolo | Mode::BroadYolo | Mode::Full, None) => {
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
        let allowed = entry
            .get("tools")
            .and_then(Value::as_array)
            .ok_or("client tools must be an array")?;
        let mut actions = Vec::new();
        let mut names = HashSet::new();
        let mut seen_instruction_run = false;
        for tool in allowed {
            let label = tool.as_str().ok_or("unsupported tool grant")?;
            // The instruction package format defines no executable entry point.
            if label == "skills_run" && document.get("skills_dir").is_some() {
                if seen_instruction_run {
                    return Err("duplicate tool grant".into());
                }
                seen_instruction_run = true;
                continue;
            }
            let tool = Tool::parse(label).ok_or("unsupported tool grant")?;
            if matches!(tool, Tool::SkillsList | Tool::SkillsRead)
                && (!cfg!(target_os = "linux") || document.get("skills_dir").is_none())
            {
                return Err("Skill tools require a configured Linux skills directory".into());
            }
            if !names.insert(tool) {
                return Err("duplicate tool grant".into());
            }
            if !actions.contains(&tool.action()) {
                actions.push(tool.action());
            }
        }
        if !actions.is_empty() {
            actions.push(Action::ListTools);
        }
        let has_job_grant = actions.iter().any(|action| action.is_job());
        if has_job_grant && (!has_job_profiles || !cfg!(target_os = "linux")) {
            return Err("Job grants require private Linux job configuration".into());
        }
        #[cfg(target_os = "linux")]
        let mutation_root = if actions.iter().any(|action| {
            matches!(
                action,
                Action::ReadFile
                    | Action::WriteFile
                    | Action::ApplyPatch
                    | Action::SearchFiles
                    | Action::GitInspect
                    | Action::SystemInfo
                    | Action::SystemInspect
                    | Action::ProjectContext
                    | Action::SystemContext
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
            let credentials = path
                .canonicalize()
                .map_err(|_| "Credential path unavailable")?;
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
            if has_job_grant && (mode == Mode::ScopedYolo || document["policy_version"] == 3) {
                let key = if document["policy_version"] == 3 {
                    "extra_roots"
                } else {
                    "yolo_roots"
                };
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
        let upstream_grants = crate::upstream::Grants::parse(entry, &upstreams)?;
        clients.push(Client {
            id: id.to_string(),
            digest,
            expires_at,
            root,
            actions,
            tools: names,
            mode: mode.into(),
            disabled: entry["disabled"].as_bool().unwrap_or(false),
            #[cfg(target_os = "linux")]
            explicit_extra_roots: document["policy_version"] == 3 && mode == Mode::Standard,
            #[cfg(target_os = "linux")]
            skills: crate::skills::parse_names(entry.get("skills"))?,
            #[cfg(target_os = "linux")]
            upstreams: upstream_grants,
            #[cfg(target_os = "linux")]
            yolo_revision,
            #[cfg(target_os = "linux")]
            extra_roots,
            #[cfg(target_os = "linux")]
            job_extra_roots,
            #[cfg(target_os = "linux")]
            mutation_root,
            #[cfg(target_os = "linux")]
            job_root: if has_job_grant {
                Some(JobRoot::open(&configured_root)?)
            } else {
                None
            },
        });
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
    let protected_paths = crate::protected_paths::Rules::parse(&document)?;
    #[allow(unused_mut)]
    let mut settings = Configuration {
        #[cfg(target_os = "linux")]
        audit_limits: mcp_gateway::security::audit::AuditLimits::from_config(&document)
            .map_err(|error| error.to_string())?,
        clients,
        audit_log,
        #[cfg(target_os = "linux")]
        tailnet: document
            .get("tailscale_serve")
            .map(crate::tailnet::Settings::parse)
            .transpose()?,
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

pub(super) fn decode_sha256(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid token verifier encoding".into());
    }
    let mut digest = [0_u8; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
            .map_err(|_| "invalid token verifier encoding")?;
    }
    Ok(digest)
}

pub fn authenticate(clients: &[Client], header: Option<&HeaderValue>, now: u64) -> Option<usize> {
    let header = header?.to_str().ok()?;
    let token = header.strip_prefix("Bearer ")?;
    let candidate = token_digest(token)?;
    let mut found = None;
    for (index, client) in clients.iter().enumerate() {
        // Inspect every verifier, even after a match.
        let matched: bool = client.digest.ct_eq(&candidate).into();
        if matched
            && now < client.expires_at
            && !client.disabled
            && client.mode != ExecutionMode::Disabled
        {
            found = Some(index);
        }
    }
    found
}

pub(super) fn token_shape(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

pub(super) fn token_digest(token: &str) -> Option<[u8; 32]> {
    token_shape(token).then(|| Sha256::digest(token.as_bytes()).into())
}
