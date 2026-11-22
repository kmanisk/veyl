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
use mcp_gateway::security::policy::Action;

pub struct Client {
    pub id: String,
    digest: [u8; 32],
    pub expires_at: u64,
    pub root: PathBuf,
    pub actions: Vec<Action>,
    #[cfg(target_os = "linux")]
    pub mutation_root: Option<MutationRoot>,
    #[cfg(target_os = "linux")]
    pub job_root: Option<JobRoot>,
}

pub struct Configuration {
    #[cfg(target_os = "linux")]
    pub audit_limits: mcp_gateway::security::audit::AuditLimits,
    pub clients: Vec<Client>,
    pub audit_log: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    pub jobs: Option<(PathBuf, Profiles)>,
}

pub fn load_clients(path: &Path) -> Result<Configuration, String> {
    if !path.is_absolute() {
        return Err("credential config requires an absolute path".into());
    }
    let bytes = read_config(path)?;
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "invalid credential configuration".to_string())?;
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
    let has_job_settings =
        document.get("job_state_dir").is_some() || document.get("job_profiles").is_some();
    #[cfg(target_os = "linux")]
    let jobs = if has_job_settings {
        let (state, profiles) = crate::jobs::parse_settings(&bytes)?;
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
    if has_job_settings {
        return Err("Job configuration is supported only on Linux".into());
    }
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
        if !root.is_dir() {
            return Err("client root must be an existing directory".into());
        }
        let allowed = entry
            .get("tools")
            .and_then(Value::as_array)
            .ok_or("client tools must be an array")?;
        let mut actions = Vec::new();
        let mut names = HashSet::new();
        for tool in allowed {
            let tool = tool
                .as_str()
                .and_then(Tool::parse)
                .ok_or("unsupported tool grant")?;
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
        if has_job_grant && (!has_job_settings || !cfg!(target_os = "linux")) {
            return Err("Job grants require private Linux job configuration".into());
        }
        #[cfg(target_os = "linux")]
        let mutation_root =
            if actions.contains(&Action::WriteFile) || actions.contains(&Action::ApplyPatch) {
                Some(
                    MutationRoot::open(&configured_root)
                        .map_err(|_| "mutation root must be an existing symlink-free directory")?,
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
        clients.push(Client {
            id: id.to_string(),
            digest,
            expires_at,
            root,
            actions,
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
    Ok(Configuration {
        #[cfg(target_os = "linux")]
        audit_limits: mcp_gateway::security::audit::AuditLimits::from_config(&document)
            .map_err(|error| error.to_string())?,
        clients,
        audit_log,
        #[cfg(target_os = "linux")]
        jobs,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn read_config(path: &Path) -> Result<Vec<u8>, String> {
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
    let mut bytes = Vec::new();
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "credential config cannot be read")?;
    if bytes.len() > 65_536 {
        return Err("credential config exceeds size limit".into());
    }
    Ok(bytes)
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

fn decode_sha256(value: &str) -> Result<[u8; 32], String> {
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
    if token.len() != 64
        || !token
            .bytes()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return None;
    }
    let candidate = Sha256::digest(token.as_bytes());
    let mut found = None;
    for (index, client) in clients.iter().enumerate() {
        // Inspect every verifier, even after a match.
        let matched: bool = client.digest.ct_eq(candidate.as_slice()).into();
        if matched && now < client.expires_at {
            found = Some(index);
        }
    }
    found
}
