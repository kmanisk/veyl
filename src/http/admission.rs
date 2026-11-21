//! Protected local credential configuration and constant-time bearer lookup.
//! No raw bearer tokens are stored or displayed by the HTTP service.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use hyper::header::HeaderValue;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use mcp_gateway::security::policy::Action;

pub struct Client {
    pub id: String,
    digest: [u8; 32],
    pub expires_at: u64,
    pub root: PathBuf,
    pub actions: Vec<Action>,
}

pub fn load_clients(path: &Path) -> Result<Vec<Client>, String> {
    if !path.is_absolute() {
        return Err("credential config requires an absolute path".into());
    }
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
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "invalid credential configuration".to_string())?;
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
        let root = PathBuf::from(field("root").ok_or("missing client root")?);
        if !root.is_absolute() {
            return Err("client root must be absolute".into());
        }
        let root = root
            .canonicalize()
            .map_err(|_| "client root is unavailable".to_string())?;
        if !root.is_dir() {
            return Err("client root must be an existing directory".into());
        }
        let allowed = entry
            .get("tools")
            .and_then(Value::as_array)
            .ok_or("client tools must be an array")?;
        if allowed.len() > 1 {
            return Err("duplicate or unsupported tool grant".into());
        }
        let mut actions = Vec::new();
        for tool in allowed {
            if tool.as_str() != Some("read_file") {
                return Err("unsupported tool grant".into());
            }
            actions.push(Action::ReadFile);
            actions.push(Action::ListTools);
        }
        clients.push(Client {
            id: id.to_string(),
            digest,
            expires_at,
            root,
            actions,
        });
    }
    Ok(clients)
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
