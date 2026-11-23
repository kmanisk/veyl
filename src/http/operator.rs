//! Trusted local policy storage and explicitly approved filesystem scopes.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use mcp_gateway::security::audit::{AuditPhase, AuditSink};
use mcp_gateway::security::linux_fs::{open_operator_dir, reopen_regular};
use mcp_gateway::security::policy::ExecutionMode;
use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode as FileMode, OFlags};
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::admission::{
    ConfigStamp, Configuration, parse_clients, read_config, read_config_version,
};

const PRIVATE: FileMode = FileMode::RUSR.union(FileMode::WUSR);
const CREATE: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum Mode {
    Standard,
    ScopedYolo,
    BroadYolo,
    Full,
    Disabled,
}

impl Mode {
    pub(crate) fn from_entry(entry: &Value) -> Result<Self, String> {
        match entry.get("mode") {
            None => Ok(Self::Standard),
            Some(value) => match value.as_str() {
                Some("standard") => Ok(Self::Standard),
                Some("yolo") => Ok(Self::ScopedYolo),
                Some("broad_yolo") => Ok(Self::BroadYolo),
                Some("full") => Ok(Self::Full),
                Some("disabled") => Ok(Self::Disabled),
                _ => Err("Invalid client authorization mode".into()),
            },
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::ScopedYolo => "yolo",
            Self::BroadYolo => "broad_yolo",
            Self::Full => "full",
            Self::Disabled => "disabled",
        }
    }
}

impl From<Mode> for ExecutionMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::Standard,
            Mode::ScopedYolo => Self::PersistentYolo,
            Mode::BroadYolo => Self::BroadYolo,
            Mode::Full => Self::Full,
            Mode::Disabled => Self::Disabled,
        }
    }
}

pub(super) struct PolicyCache {
    path: PathBuf,
    snapshot: Mutex<CachedPolicy>,
}

pub(crate) fn require_completed_legacy_jobs(settings: &Configuration) -> Result<(), String> {
    if let Some((state, _)) = &settings.jobs
        && crate::jobs::has_unconfined_jobs(state)
            .map_err(|_| "Cannot verify legacy job state before enabling managed policy")?
    {
        return Err("Wait for legacy jobs to finish before enabling managed policy".into());
    }
    Ok(())
}

pub(crate) fn verify_approvals(settings: &Configuration) -> Result<(), String> {
    let expected: Vec<_> = settings
        .clients
        .iter()
        .filter_map(|client| {
            client.yolo_revision.as_deref().map(|revision| {
                (
                    client.id.as_str(),
                    revision,
                    client.mode.audit_mode().unwrap_or("disabled"),
                )
            })
        })
        .collect();
    if expected.is_empty() {
        return Ok(());
    }
    let audit = settings
        .audit_log
        .as_deref()
        .ok_or("Managed YOLO requires a private audit ledger")?;
    AuditSink::verify_mode_approvals(audit, &expected)
        .map_err(|_| "Cannot verify durable YOLO authorization".into())
}

pub(crate) fn revision() -> io::Result<String> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| io::Error::other("secure randomness unavailable"))?;
    Ok(format!("{:032x}", u128::from_ne_bytes(nonce)))
}

struct CachedPolicy {
    bytes: Vec<u8>,
    stamp: ConfigStamp,
    settings: Arc<Configuration>,
}

impl PolicyCache {
    pub(super) fn open(path: &Path) -> Result<(Self, Arc<Configuration>), String> {
        let policy = PolicyFile::lock(path, false)?;
        let (bytes, stamp) = policy.admitted_snapshot()?;
        let settings = Arc::new(parse_clients(path, &bytes)?);
        Ok((
            Self {
                path: path.to_owned(),
                snapshot: Mutex::new(CachedPolicy {
                    bytes,
                    stamp,
                    settings: settings.clone(),
                }),
            },
            settings,
        ))
    }

    pub(super) fn read(&self) -> Result<(PolicyFile, Arc<Configuration>), String> {
        let policy = PolicyFile::lock(&self.path, false)?;
        let (bytes, stamp) = policy.admitted_snapshot()?;
        let mut snapshot = self
            .snapshot
            .lock()
            .map_err(|_| "Policy cache unavailable")?;
        if snapshot.stamp != stamp || snapshot.bytes != bytes {
            let settings = parse_clients(&self.path, &bytes)?;
            if settings.runtime_settings != snapshot.settings.runtime_settings
                || snapshot.settings.managed && !settings.managed
            {
                return Err("Security-sensitive runtime settings changed; restart required".into());
            }
            if settings.managed && !snapshot.settings.managed {
                require_completed_legacy_jobs(&settings)?;
            }
            verify_approvals(&settings)?;
            *snapshot = CachedPolicy {
                bytes,
                stamp,
                settings: Arc::new(settings),
            };
        }
        Ok((policy, snapshot.settings.clone()))
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

/// Serializes local writers and snapshots used for request admission. The
/// marker survives a crash, so an incompletely audited grant stays unusable.
pub(crate) struct PolicyFile {
    path: PathBuf,
    directory: OwnedFd,
    _lock: OwnedFd,
    pending: OsString,
}

impl PolicyFile {
    pub(crate) fn lock(path: &Path, exclusive: bool) -> Result<Self, String> {
        Self::open(path, exclusive).map_err(|_| "Private authorization storage unavailable".into())
    }

    fn open(path: &Path, exclusive: bool) -> io::Result<Self> {
        if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
            return Err(invalid());
        }
        let parent = path.parent().ok_or_else(invalid)?;
        let directory = open_operator_dir(parent)?;
        let meta = fs::fstat(&directory)?;
        if meta.st_uid != rustix::process::geteuid().as_raw() || meta.st_mode & 0o7022 != 0 {
            return Err(invalid());
        }
        let name = path.file_name().ok_or_else(invalid)?;
        let lock_name = companion(name, ".policy-lock");
        let lock = match fs::openat(&directory, &lock_name, CREATE, PRIVATE) {
            Ok(lock) => {
                fs::fsync(&lock)?;
                fs::fsync(&directory)?;
                lock
            }
            Err(rustix::io::Errno::EXIST) => open_private(&directory, &lock_name)?,
            Err(error) => return Err(error.into()),
        };
        fs::flock(
            &lock,
            if exclusive {
                FlockOperation::LockExclusive
            } else {
                FlockOperation::LockShared
            },
        )?;
        let name_now = fs::statat(&directory, &lock_name, AtFlags::SYMLINK_NOFOLLOW)?;
        let lock_meta = fs::fstat(&lock)?;
        let current = fs::fstat(open_operator_dir(parent)?)?;
        if (name_now.st_dev, name_now.st_ino) != (lock_meta.st_dev, lock_meta.st_ino)
            || (current.st_dev, current.st_ino) != (meta.st_dev, meta.st_ino)
        {
            return Err(invalid());
        }

        Ok(Self {
            path: path.to_owned(),
            directory,
            _lock: lock,
            pending: companion(name, ".policy-pending"),
        })
    }

    pub(crate) fn snapshot(&self) -> Result<Configuration, String> {
        let (bytes, _) = self.admitted_snapshot()?;
        parse_clients(&self.path, &bytes)
    }

    fn admitted_snapshot(&self) -> Result<(Vec<u8>, ConfigStamp), String> {
        if self.pending_client()?.is_some() {
            return Err("Interrupted policy update requires local operator recovery".into());
        }
        read_config_version(&self.path)
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>, String> {
        read_config(&self.path)
    }

    pub(crate) fn pending_client(&self) -> Result<Option<String>, String> {
        match open_private(&self.directory, &self.pending) {
            Ok(file) => {
                let mut value = String::new();
                File::from(file)
                    .take(129)
                    .read_to_string(&mut value)
                    .map_err(|_| "Invalid authorization transaction marker")?;
                if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                    return Err("Invalid authorization transaction marker".into());
                }
                Ok(Some(value))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("Invalid authorization transaction marker".into()),
        }
    }

    pub(crate) fn begin(&self, client: &str) -> io::Result<()> {
        self.write_named(&self.pending, client.as_bytes())
    }

    pub(crate) fn replace(&self, bytes: &[u8]) -> io::Result<()> {
        self.write_named(self.path.file_name().ok_or_else(invalid)?, bytes)
    }

    fn write_named(&self, name: &OsStr, bytes: &[u8]) -> io::Result<()> {
        let temporary = format!(".mcp-policy-{}", revision()?);
        let mut file = File::from(fs::openat(&self.directory, &temporary, CREATE, PRIVATE)?);
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::renameat(&self.directory, &temporary, &self.directory, name)?;
            Ok(fs::fsync(&self.directory)?)
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.directory, &temporary, AtFlags::empty());
        }
        result
    }

    /// Publish an audited configuration edit with admission closed until both writes succeed.
    pub(crate) fn commit_edit(
        &self,
        document: &Value,
        marker: &str,
        record: impl Fn(AuditPhase) -> io::Result<()>,
    ) -> Result<(), String> {
        let pending = self.pending_client()?;
        if pending.as_deref().is_some_and(|prior| prior != marker) {
            return Err("Repeat the original local command to recover interrupted policy".into());
        }
        let mut candidate =
            serde_json::to_vec_pretty(document).map_err(|_| "Cannot encode policy")?;
        candidate.push(b'\n');
        if candidate.len() > 65_536 {
            return Err("Credential configuration exceeds size limit".into());
        }
        parse_clients(&self.path, &candidate)?;
        record(AuditPhase::Intent).map_err(|_| "Cannot persist authorization intent")?;
        if pending.is_none() {
            self.begin(marker)
                .map_err(|_| "Cannot persist policy transaction marker")?;
        }
        if self.replace(&candidate).is_err() {
            let _ = record(AuditPhase::Uncertain);
            return Err("Policy update requires local command recovery".into());
        }
        record(AuditPhase::Success).map_err(|_| "Policy update requires local command recovery")?;
        self.finish()
            .map_err(|_| "Policy update requires local command recovery")?;
        Ok(())
    }

    pub(super) fn write_pairing(&self, bytes: &[u8]) -> io::Result<()> {
        self.write_named(&self.pairing_name(), bytes)
    }

    pub(super) fn read_pairing(&self) -> io::Result<String> {
        let mut value = String::new();
        File::from(open_private(&self.directory, &self.pairing_name())?)
            .take(128)
            .read_to_string(&mut value)?;
        Ok(value)
    }

    pub(super) fn consume_pairing(&self) -> io::Result<()> {
        fs::unlinkat(&self.directory, self.pairing_name(), AtFlags::empty())?;
        fs::fsync(&self.directory)?;
        Ok(())
    }

    fn pairing_name(&self) -> OsString {
        companion(self.path.file_name().unwrap_or_default(), ".dashboard-pair")
    }

    pub(crate) fn finish(&self) -> io::Result<()> {
        fs::unlinkat(&self.directory, &self.pending, AtFlags::empty())?;
        fs::fsync(&self.directory)?;
        Ok(())
    }
}

fn companion(name: &OsStr, suffix: &str) -> OsString {
    let mut path = OsString::from(".");
    path.push(name);
    path.push(suffix);
    path
}

fn open_private(directory: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
    let file = fs::openat(
        directory,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        FileMode::empty(),
    )?;
    let meta = fs::fstat(&file)?;
    if FileType::from_raw_mode(meta.st_mode) != FileType::RegularFile
        || meta.st_uid != rustix::process::geteuid().as_raw()
        || meta.st_mode & 0o7777 != 0o600
        || meta.st_nlink != 1
    {
        return Err(invalid());
    }
    reopen_regular(file, OFlags::RDONLY)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "invalid operator policy storage",
    )
}

pub(crate) fn policy_path(config: &Path, path: &Path) -> bool {
    config == path
        || config.parent() == path.parent()
            && path.file_name().is_some_and(|name| {
                let config_name = config.file_name().unwrap_or_default();
                name == companion(config_name, ".policy-lock")
                    || name == companion(config_name, ".dashboard-pair")
                    || name == companion(config_name, ".policy-pending")
                    || name.as_encoded_bytes().starts_with(b".mcp-policy-")
                    || name.as_encoded_bytes().starts_with(b".mcp-upstream-")
            })
}

// Reject duplicate fields before using JSON values for an atomic edit.
pub(super) fn parse_document(bytes: &[u8]) -> Result<Value, String> {
    let StrictJson(document) = serde_json::from_slice(bytes)
        .map_err(|_| "Invalid or ambiguous credential configuration")?;
    const TOP: &[&str] = &[
        "clients",
        "audit_log",
        "job_state_dir",
        "job_profiles",
        "max_audit_file_bytes",
        "max_audit_dir_bytes",
        "policy_version",
        "protected_paths",
        "skills_dir",
        "skills_disabled",
        "admin_listen",
        "mcp_servers",
    ];
    const CLIENT: &[&str] = &[
        "id",
        "root",
        "token_sha256",
        "expires_at_unix_seconds",
        "tools",
        "mode",
        "yolo_roots",
        "yolo_shared_roots",
        "yolo_revision",
        "skills",
        "allowed_servers",
        "allowed_server_tools",
    ];
    let allowed = |value: &Value, fields: &[&str]| {
        value
            .as_object()
            .is_some_and(|object| object.keys().all(|key| fields.contains(&key.as_str())))
    };
    if !allowed(&document, TOP)
        || !document["clients"]
            .as_array()
            .is_some_and(|clients| clients.iter().all(|client| allowed(client, CLIENT)))
    {
        return Err("Unknown field in credential configuration".into());
    }
    if document
        .get("policy_version")
        .is_some_and(|version| !matches!(version.as_u64(), Some(1 | 2)))
    {
        return Err("Unsupported authorization policy schema".into());
    }
    if document["policy_version"].as_u64() != Some(2)
        && document["clients"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|entry| matches!(entry["mode"].as_str(), Some("full" | "broad_yolo")))
    {
        return Err("FULL and broad YOLO require authorization policy version 2".into());
    }
    if document.get("policy_version").is_none()
        && document["clients"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|entry| {
                entry["mode"].as_str() == Some("yolo") || entry.get("yolo_shared_roots").is_some()
            })
    {
        return Err("Persistent YOLO requires a managed authorization policy".into());
    }
    Ok(document)
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct Unique;
        impl<'de> Visitor<'de> for Unique {
            type Value = StrictJson;

            fn expecting(&self, format: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                format.write_str("JSON with unique fields")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> Result<StrictJson, M::Error> {
                let mut object = Map::new();
                while let Some((key, StrictJson(value))) = input.next_entry()? {
                    if object.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate configuration field"));
                    }
                }
                Ok(StrictJson(Value::Object(object)))
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut input: S) -> Result<StrictJson, S::Error> {
                let mut values = Vec::new();
                while let Some(StrictJson(value)) = input.next_element()? {
                    values.push(value);
                }
                Ok(StrictJson(Value::Array(values)))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<StrictJson, E> {
                Ok(StrictJson(value.into()))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<StrictJson, E> {
                Ok(StrictJson(value.into()))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<StrictJson, E> {
                Ok(StrictJson(value.into()))
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<StrictJson, E> {
                Ok(StrictJson(value.into()))
            }

            fn visit_unit<E: de::Error>(self) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Null))
            }
        }
        input.deserialize_any(Unique)
    }
}
