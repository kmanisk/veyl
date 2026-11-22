//! Workspace scope resolution for persistent authorization.

use std::path::{Path, PathBuf};

use mcp_gateway::security::{linux_fs::open_operator_dir, policy::Action};
use rustix::fs::{self, AtFlags, FileType};
use serde_json::Value;

use crate::tools::MutationRoot;

use super::admission::{Client, Configuration};
use super::operator::Mode;

const MAX_ROOTS: usize = 16;

pub(super) fn protected(
    config: &Path,
    audit: Option<&Path>,
    jobs: Option<&Path>,
    root: &Path,
) -> bool {
    let overlaps = |location: &Path| root.starts_with(location) || location.starts_with(root);
    config.starts_with(root)
        || audit.and_then(Path::parent).is_some_and(overlaps)
        || jobs.is_some_and(overlaps)
}

pub(super) fn open_extra_roots(
    document: &Value,
    entry: &Value,
    primary: &Path,
    config: &Path,
    audit: Option<&Path>,
    jobs: Option<&Path>,
) -> Result<Vec<MutationRoot>, String> {
    let explicit = root_paths(entry, "yolo_roots")?;
    let shared = root_paths(entry, "yolo_shared_roots")?;
    if !shared.is_empty() && Mode::from_entry(entry)? != Mode::ScopedYolo {
        return Err("Inactive client has retained implicit YOLO scopes".into());
    }
    let roots: Vec<_> = explicit.into_iter().chain(shared).collect();
    if roots.len() > MAX_ROOTS {
        return Err("Too many YOLO filesystem scopes".into());
    }
    let mut approved = Vec::<MutationRoot>::new();
    for root in roots {
        if protected(config, audit, jobs, &root)
            || root.starts_with(primary)
            || primary.starts_with(&root)
            || approved
                .iter()
                .any(|other| other.path().starts_with(&root) || root.starts_with(other.path()))
            || document["clients"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|other| {
                    other["root"]
                        .as_str()
                        .and_then(|path| Path::new(path).canonicalize().ok())
                        .is_some_and(|other| other.starts_with(&root) || root.starts_with(other))
                })
        {
            return Err("YOLO filesystem scope overlaps protected or client state".into());
        }
        if std::fs::canonicalize(&root).ok().as_ref() != Some(&root) {
            return Err("YOLO filesystem scope must be a canonical directory".into());
        }
        approved.push(MutationRoot::open(&root).map_err(|_| "YOLO filesystem scope unavailable")?);
    }
    Ok(approved)
}

pub(crate) fn root_paths(entry: &Value, key: &str) -> Result<Vec<PathBuf>, String> {
    entry.get(key).map_or_else(
        || Ok(Vec::new()),
        |value| {
            serde_json::from_value(value.clone())
                .map_err(|_| "Invalid YOLO filesystem scopes".into())
        },
    )
}

pub(crate) fn sibling_scopes(
    config: &Path,
    settings: &Configuration,
    client: &Client,
) -> Result<Vec<PathBuf>, String> {
    let parent = config.parent().ok_or("Invalid configuration directory")?;
    let directory = open_operator_dir(parent).map_err(|_| "Workspace collection unavailable")?;
    let meta = fs::fstat(&directory).map_err(|_| "Workspace collection unavailable")?;
    // Legacy file-only configurations can opt into the private collection
    // by explicitly enabling YOLO. No job gets an inferred bind mount.
    if client.root.parent() != Some(parent)
        || meta.st_mode & 0o7777 != 0o700
        || client
            .actions
            .iter()
            .any(|action| matches!(action, Action::StartJob | Action::RunShortJob))
    {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let entries = std::fs::read_dir(parent).map_err(|_| "Workspace collection unavailable")?;
    for entry in entries {
        let entry = entry.map_err(|_| "Workspace collection unavailable")?;
        let path = entry.path();
        if entry.file_name().as_encoded_bytes().starts_with(b".")
            || protected(
                config,
                settings.audit_log.as_deref(),
                settings.jobs.as_ref().map(|job| job.0.as_path()),
                &path,
            )
            || settings
                .clients
                .iter()
                .any(|other| other.root.starts_with(&path) || path.starts_with(&other.root))
        {
            continue;
        }
        let Ok(stat) = fs::statat(&directory, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && stat.st_uid == meta.st_uid
            && stat.st_dev == meta.st_dev
            && stat.st_mode & 0o7777 == 0o700
        {
            result.push(path);
        }
    }
    result.sort();
    if result.len() > MAX_ROOTS {
        return Err("Workspace collection is too broad; configure explicit yolo_roots".into());
    }
    Ok(result)
}
