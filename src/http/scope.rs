//! Workspace scope resolution for persistent authorization.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::tools::MutationRoot;

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
    let version = document["policy_version"].as_u64();
    let mode = Mode::from_entry(entry, version)?;
    if matches!(mode, Mode::ScopedYolo | Mode::BroadYolo) {
        return Ok(Vec::new());
    }
    let explicit = root_paths(
        entry,
        if matches!(version, Some(3 | 4)) {
            "extra_roots"
        } else {
            "yolo_roots"
        },
    )?;
    let shared = root_paths(entry, "yolo_shared_roots")?;
    if !shared.is_empty() && mode != Mode::ScopedYolo {
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
