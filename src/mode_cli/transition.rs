//! Atomic, audited mode selection and compatibility with the older schemas.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::security::audit::AuditSink;
use serde_json::Value;

use crate::http::admission::{Configuration, parse_clients, parse_document};
use crate::http::operator::{
    Mode, PolicyFile, require_completed_legacy_jobs, revision, verify_approvals,
    verify_approvals_except,
};

use super::Operation;

struct ModeChange {
    id: String,
    previous: &'static str,
    requested: &'static str,
    revision: String,
}

impl ModeChange {
    fn new(id: &str, previous: &'static str, requested: &'static str) -> Result<Self, String> {
        Ok(Self {
            id: id.to_owned(),
            previous,
            requested,
            revision: revision().map_err(|_| "Cannot allocate an authorization revision")?,
        })
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn audit(settings: &Configuration) -> Result<AuditSink, String> {
    AuditSink::open_with_limits(
        settings
            .audit_log
            .as_ref()
            .ok_or("Mode changes require a private audit ledger")?,
        settings.audit_limits,
    )
    .map_err(|_| "Mode changes require a healthy private audit ledger".into())
}

fn require_operator() -> Result<(), String> {
    if rustix::process::geteuid().is_root() {
        return Err("Mode administration requires the unprivileged gateway owner".into());
    }
    Ok(())
}

fn migrate_document(document: &mut Value, settings: &Configuration) -> Result<Vec<ModeChange>, String> {
    let version = document["policy_version"].as_u64();
    let mut changes = Vec::new();
    for (entry, client) in document["clients"]
        .as_array_mut()
        .ok_or("Invalid clients")?
        .iter_mut()
        .zip(&settings.clients)
    {
        let old = Mode::from_entry(entry, version)?;
        let preserve_native = old == Mode::Full && !client.is_disabled();
        let requested = if preserve_native { "native_yolo" } else { "standard" };
        let object = entry.as_object_mut().ok_or("Invalid client")?;
        object.remove("yolo_revision");
        object.remove("native_tool_preset");
        object.remove("yolo_roots");
        object.remove("yolo_shared_roots");
        if let Some(previous) = client.approval_mode {
            let change = ModeChange::new(&client.id, previous, requested)?;
            if preserve_native {
                object.insert("yolo_revision".into(), change.revision.as_str().into());
            }
            changes.push(change);
        }
        entry["mode"] = if preserve_native { "yolo" } else { "standard" }.into();
        entry["disabled"] = client.is_disabled().into();
    }
    document["policy_version"] = 4.into();
    Ok(changes)
}

fn commit(
    policy: &PolicyFile,
    document: &Value,
    settings: &Configuration,
    marker: &str,
    migrated: bool,
    state_event: Option<(&str, &'static str, &'static str)>,
    changes: &[ModeChange],
) -> Result<(), String> {
    let audit = audit(settings)?;
    policy.commit_edit(document, marker, |phase| {
        let now = now();
        if migrated {
            audit.record_runtime_mode(
                "local_operator",
                mcp_gateway::security::audit::POLICY_SCHEMA_FOUR,
                "standard",
                phase,
                now,
            )?;
        }
        if let Some((id, operation, mode)) = state_event {
            audit.record_runtime_mode(id, operation, mode, phase, now)?;
        }
        for change in changes {
            audit.record_mode(
                &change.id,
                change.previous,
                change.requested,
                &change.revision,
                phase,
                now,
            )?;
        }
        Ok(())
    })?;
    verify_approvals(&policy.snapshot()?)
}

const MIGRATION: &str = "@mode-migration";
const BULK: &str = "@mode-all";

pub(super) fn migrate(path: &Path) -> Result<(), String> {
    require_operator()?;
    let policy = PolicyFile::lock(path, true)?;
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    if policy.pending_client()?.is_some() {
        return Err("Interrupted policy update. Use local Standard recovery before migration".into());
    }
    let settings = parse_clients(path, &bytes)?;
    verify_approvals(&settings)?;
    if document["policy_version"] != 4 {
        require_completed_legacy_jobs(&settings)?;
        let changes = migrate_document(&mut document, &settings)?;
        // Quarantine before recording the durable format boundary. Recovery
        // can demote safely even when only the intent reached the ledger.
        policy.begin(MIGRATION).map_err(|_| "Cannot begin policy migration")?;
        commit(&policy, &document, &settings, MIGRATION, true, None, &changes)?;
    }
    println!("policy_version=4");
    Ok(())
}

fn select(
    entry: &mut Value,
    client: &crate::http::admission::Client,
    mode: Mode,
) -> Result<ModeChange, String> {
    let change = ModeChange::new(
        &client.id,
        client.approval_mode.unwrap_or("standard"),
        if mode == Mode::NativeYolo { "native_yolo_preset" } else { mode.label() },
    )?;
    let object = entry.as_object_mut().ok_or("Invalid client")?;
    object.remove("native_tool_preset");
    object.remove("yolo_revision");
    if mode == Mode::NativeYolo {
        object.insert("yolo_revision".into(), change.revision.as_str().into());
        object.insert("native_tool_preset".into(), true.into());
        object.insert("mode".into(), "yolo".into());
    } else {
        object.insert("mode".into(), "standard".into());
    }
    Ok(change)
}

pub(super) fn apply(path: &Path, id: &str, operation: Operation) -> Result<(), String> {
    require_operator()?;
    let policy = PolicyFile::lock(path, true)?;
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    if document["policy_version"] != 4 {
        return Err("Run veyl mode migrate --config PATH first".into());
    }
    let settings = parse_clients(path, &bytes)?;
    let index = settings.clients.iter().position(|client| client.id == id).ok_or("Unknown client")?;
    let client = &settings.clients[index];
    let pending = policy.pending_client()?;
    let safely_reset = matches!(operation, Operation::Select(Mode::Standard) | Operation::SetDisabled(true));
    if pending.as_deref().is_some_and(|prior| prior != id || !safely_reset) {
        return Err("Interrupted policy update requires a local Standard reset".into());
    }
    if safely_reset {
        verify_approvals_except(&settings, Some(id))?;
    } else {
        verify_approvals(&settings)?;
    }
    let entry = &mut document["clients"][index];
    let mut changes = Vec::new();
    let mut state_event = None;
    match operation {
        Operation::Select(mode) => {
            if client.is_disabled() && mode == Mode::NativeYolo {
                return Err("Enable the client before selecting YOLO".into());
            }
            changes.push(select(entry, client, mode)?);
        }
        Operation::SetDisabled(disabled) => {
            if disabled || client.is_disabled() {
                // Repair disabled native entries produced by earlier candidates too.
                changes.push(select(entry, client, Mode::Standard)?);
            }
            entry["disabled"] = disabled.into();
            let event = if disabled { "schema4_client_disable" } else { "schema4_client_enable" };
            state_event = Some((id, event, entry["mode"].as_str().map_or("standard", |mode| {
                if mode == "yolo" { "native_yolo" } else { "standard" }
            })));
        }
        _ => return Err("Invalid local mode operation".into()),
    }
    if pending.is_some() {
        // A possibly interrupted enable must never reopen admission.
        entry["disabled"] = true.into();
        state_event = Some((id, "schema4_client_disable", "standard"));
    }
    commit(&policy, &document, &settings, id, false, state_event, &changes)
}

/// Persistently update `default_mode` and apply `mode` to every enabled static
/// client in `path`. Disabled clients never regain access or become YOLO. Zero
/// static clients succeeds cleanly while recording the audited default transition.
pub(crate) fn set_default_and_apply_all(path: &Path, mode: Mode) -> Result<(), String> {
    require_operator()?;
    let policy = PolicyFile::lock(path, true)?;
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    let settings = parse_clients(path, &bytes)?;
    let pending = policy.pending_client()?;
    let recovery = mode == Mode::Standard && matches!(pending.as_deref(), Some(BULK | MIGRATION));
    if pending.is_some() && !recovery {
        return Err("Interrupted policy update requires a local Standard reset".into());
    }
    let migrated = document["policy_version"] != 4;
    if migrated && !recovery {
        return Err("Run veyl mode migrate --config PATH first".into());
    }
    if !recovery {
        verify_approvals(&settings)?;
    }
    let mut changes = if migrated {
        migrate_document(&mut document, &settings)?
    } else {
        Vec::new()
    };
    let mode_str = if mode == Mode::NativeYolo {
        "yolo"
    } else {
        "standard"
    };
    document["default_mode"] = mode_str.into();
    for (entry, client) in document["clients"]
        .as_array_mut()
        .ok_or("Invalid clients")?
        .iter_mut()
        .zip(&settings.clients)
    {
        if mode == Mode::Standard || !client.is_disabled() {
            changes.push(select(entry, client, mode)?);
        }
    }
    commit(
        &policy,
        &document,
        &settings,
        pending.as_deref().unwrap_or(BULK),
        migrated,
        Some(("local_operator", "default_mode", mode_str)),
        &changes,
    )
}

/// Set the local preference for future OAuth approvals without changing grants.
pub(crate) fn set_default(path: &Path, mode: Mode) -> Result<(), String> {
    require_operator()?;
    let policy = PolicyFile::lock(path, true)?;
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    if document["policy_version"] != 4 || policy.pending_client()?.is_some() {
        return Err("Finish local policy migration or recovery first".into());
    }
    let settings = parse_clients(path, &bytes)?;
    verify_approvals(&settings)?;
    let mode = if mode == Mode::NativeYolo { "yolo" } else { "standard" };
    document["default_mode"] = mode.into();
    commit(&policy, &document, &settings, BULK, false,
        Some(("local_operator", "default_mode", mode)), &[])
}

pub(crate) fn set_static_mode(path: &Path, id: &str, mode: Mode) -> Result<(), String> {
    apply(path, id, Operation::Select(mode))
}

/// Immediately disable a static client and demote any native YOLO grant while
/// preserving its audit history and verifier record.
pub(crate) fn revoke_static_client(path: &Path, id: &str) -> Result<(), String> {
    apply(path, id, Operation::SetDisabled(true))
}
