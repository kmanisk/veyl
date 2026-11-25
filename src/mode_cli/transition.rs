//! Atomic, audited mode selection and compatibility with the older schemas.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::security::audit::AuditSink;
use mcp_gateway::security::policy::Action;
use serde_json::Value;

use crate::http::admission::{Configuration, parse_clients, parse_document};
use crate::http::operator::{
    Mode, PolicyFile, require_completed_legacy_jobs, revision, verify_approvals,
    verify_approvals_except,
};
use crate::http::scope::{root_paths, sibling_scopes};

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

/// Convert older entries without granting new native tools or sandbox mounts.
/// Only active, explicitly approved roots survive. Inferred sibling scopes
/// never served as job mounts and are dropped to avoid widening job access.
fn migrate_document(document: &mut Value) -> Result<Vec<ModeChange>, String> {
    let mut changes = Vec::new();
    for entry in document["clients"]
        .as_array_mut()
        .ok_or("Invalid clients")?
    {
        let old = Mode::from_entry(entry)?;
        let roots = if old == Mode::ScopedYolo {
            root_paths(entry, "yolo_roots")?
        } else {
            Vec::new()
        };
        if old == Mode::ScopedYolo {
            changes.push(ModeChange::new(
                entry["id"].as_str().ok_or("Invalid client identity")?,
                old.label(),
                "standard",
            )?);
            entry
                .as_object_mut()
                .ok_or("Invalid client")?
                .remove("yolo_revision");
        }
        entry["mode"] = match old {
            Mode::BroadYolo => "yolo",
            Mode::Full => "full",
            _ => "standard",
        }
        .into();
        entry["disabled"] = (old == Mode::Disabled).into();
        entry["extra_roots"] = serde_json::json!(roots);
        let object = entry.as_object_mut().ok_or("Invalid client")?;
        object.remove("yolo_roots");
        object.remove("yolo_shared_roots");
    }
    document["policy_version"] = 3.into();
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
                "mode_migration",
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

pub(super) fn migrate(path: &Path) -> Result<(), String> {
    require_operator()?;
    let policy = PolicyFile::lock(path, true)?;
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    if policy.pending_client()?.is_some() {
        return Err("Interrupted policy update requires local review before migration".into());
    }
    let settings = parse_clients(path, &bytes)?;
    verify_approvals(&settings)?;
    if document["policy_version"] != 3 {
        if !settings.managed {
            require_completed_legacy_jobs(&settings)?;
        }
        let changes = migrate_document(&mut document)?;
        commit(
            &policy,
            &document,
            &settings,
            "mode-migration",
            true,
            None,
            &changes,
        )?;
    }
    println!("policy_version=3");
    Ok(())
}

pub(super) fn apply(
    path: &Path,
    id: &str,
    operation: Operation,
    legacy: bool,
) -> Result<(), String> {
    require_operator()?;
    let policy = PolicyFile::lock(path, true)?;
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    let settings = parse_clients(path, &bytes)?;
    let index = settings
        .clients
        .iter()
        .position(|client| client.id == id)
        .ok_or("Unknown client")?;
    let client = &settings.clients[index];
    let old_schema = document["policy_version"] != 3;
    if !old_schema && matches!(operation, Operation::Reset | Operation::LegacyDowngrade) {
        return Err("Use veyl mode standard or veyl mode disable for policy version 3".into());
    }
    let operation = match operation {
        Operation::Select(Mode::Standard) if old_schema && legacy => Operation::Reset,
        operation => operation,
    };
    let pending = policy.pending_client()?;
    let recover_disabled = pending.is_some() && operation == Operation::SetDisabled(true);
    let recovery = recover_disabled
        || matches!(
            operation,
            Operation::Reset | Operation::LegacyDowngrade | Operation::Select(Mode::Standard)
        );
    if pending
        .as_deref()
        .is_some_and(|prior| prior != id || !recovery)
    {
        return Err("Interrupted authorization update requires a local Standard reset of the affected client".into());
    }
    if client.is_disabled()
        && pending.is_none()
        && !matches!(
            operation,
            Operation::SetDisabled(_) | Operation::Reset | Operation::LegacyDowngrade
        )
    {
        return Err("Client is disabled; enable it explicitly first".into());
    }
    if recovery {
        // A reset may remove a failed or replayed approval for this client.
        // Unrelated approvals must still validate before changing the file.
        verify_approvals_except(&settings, Some(id))?;
    } else {
        verify_approvals(&settings)?;
    }

    let migrated = old_schema && !legacy;
    let mut changes = if migrated {
        if !settings.managed {
            require_completed_legacy_jobs(&settings)?;
        }
        migrate_document(&mut document)?
    } else {
        Vec::new()
    };
    let version3 = document["policy_version"] == 3;
    let entry = &mut document["clients"][index];
    let previous = Mode::from_entry(entry)?;
    let selected = match operation {
        Operation::SetDisabled(true) if recover_disabled => Mode::Standard,
        Operation::Select(mode) => mode,
        Operation::Reset => Mode::Standard,
        Operation::LegacyDowngrade if previous != Mode::Disabled => Mode::Standard,
        Operation::LegacyDowngrade | Operation::SetDisabled(_) => previous,
        Operation::EnableScoped if version3 => {
            return Err(
                "Legacy 'yolo enable' is deprecated under policy version 3; use 'veyl mode set CLIENT yolo' (or 'veyl mode yolo') to select YOLO, or 'veyl mode enable' to restore client access"
                    .into(),
            );
        }
        Operation::EnableScoped if matches!(previous, Mode::BroadYolo | Mode::Full) => {
            return Err("Select Standard before enabling an older scoped policy".into());
        }
        Operation::EnableScoped => Mode::ScopedYolo,
        _ => return Err("Invalid local mode operation".into()),
    };
    let disabled = match operation {
        Operation::SetDisabled(disabled) => disabled,
        Operation::Reset => false,
        _ => client.is_disabled(),
    };
    let preset = selected == Mode::BroadYolo
        && version3
        && (operation == Operation::Select(Mode::BroadYolo) || client.native_tool_preset);
    let state_changed = version3 && client.is_disabled() != disabled;
    let mode_changed =
        selected != previous || preset != client.native_tool_preset || pending.is_some();
    if operation == Operation::Select(Mode::BroadYolo)
        || selected == Mode::BroadYolo
            && operation == Operation::SetDisabled(false)
            && state_changed
    {
        crate::jobs::broad::Broad::prepare(path, &settings)
            .and_then(|plan| plan.probe(&client.root).map_err(|error| error.to_string()))
            .map_err(|reason| {
                let mode = if legacy { "Broad YOLO" } else { "YOLO" };
                format!("{mode} isolation is unavailable: {reason}")
            })?;
    }
    if selected == Mode::ScopedYolo
        && settings.jobs.is_some()
        && (!settings.managed
            || client
                .actions
                .iter()
                .any(|action| matches!(action, Action::RunShortJob | Action::StartJob)))
    {
        crate::jobs::probe_sandbox()
            .map_err(|_| "Required Linux execution isolation unavailable")?;
    }
    if !(migrated || state_changed || mode_changed) {
        return Ok(());
    }
    if !migrated && !settings.managed && mode_changed {
        require_completed_legacy_jobs(&settings)?;
    }

    if version3 {
        entry["disabled"] = disabled.into();
    }
    if mode_changed {
        let change = ModeChange::new(
            id,
            if client.native_tool_preset {
                "yolo_native"
            } else {
                previous.label()
            },
            if preset {
                "yolo_native"
            } else {
                selected.label()
            },
        )?;
        let implicit = if selected == Mode::ScopedYolo && entry.get("yolo_roots").is_none() {
            sibling_scopes(path, &settings, client)?
        } else {
            Vec::new()
        };
        entry["mode"] = if version3 && selected == Mode::BroadYolo {
            "yolo"
        } else {
            selected.label()
        }
        .into();
        let object = entry
            .as_object_mut()
            .ok_or("Invalid client configuration")?;
        object.remove("yolo_revision");
        object.remove("yolo_shared_roots");
        object.remove("native_tool_preset");
        if matches!(selected, Mode::ScopedYolo | Mode::BroadYolo | Mode::Full) {
            object.insert("yolo_revision".into(), change.revision.as_str().into());
        }
        if preset {
            object.insert("native_tool_preset".into(), true.into());
        }
        if !implicit.is_empty() {
            object.insert("yolo_shared_roots".into(), serde_json::json!(implicit));
        }
        changes.push(change);
    }
    if !version3 {
        document["policy_version"] = if matches!(selected, Mode::BroadYolo | Mode::Full)
            || document["policy_version"] == 2
        {
            2
        } else {
            1
        }
        .into();
    }
    let state_event = state_changed.then_some((
        id,
        if disabled {
            "client_disable"
        } else {
            "client_enable"
        },
        selected.label(),
    ));
    commit(
        &policy,
        &document,
        &settings,
        id,
        migrated,
        state_event,
        &changes,
    )
}

/// Explicit local bulk selection. Preserve per-client grants, denials, roots,
/// authentication and enabled state. Commit the whole configuration once.
pub(super) fn apply_all(path: &Path, selected: Mode) -> Result<(), String> {
    const MARKER: &str = "@mode-all";
    require_operator()?;
    if !matches!(selected, Mode::Standard | Mode::BroadYolo | Mode::Full) {
        return Err("Unsupported bulk mode".into());
    }
    let policy = PolicyFile::lock(path, true)?;
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    let settings = parse_clients(path, &bytes)?;
    if document["policy_version"] != 3 {
        return Err("Run veyl mode migrate before selecting a mode for all clients".into());
    }
    let pending = policy.pending_client()?;
    let recovery = pending.as_deref() == Some(MARKER) && selected == Mode::Standard;
    if pending.is_some() && !recovery {
        return Err("Interrupted policy update; for an interrupted bulk selection, run veyl mode standard --all".into());
    }
    // Recovery removes every elevation, including those retained by disabled
    // clients, before admitting anything. Other operations verify approvals.
    if !recovery {
        verify_approvals(&settings)?;
    }
    if selected == Mode::BroadYolo {
        let plan = crate::jobs::broad::Broad::prepare(path, &settings)?;
        for client in settings.clients.iter().filter(|c| !c.is_disabled()) {
            plan.probe(&client.root).map_err(|_| "YOLO isolation is unavailable for an enabled client")?;
        }
    }
    let mut changes = Vec::new();
    for (entry, client) in document["clients"].as_array_mut().ok_or("Invalid clients")?
        .iter_mut().zip(&settings.clients)
    {
        if client.is_disabled() && !recovery {
            continue;
        }
        let previous = Mode::from_entry(entry)?;
        let preset = selected == Mode::BroadYolo;
        if !recovery && previous == selected && client.native_tool_preset == preset {
            continue;
        }
        let change = ModeChange::new(
            &client.id,
            if client.native_tool_preset { "yolo_native" } else { previous.label() },
            if preset { "yolo_native" } else { selected.label() },
        )?;
        entry["mode"] = if preset { "yolo" } else { selected.label() }.into();
        let object = entry.as_object_mut().ok_or("Invalid client")?;
        object.remove("yolo_revision");
        object.remove("yolo_shared_roots");
        object.remove("native_tool_preset");
        if matches!(selected, Mode::BroadYolo | Mode::Full) {
            object.insert("yolo_revision".into(), change.revision.as_str().into());
        }
        if preset {
            object.insert("native_tool_preset".into(), true.into());
        }
        changes.push(change);
    }
    if changes.is_empty() && !recovery {
        return Ok(());
    }
    if !settings.managed {
        require_completed_legacy_jobs(&settings)?;
    }
    commit(&policy, &document, &settings, MARKER, false, None, &changes)
}
