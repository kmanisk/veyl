//! Local operator entry point; no MCP or HTTP dispatch reaches this module.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::security::audit::{AuditPhase, AuditSink};
use mcp_gateway::security::policy::Action;
use serde_json::Value;

use crate::http::admission::{parse_clients, parse_document};
use crate::http::operator::{
    Mode, PolicyFile, require_completed_legacy_jobs, revision, verify_approvals,
};
use crate::http::scope::sibling_scopes;

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    const USAGE: &str = "usage: mcp-gateway yolo <enable|disable|reset|status|set --mode MODE [--confirm-full]> --client ID --config PATH";
    if args.iter().any(|arg| arg == "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    let command = args.first().and_then(|arg| arg.to_str()).ok_or(USAGE)?;
    if !matches!(
        command,
        "enable" | "disable" | "reset" | "standard" | "status" | "set"
    ) {
        return Err(USAGE.into());
    }
    if rustix::process::geteuid().is_root() {
        return Err("YOLO administration requires the unprivileged gateway owner".into());
    }
    let mut id = None;
    let mut path = None;
    let mut requested_mode = None;
    let mut confirm_full = false;
    let mut args = args[1..].iter();
    while let Some(option) = args.next() {
        match option.to_str() {
            Some("--client") if id.is_none() => id = args.next().and_then(|arg| arg.to_str()),
            Some("--confirm-full") if command == "set" && !confirm_full => confirm_full = true,
            Some("--mode") if command == "set" && requested_mode.is_none() => {
                requested_mode = Some(args.next().and_then(|arg| arg.to_str()).ok_or(USAGE)?);
            }
            Some("--config") if path.is_none() => path = args.next().map(PathBuf::from),
            _ => return Err(USAGE.into()),
        }
    }
    if confirm_full && requested_mode != Some("full") {
        return Err(USAGE.into());
    }
    let command = match (command, requested_mode) {
        ("set", Some("standard")) | ("standard", None) => "reset",
        ("set", Some("full")) if confirm_full => "full",
        ("set", Some("full")) => return Err("FULL requires --confirm-full".into()),
        ("set", Some("yolo")) => return Err("Broad YOLO isolation is unavailable".into()),
        ("set", _) => return Err(USAGE.into()),
        _ => command,
    };
    let id = id.ok_or(USAGE)?;
    let path = path.ok_or(USAGE)?;
    let policy = PolicyFile::lock(&path, command != "status")?;
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    let settings = parse_clients(&path, &bytes)?;
    let client = settings
        .clients
        .iter()
        .find(|client| client.id == id)
        .ok_or("Unknown client")?;
    let mut entries = document["clients"]
        .as_array_mut()
        .ok_or("invalid configuration")?
        .iter_mut();
    let entry = entries
        .find(|entry| entry["id"].as_str() == Some(id))
        .ok_or("Unknown client")?;
    let previous = Mode::from_entry(entry)?;
    let pending = policy.pending_client()?;
    if pending
        .as_deref()
        .is_some_and(|pending| !matches!(command, "disable" | "reset") || pending != id)
    {
        return Err(
            "Interrupted authorization update requires local YOLO disable of the affected client"
                .into(),
        );
    }
    if pending.is_none() && !matches!(command, "disable" | "reset") {
        verify_approvals(&settings)?;
    }
    let target = match command {
        "enable" | "full" if previous == Mode::Disabled => return Err("Client is disabled".into()),
        "enable" if previous == Mode::Full => {
            return Err("Select Standard before enabling scoped YOLO".into());
        }
        "enable" => Mode::ScopedYolo,
        "full" => Mode::Full,
        "reset" => Mode::Standard,
        "disable" if previous != Mode::Disabled => Mode::Standard,
        _ => previous,
    };
    if !settings.managed && target != previous && command != "status" {
        require_completed_legacy_jobs(&settings)?;
    }
    if command == "enable"
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

    if command != "status" && (target != previous || pending.is_some()) {
        let audit_path = settings
            .audit_log
            .as_ref()
            .ok_or("YOLO requires a private audit ledger")?;
        let audit = AuditSink::open_with_limits(audit_path, settings.audit_limits)
            .map_err(|_| "YOLO requires a healthy private audit ledger")?;
        let implicit = if target == Mode::ScopedYolo && entry.get("yolo_roots").is_none() {
            sibling_scopes(&path, &settings, client)?
        } else {
            Vec::new()
        };
        let revision = revision().map_err(|_| "Cannot allocate an authorization revision")?;
        let object = entry
            .as_object_mut()
            .ok_or("Invalid client configuration")?;
        object.insert("mode".into(), Value::from(target.label()));
        object.remove("yolo_shared_roots");
        object.remove("yolo_revision");
        if matches!(target, Mode::ScopedYolo | Mode::Full) {
            object.insert("yolo_revision".into(), Value::from(revision.as_str()));
        }
        if !implicit.is_empty() {
            object.insert("yolo_shared_roots".into(), serde_json::json!(implicit));
        }
        document["policy_version"] = if target == Mode::Full || document["policy_version"] == 2 {
            2
        } else {
            1
        }
        .into();
        let mut candidate =
            serde_json::to_vec_pretty(&document).map_err(|_| "Cannot encode policy")?;
        candidate.push(b'\n');
        if candidate.len() > 65_536 {
            return Err("Credential configuration exceeds size limit".into());
        }
        parse_clients(&path, &candidate)?;
        let record = |phase| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            audit.record_mode(id, previous.label(), target.label(), &revision, phase, now)
        };
        record(AuditPhase::Intent).map_err(|_| "Cannot persist authorization audit intent")?;
        if pending.is_none() {
            policy
                .begin(id)
                .map_err(|_| "Cannot persist authorization transaction marker")?;
        }
        if policy.replace(&candidate).is_err() {
            let _ = record(AuditPhase::Uncertain);
            return Err("Authorization update requires local recovery".into());
        }
        record(AuditPhase::Success).map_err(|_| "Authorization update requires local recovery")?;
        policy
            .finish()
            .map_err(|_| "Authorization update requires local recovery")?;
        verify_approvals(&policy.snapshot()?)?;
    }
    println!(
        "client={id} client_state={} yolo={} mode={} effective_policy={} tool_grants={}",
        if target == Mode::Disabled {
            "disabled"
        } else {
            "enabled"
        },
        if target == Mode::ScopedYolo {
            "enabled"
        } else {
            "disabled"
        },
        target.label(),
        if target == Mode::ScopedYolo {
            "legacy_scoped_yolo"
        } else {
            target.label()
        },
        client
            .actions
            .iter()
            .filter(|action| **action != Action::ListTools)
            .count()
    );
    Ok(())
}
