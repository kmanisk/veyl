//! Local administration of configured protection rules.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::security::audit::{AuditPhase, AuditSink};
use sha2::{Digest, Sha256};

use crate::http::admission::{parse_clients, parse_document};
use crate::http::operator::{PolicyFile, verify_approvals};
use crate::protected_paths::{
    Kind, OPTIONAL_DEFAULTS, READONLY_DEFAULTS, Rule, check_conflicts, validate_path,
};

const USAGE: &str =
    "usage: veyl protected-paths list [--mandatory|--optional|--readonly] --config PATH
       veyl protected-paths <add|remove|validate> [--optional|--readonly] PATH --config PATH";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let action = args.first().and_then(|arg| arg.to_str()).ok_or(USAGE)?;
    if !matches!(action, "list" | "add" | "remove" | "validate") {
        return Err(USAGE.into());
    }
    if args.len() == 2 && args[1] == "--help" {
        println!("{USAGE}");
        return Ok(());
    }
    if rustix::process::geteuid().is_root() {
        return Err("Protected-path administration requires the unprivileged gateway owner".into());
    }
    let mut args = args[1..].iter();
    let (mut config, mut filter, mut target) = (None, None, None);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config") if config.is_none() => {
                config = Some(PathBuf::from(args.next().ok_or(USAGE)?));
            }
            Some(option @ ("--mandatory" | "--optional" | "--readonly")) if filter.is_none() => {
                filter = Some(option);
            }
            Some(path) if !path.starts_with('-') && target.is_none() => {
                target = Some(Path::new(path));
            }
            _ => return Err(USAGE.into()),
        }
    }
    let config = config.ok_or(USAGE)?;
    let mutates = matches!(action, "add" | "remove");
    let policy = PolicyFile::lock(&config, mutates)?;
    let pending = policy.pending_client()?;
    let bytes = policy.bytes()?;
    let settings = parse_clients(&config, &bytes)?;
    verify_approvals(&settings)?;
    if action == "list" {
        if target.is_some() || pending.is_some() {
            return Err("Listing requires no target or interrupted policy update".into());
        }
        list(&config, &settings, filter);
        return Ok(());
    }

    let path = target.ok_or(USAGE)?;
    validate_path(path)?;
    let kind = match filter {
        Some("--mandatory") => return Err("Mandatory gateway protection cannot be edited".into()),
        Some("--readonly") => Kind::ReadOnly,
        _ => Kind::Optional,
    };
    check_conflicts(&config, &settings, path, kind)?;
    let digest = format!("{:x}", Sha256::digest(path.as_os_str().as_encoded_bytes()));
    let transaction = format!("protected-paths:{action}:{}:{digest}", kind.label());
    if pending
        .as_deref()
        .is_some_and(|marker| !mutates || marker != transaction)
    {
        return Err(
            "Interrupted policy update requires repeating the original local command".into(),
        );
    }

    if action == "validate" {
        let rule = Rule::inspect(path, kind)?;
        settings.protected_paths.check_candidate(kind, &rule)?;
        println!("valid {} {}", kind.label(), path.display());
        return Ok(());
    }

    let mut rules = settings.protected_paths;
    let changed = if action == "add" {
        rules.insert(kind, Rule::inspect(path, kind)?)?
    } else {
        rules.remove(kind, path)
    };
    if !changed && pending.is_none() {
        return Err(if action == "add" {
            "Protected path is already configured".into()
        } else {
            "No custom rule matches this path".into()
        });
    }
    let mut document = parse_document(&bytes)?;
    if rules.is_empty() {
        document
            .as_object_mut()
            .ok_or("Invalid policy")?
            .remove("protected_paths");
    } else {
        document["protected_paths"] =
            serde_json::to_value(rules).map_err(|_| "Cannot encode protected paths")?;
    }
    let mut candidate = serde_json::to_vec_pretty(&document).map_err(|_| "Cannot encode policy")?;
    candidate.push(b'\n');
    if candidate.len() > 65_536 {
        return Err("Credential configuration exceeds size limit".into());
    }
    parse_clients(&config, &candidate)?;

    let ledger = settings
        .audit_log
        .as_ref()
        .ok_or("Protected-path updates require an audit ledger")?;
    let audit = AuditSink::open_with_limits(ledger, settings.audit_limits)
        .map_err(|_| "Protected-path updates require a healthy audit ledger")?;
    let record = |phase| {
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        audit.record_protected_paths(action, kind.label(), &digest, phase, at)
    };
    record(AuditPhase::Intent).map_err(|_| "Cannot persist protected-path intent")?;
    if pending.is_none() {
        policy
            .begin(&transaction)
            .map_err(|_| "Cannot persist policy transaction marker")?;
    }
    if policy.replace(&candidate).is_err() {
        let _ = record(AuditPhase::Uncertain);
        return Err("Protected-path update requires local command recovery".into());
    }
    record(AuditPhase::Success)
        .map_err(|_| "Protected-path update requires local command recovery")?;
    policy
        .finish()
        .map_err(|_| "Protected-path update requires local command recovery")?;
    println!(
        "{action} {} {} enforcement=broad-yolo-unavailable",
        kind.label(),
        path.display()
    );
    Ok(())
}

fn list(config: &Path, settings: &crate::http::admission::Configuration, filter: Option<&str>) {
    if filter.is_none() || filter == Some("--mandatory") {
        println!("mandatory configuration={}", config.display());
        if let Some(ledger) = &settings.audit_log {
            println!("mandatory audit_log={}", ledger.display());
            if let Some(directory) = ledger.parent() {
                println!("mandatory audit_directory={}", directory.display());
            }
        }
        if let Some(state) = settings.job_state_path() {
            println!("mandatory job_state_dir={}", state.display());
        }
    }
    for (kind, defaults) in [
        (Kind::Optional, OPTIONAL_DEFAULTS),
        (Kind::ReadOnly, READONLY_DEFAULTS),
    ] {
        if filter.is_none()
            || filter.and_then(|value| value.strip_prefix("--")) == Some(kind.label())
        {
            for relative in defaults {
                println!("{} default ~/{}", kind.label(), relative);
            }
            for rule in settings.protected_paths.selected(kind) {
                let status = if rule.check_identity(kind).is_ok() {
                    "verified"
                } else {
                    "stale"
                };
                println!(
                    "{} custom {} identity={status}",
                    kind.label(),
                    rule.path.display()
                );
            }
        }
    }
    println!("enforcement=broad-yolo-unavailable");
}
