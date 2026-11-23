//! Operator-only administration of skill availability.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::security::audit::{AuditPhase, AuditSink};

use crate::http::admission::{parse_clients, parse_document};
use crate::http::operator::{PolicyFile, verify_approvals};
use crate::skills::valid_name;

const HELP: &str = "usage: mcp-gateway skills <enable|disable> NAME --config PATH";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let [operation, name, key, path] = args else {
        return Err(HELP.into());
    };
    let operation = operation
        .to_str()
        .filter(|action| matches!(*action, "enable" | "disable"))
        .ok_or(HELP)?;
    let name = name.to_str().filter(|name| valid_name(name)).ok_or(HELP)?;
    if key != "--config" || rustix::process::geteuid().is_root() {
        return Err(HELP.into());
    }
    let path = PathBuf::from(path);
    let policy = PolicyFile::lock(&path, true)?;
    let pending = policy.pending_client()?;
    let marker = format!("skills:{operation}:{name}");
    if pending.as_deref().is_some_and(|prior| prior != marker) {
        return Err(
            "Interrupted policy update requires repeating the original local command".into(),
        );
    }
    let bytes = policy.bytes()?;
    let settings = parse_clients(&path, &bytes)?;
    verify_approvals(&settings)?;
    let mut skills = settings.skills.ok_or("No configured skills directory")?;
    let changed = if operation == "enable" {
        skills.read(name)?;
        skills.disabled.remove(name)
    } else {
        if !skills.disabled.contains(name)
            && !settings
                .clients
                .iter()
                .any(|client| client.skills.contains(name))
        {
            skills.read(name)?;
        }
        skills.disabled.insert(name.into())
    };
    if changed || pending.is_some() {
        let mut document = parse_document(&bytes)?;
        document["skills_disabled"] = serde_json::json!(skills.disabled);
        let mut candidate =
            serde_json::to_vec_pretty(&document).map_err(|_| "Cannot encode policy")?;
        candidate.push(b'\n');
        if candidate.len() > 65_536 {
            return Err("Credential configuration exceeds size limit".into());
        }
        parse_clients(&path, &candidate)?;
        let ledger = settings
            .audit_log
            .as_deref()
            .ok_or("Skill changes require audit logging")?;
        let audit = AuditSink::open_with_limits(ledger, settings.audit_limits)
            .map_err(|_| "Skill changes require a healthy audit ledger")?;
        let record = |phase| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            audit.record_skill_change(operation, name, phase, now)
        };
        record(AuditPhase::Intent).map_err(|_| "Cannot persist skill authorization intent")?;
        if pending.is_none() {
            policy
                .begin(&marker)
                .map_err(|_| "Cannot persist policy transaction marker")?;
        }
        if policy.replace(&candidate).is_err() {
            let _ = record(AuditPhase::Uncertain);
            return Err("Skill update requires local command recovery".into());
        }
        record(AuditPhase::Success).map_err(|_| "Skill update requires local command recovery")?;
        policy
            .finish()
            .map_err(|_| "Skill update requires local command recovery")?;
    }
    let state = if operation == "enable" {
        "enabled"
    } else {
        "disabled"
    };
    println!("skill={name} state={state}");
    Ok(())
}
