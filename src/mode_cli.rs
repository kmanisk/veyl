//! Three-mode operator interface and explicit, audited policy migration.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::security::audit::AuditSink;
use serde_json::Value;

use crate::http::admission::{parse_clients, parse_document};
use crate::http::operator::{Mode, PolicyFile, revision, verify_approvals};
use crate::http::scope::root_paths;

const USAGE: &str = "usage: veyl mode get --client ID --config PATH | veyl mode set --client ID --mode standard|yolo|full [--confirm-full] --config PATH | veyl mode migrate --config PATH | veyl mode enable|disable --client ID --config PATH";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "migrate") {
        let [_, option, path] = args else {
            return Err(USAGE.into());
        };
        if option != "--config" {
            return Err(USAGE.into());
        }
        return migrate(Path::new(path));
    }
    if args
        .first()
        .is_some_and(|arg| arg == "enable" || arg == "disable")
    {
        let disabled = args[0] == "disable";
        let mut query = args.to_vec();
        query[0] = "get".into();
        let translated = translate(&query)?;
        let id = translated[2].to_str().ok_or(USAGE)?;
        return set_disabled(Path::new(&translated[4]), id, disabled);
    }
    crate::yolo_cli::run(&translate(args)?)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn migrate(path: &Path) -> Result<(), String> {
    if rustix::process::geteuid().is_root() {
        return Err("Policy migration requires the unprivileged gateway owner".into());
    }
    let policy = PolicyFile::lock(path, true)?;
    if policy.pending_client()?.is_some() {
        return Err("Interrupted policy update requires local review before migration".into());
    }
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    let settings = parse_clients(path, &bytes)?;
    verify_approvals(&settings)?;
    if document["policy_version"] == 3 {
        println!("policy_version=3");
        return Ok(());
    }
    if !settings.managed {
        crate::http::operator::require_completed_legacy_jobs(&settings)?;
    }
    let audit = AuditSink::open_with_limits(
        settings
            .audit_log
            .as_ref()
            .ok_or("Migration requires a private audit ledger")?,
        settings.audit_limits,
    )
    .map_err(|_| "Migration requires a healthy audit ledger")?;
    // Only previously active scoped roots carry over. Dormant legacy roots
    // cannot become new Standard grants simply because the schema changes.
    let mut transitions = Vec::new();
    for entry in document["clients"]
        .as_array_mut()
        .ok_or("Invalid clients")?
    {
        let old = Mode::from_entry(entry)?;
        let roots: Vec<PathBuf> = if old == Mode::ScopedYolo {
            root_paths(entry, "yolo_roots")?
                .into_iter()
                .chain(root_paths(entry, "yolo_shared_roots")?)
                .collect()
        } else {
            Vec::new()
        };
        let id = entry["id"]
            .as_str()
            .ok_or("Invalid client identity")?
            .to_owned();
        let next = match old {
            Mode::BroadYolo => "yolo",
            Mode::Full => "full",
            _ => "standard",
        };
        let object = entry.as_object_mut().ok_or("Invalid client")?;
        object.insert("mode".into(), next.into());
        object.insert("disabled".into(), Value::Bool(old == Mode::Disabled));
        object.remove("yolo_roots");
        object.remove("yolo_shared_roots");
        object.insert("extra_roots".into(), serde_json::json!(roots));
        if old == Mode::ScopedYolo {
            object.remove("yolo_revision");
            transitions.push((
                id,
                revision().map_err(|_| "Cannot allocate migration revision")?,
            ));
        }
    }
    document["policy_version"] = 3.into();
    policy.commit_edit(&document, "mode-migration", |phase| {
        audit.record_runtime_mode("local_operator", "mode_migration", "standard", phase, now())?;
        for (id, rev) in &transitions {
            audit.record_mode(id, "yolo", "standard", rev, phase, now())?;
        }
        Ok(())
    })?;
    verify_approvals(&policy.snapshot()?)?;
    println!("policy_version=3");
    Ok(())
}

fn set_disabled(path: &Path, id: &str, disabled: bool) -> Result<(), String> {
    if rustix::process::geteuid().is_root() {
        return Err("Client administration requires the unprivileged gateway owner".into());
    }
    // Check identity before migration so a typo cannot rewrite the policy.
    {
        let policy = PolicyFile::lock(path, false)?;
        let settings = policy.snapshot()?;
        if !settings.clients.iter().any(|client| client.id == id) {
            return Err("Unknown client".into());
        }
    }
    migrate(path)?;
    let policy = PolicyFile::lock(path, true)?;
    let bytes = policy.bytes()?;
    let mut document = parse_document(&bytes)?;
    if document["policy_version"] != 3 {
        return Err("Policy version changed; retry after review".into());
    }
    let settings = parse_clients(path, &bytes)?;
    verify_approvals(&settings)?;
    let client = settings
        .clients
        .iter()
        .find(|client| client.id == id)
        .ok_or("Unknown client")?;
    let entry = document["clients"]
        .as_array_mut()
        .ok_or("Invalid clients")?
        .iter_mut()
        .find(|entry| entry["id"].as_str() == Some(id))
        .ok_or("Unknown client")?;
    let mode = entry["mode"].as_str().ok_or("Invalid mode")?.to_owned();
    entry["disabled"] = disabled.into();
    if client.disabled != disabled || policy.pending_client()?.is_some() {
        let audit = AuditSink::open_with_limits(
            settings
                .audit_log
                .as_ref()
                .ok_or("Client administration requires an audit ledger")?,
            settings.audit_limits,
        )
        .map_err(|_| "Client administration requires a healthy audit ledger")?;
        let operation = if disabled {
            "client_disable"
        } else {
            "client_enable"
        };
        policy.commit_edit(&document, id, |phase| {
            audit.record_runtime_mode(
                id,
                operation,
                client.mode.audit_mode().unwrap_or("standard"),
                phase,
                now(),
            )
        })?;
    }
    println!(
        "client={id} client_state={} mode={mode}",
        if disabled { "disabled" } else { "enabled" }
    );
    Ok(())
}

fn translate(args: &[OsString]) -> Result<Vec<OsString>, String> {
    let operation = args.first().and_then(|arg| arg.to_str()).ok_or(USAGE)?;
    if !matches!(operation, "get" | "status" | "set") {
        return Err(USAGE.into());
    }
    let mut id = None;
    let mut mode = None;
    let mut config = None;
    let mut confirm = false;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.to_str() {
            Some("--client") if id.is_none() => id = Some(rest.next().ok_or(USAGE)?.clone()),
            Some("--mode") if operation == "set" && mode.is_none() => {
                mode = Some(rest.next().ok_or(USAGE)?.clone());
            }
            Some("--config") if config.is_none() => {
                config = Some(rest.next().ok_or(USAGE)?.clone());
            }
            Some("--confirm-full") if operation == "set" && !confirm => confirm = true,
            Some(value) if !value.starts_with('-') && id.is_none() => id = Some(arg.clone()),
            Some(value) if !value.starts_with('-') && operation == "set" && mode.is_none() => {
                mode = Some(arg.clone());
            }
            _ => return Err(USAGE.into()),
        }
    }
    let id = id.ok_or(USAGE)?;
    let config = config.ok_or(USAGE)?;
    let mut translated = vec![
        OsString::from(if operation == "set" { "set" } else { "status" }),
        OsString::from("--client"),
        id,
        OsString::from("--config"),
        config,
    ];
    if operation == "set" {
        let mode = mode.ok_or(USAGE)?;
        match mode.to_str() {
            Some("full") if !confirm => return Err("FULL requires --confirm-full".into()),
            Some("standard" | "yolo") if confirm => return Err(USAGE.into()),
            Some("standard" | "yolo" | "full") => {}
            _ => return Err(USAGE.into()),
        }
        translated.extend([OsString::from("--mode"), mode]);
        if confirm {
            translated.push(OsString::from("--confirm-full"));
        }
    }
    Ok(translated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn maps_explicit_mode_to_existing_audited_transaction() {
        assert_eq!(
            translate(&args(&[
                "set",
                "--client",
                "dev",
                "--mode",
                "yolo",
                "--config",
                "/tmp/config"
            ]))
            .unwrap(),
            args(&[
                "set",
                "--client",
                "dev",
                "--config",
                "/tmp/config",
                "--mode",
                "yolo"
            ])
        );
        assert_eq!(
            translate(&args(&["get", "dev", "--config", "/tmp/config"])).unwrap(),
            args(&["status", "--client", "dev", "--config", "/tmp/config"])
        );
    }

    #[test]
    fn full_requires_explicit_confirmation_and_rejects_ambiguity() {
        assert!(translate(&args(&["set", "dev", "full", "--config", "/tmp/config"])).is_err());
        assert!(
            translate(&args(&[
                "set",
                "dev",
                "standard",
                "--confirm-full",
                "--config",
                "/tmp/config"
            ]))
            .is_err()
        );
        assert!(
            translate(&args(&[
                "set",
                "dev",
                "full",
                "--confirm-full",
                "--config",
                "/tmp/config"
            ]))
            .is_ok()
        );
        assert!(
            translate(&args(&[
                "set",
                "dev",
                "yolo",
                "--mode",
                "full",
                "--config",
                "/tmp/config"
            ]))
            .is_err()
        );
    }
}
