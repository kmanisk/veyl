//! Shared operator actions for the CLI and authenticated dashboard.

use std::ffi::OsString;
use std::path::Path;

use mcp_gateway::security::audit::{AuditPhase, AuditSink};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::http::admission::{parse_clients, parse_document};
use crate::http::operator::{PolicyFile, verify_approvals};
use crate::skills::{Skill, valid_name};
use crate::tools::MutationRoot;

const HELP: &str = "usage: veyl skills list | read NAME | import /absolute/SKILL_FOLDER | enable NAME | disable NAME | grant CLIENT NAME | revoke CLIENT NAME (append --config PATH)";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let [params @ .., key, path] = args else {
        return Err(HELP.into());
    };
    if key != "--config" {
        return Err(HELP.into());
    }
    let params = params
        .iter()
        .map(|arg| arg.to_str().ok_or(HELP))
        .collect::<Result<Vec<_>, _>>()?;
    let result = manage(Path::new(path), &params)?;
    if let Some(document) = result["document"].as_str() {
        print!("{document}");
    } else {
        println!("{result}");
    }
    Ok(())
}

pub(crate) fn manage(path: &Path, params: &[&str]) -> Result<Value, String> {
    if rustix::process::geteuid().is_root() {
        return Err("Use the local unprivileged operator identity".into());
    }
    let exclusive = !matches!(params, ["list"] | ["read", _]);
    let policy = PolicyFile::lock(path, exclusive)?;
    let bytes = policy.bytes()?;
    let settings = parse_clients(path, &bytes)?;
    verify_approvals(&settings)?;
    let skills = settings
        .skills
        .as_ref()
        .ok_or("No configured skills directory")?;
    let pending = policy.pending_client()?;
    let marker = format!("skills:{:x}", Sha256::digest(json!(params).to_string()));
    if pending.as_deref().is_some_and(|prior| prior != marker) {
        return Err("Repeat the original local command to recover interrupted policy".into());
    }
    match params {
        ["list"] => return Ok(json!({"skills": skills.catalog()?})),
        ["read", name] => return Ok(json!({"name":name,"document":skills.read(name)?.document})),
        _ => {}
    }
    let ledger = settings
        .audit_log
        .as_deref()
        .ok_or("Skill changes require audit logging")?;
    let audit = AuditSink::open_with_limits(ledger, settings.audit_limits)
        .map_err(|_| "Skill changes require a healthy audit ledger")?;
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    };

    if let ["import", source] = params {
        let directory = Path::new(source);
        let name = directory
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_name(name))
            .ok_or("Expected a directory named for the skill")?;
        let document = MutationRoot::open_owned(directory)
            .and_then(|source| {
                source
                    .read("SKILL.md")
                    .map_err(|_| std::io::Error::other("Skill document unavailable"))
            })
            .map_err(|_| "Cannot safely read the skill source")?;
        let skill = Skill::parse(name, document)?;
        let exists = skills
            .present(name)
            .map_err(|_| "Cannot inspect destination skill")?;
        if exists && pending.is_none() {
            return Err("Skill already exists".into());
        }
        let record = |phase| audit.record_skill_change("import", name, phase, now());
        record(AuditPhase::Intent).map_err(|_| "Cannot persist skill import intent")?;
        if pending.is_none() {
            policy
                .begin(&marker)
                .map_err(|_| "Cannot persist skill transaction marker")?;
        }
        let result = if exists {
            if skills.read(name)?.document != skill.document {
                return Err("Interrupted import requires its original document".into());
            }
            skills.sync()
        } else {
            skills.import(name, &skill.document)
        };
        if result.is_err() {
            if matches!(skills.present(name), Ok(false)) {
                record(AuditPhase::Failure).map_err(|_| "Skill import requires local recovery")?;
                policy
                    .finish()
                    .map_err(|_| "Skill import requires local recovery")?;
                return Err("Cannot publish skill".into());
            }
            let _ = record(AuditPhase::Uncertain);
            return Err("Skill import requires local recovery".into());
        }
        record(AuditPhase::Success).map_err(|_| "Skill import requires local recovery")?;
        policy
            .finish()
            .map_err(|_| "Skill import requires local recovery")?;
        return Ok(json!({"name":name,"imported":true}));
    }

    let mut document = parse_document(&bytes)?;
    let (op, name, target) = match params {
        [op @ ("enable" | "disable"), name] => {
            let mut disabled = skills.disabled.clone();
            if *op == "enable" {
                skills.read(name)?;
                disabled.remove(*name);
            } else {
                if !disabled.contains(*name)
                    && !settings
                        .clients
                        .iter()
                        .any(|client| client.skills.contains(*name))
                {
                    skills.read(name)?;
                }
                disabled.insert((*name).into());
            }
            document["skills_disabled"] = json!(disabled);
            (*op, *name, None)
        }
        [op @ ("grant" | "revoke"), id, name] => {
            let client = settings
                .clients
                .iter()
                .find(|client| client.id == *id)
                .ok_or("Unknown client")?;
            let mut names = client.skills.clone();
            if *op == "grant" {
                skills.read(name)?;
                names.insert((*name).into());
            } else {
                names.remove(*name);
            }
            let entry = document["clients"]
                .as_array_mut()
                .and_then(|entries| entries.iter_mut().find(|entry| entry["id"] == *id))
                .ok_or("Unknown client")?;
            entry["skills"] = json!(names);
            (*op, *name, Some(*id))
        }
        _ => return Err(HELP.into()),
    };
    if !valid_name(name) {
        return Err("Invalid skill name".into());
    }
    policy.commit_edit(&document, &marker, |phase| {
        audit.record_skill_change_for(op, name, target, phase, now())
    })?;
    let state = match op {
        "enable" => "enabled",
        "disable" => "disabled",
        "grant" => "granted",
        _ => "revoked",
    };
    Ok(json!({"name":name,"state":state,"client":target}))
}
