//! Administration of the persistent upstream catalog and grants.

use std::ffi::OsString;
use std::path::Path;

use mcp_gateway::security::audit::{AuditPhase, AuditSink};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{server_name, tool_name};
use crate::http::admission::{parse_clients, parse_document};
use crate::http::operator::{PolicyFile, verify_approvals};

const HELP: &str = "usage: veyl mcp-servers list | probe ID | add-stdio ID /absolute/COMMAND [ARGS...] | add-bundle ID /absolute/COMMAND [ARGS...] | add-http ID URL [CONNECT_IP] | enable ID | disable ID | remove ID | restrict CLIENT | grant CLIENT ID TOOL | revoke CLIENT ID TOOL | workspace CLIENT ID ROOT | workspace-folder CLIENT ID ROOT | unworkspace CLIENT ID (append --config PATH)";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let [params @ .., flag, path] = args else {
        return Err(HELP.into());
    };
    if flag != "--config" {
        return Err(HELP.into());
    }
    let params = params
        .iter()
        .map(|arg| arg.to_str().ok_or(HELP))
        .collect::<Result<Vec<_>, _>>()?;
    println!("{}", manage(Path::new(path), &params)?);
    Ok(())
}

pub(crate) fn manage(path: &Path, params: &[&str]) -> Result<Value, String> {
    if rustix::process::geteuid().is_root() {
        return Err("Use the local unprivileged operator identity".into());
    }
    let exclusive = !matches!(params, ["list"] | ["probe", _]);
    let policy = PolicyFile::lock(path, exclusive)?;
    let bytes = policy.bytes()?;
    let settings = parse_clients(path, &bytes)?;
    verify_approvals(&settings)?;
    let marker = format!("upstream:{:x}", Sha256::digest(json!(params).to_string()));
    let pending = policy.pending_client()?;
    if pending.as_deref().is_some_and(|prior| prior != marker) {
        return Err("Repeat the original local command to recover interrupted policy".into());
    }
    if params == ["list"] {
        return Ok(json!({"servers":settings.upstreams.listing(None)}));
    }
    let ledger = settings
        .audit_log
        .as_deref()
        .ok_or("Upstream operations require audit logging")?;
    let audit = AuditSink::open_with_limits(ledger, settings.audit_limits)
        .map_err(|_| "Upstream operations require a healthy audit ledger")?;
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    };
    if let ["probe", id] = params {
        if !server_name(id) {
            return Err("Invalid upstream server identifier".into());
        }
        let record = |phase| audit.record_upstream_change("probe", id, None, None, phase, now());
        record(AuditPhase::Intent).map_err(|_| "Cannot audit upstream probe")?;
        let result = settings.upstreams.probe(path, id);
        let ready = result
            .as_ref()
            .is_ok_and(|value| value["health"] == "ready");
        record(if ready {
            AuditPhase::Success
        } else {
            AuditPhase::Failure
        })
        .map_err(|_| "Cannot audit upstream probe outcome")?;
        return result;
    }
    let mut document = parse_document(&bytes)?;
    if document.get("mcp_servers").is_none() {
        document["mcp_servers"] = json!({});
    }
    let servers = document["mcp_servers"].as_object_mut().ok_or(HELP)?;
    let (op, id, client, tool) = match params {
        ["restrict", principal] => {
            let entry = document["clients"]
                .as_array_mut()
                .and_then(|entries| entries.iter_mut().find(|entry| entry["id"] == *principal))
                .ok_or("Unknown client")?;
            if entry.get("allowed_server_tools").is_some() && pending.is_none() {
                return Err("Client already uses per-tool upstream grants".into());
            }
            entry["allowed_server_tools"] = json!({});
            ("restrict", "", Some(*principal), None)
        }
        [
            op @ ("add-stdio" | "add-bundle" | "add-http"),
            id,
            command,
            args @ ..,
        ] => {
            let candidate = match (*op, args) {
                ("add-http", []) => json!({"transport":"http","url":command}),
                ("add-http", [address]) => {
                    json!({"transport":"http","url":command,"connect_ip":address})
                }
                ("add-stdio", _) => json!({"transport":"stdio","command":command,"args":args}),
                ("add-bundle", _) => {
                    json!({"transport":"stdio","command":command,"args":args,"runtime_bundle":true})
                }
                _ => return Err(HELP.into()),
            };
            if let Some(previous) = servers.get(*id)
                && (pending.is_none() || *previous != candidate)
            {
                return Err("Upstream server already exists".into());
            }
            servers.insert((*id).into(), candidate);
            (*op, *id, None, None)
        }
        [op @ ("enable" | "disable"), id] => {
            servers.get_mut(*id).ok_or("Unknown upstream server")?["enabled"] =
                json!(*op == "enable");
            (*op, *id, None, None)
        }
        [op @ ("workspace" | "workspace-folder"), principal, id, root] => {
            if !servers.contains_key(*id) {
                return Err("Unknown upstream server".into());
            }
            let entry = document["clients"]
                .as_array_mut()
                .and_then(|entries| entries.iter_mut().find(|entry| entry["id"] == *principal))
                .ok_or("Unknown client")?;
            if entry.get("upstream_workspace_roots").is_none() {
                entry["upstream_workspace_roots"] = json!({});
            }
            let grant = if *op == "workspace-folder" {
                if !settings.managed {
                    return Err("Provider-only workspace requires managed policy".into());
                }
                let selected = super::workspace::Grant::parse(&json!(root))?;
                match selected.durable {
                    Some(durable) => {
                        json!({"root":selected.root,"device":selected.identity[0],"inode":selected.identity[1],"durable":durable})
                    }
                    None => {
                        json!({"root":selected.root,"device":selected.identity[0],"inode":selected.identity[1]})
                    }
                }
            } else {
                json!(root)
            };
            entry["upstream_workspace_roots"][*id] = grant;
            (*op, *id, Some(*principal), None)
        }
        ["unworkspace", principal, id] => {
            let entry = document["clients"]
                .as_array_mut()
                .and_then(|entries| entries.iter_mut().find(|entry| entry["id"] == *principal))
                .ok_or("Unknown client")?;
            if let Some(map) = entry
                .get_mut("upstream_workspace_roots")
                .and_then(Value::as_object_mut)
            {
                map.remove(*id);
            }
            ("unworkspace", *id, Some(*principal), None)
        }
        ["remove", id] => {
            if servers.remove(*id).is_none() && policy.pending_client()?.is_none() {
                return Err("Unknown upstream server".into());
            }
            for client in document["clients"].as_array_mut().ok_or(HELP)? {
                if let Some(grants) = client
                    .get_mut("allowed_servers")
                    .and_then(Value::as_array_mut)
                {
                    grants.retain(|grant| grant.as_str() != Some(id));
                }
                if let Some(grants) = client
                    .get_mut("allowed_server_tools")
                    .and_then(Value::as_object_mut)
                {
                    grants.remove(*id);
                }
                if let Some(grants) = client
                    .get_mut("upstream_workspace_roots")
                    .and_then(Value::as_object_mut)
                {
                    grants.remove(*id);
                }
            }
            if let Some(oauth) = document.get_mut("oauth").and_then(Value::as_object_mut)
                && let Some(grants) = oauth.get_mut("allowed_server_tools").and_then(Value::as_object_mut)
            {
                grants.remove(*id);
                if grants.is_empty() {
                    oauth.remove("allowed_server_tools");
                    oauth.insert("workspace_upstreams".into(), json!(false));
                }
            }
            ("remove", *id, None, None)
        }
        [op @ ("grant" | "revoke"), principal, id, tool] => {
            if !servers.contains_key(*id) || !tool_name(tool) {
                return Err("Unknown server or invalid upstream tool name".into());
            }
            let client = settings
                .clients
                .iter()
                .find(|client| client.id == *principal)
                .ok_or("Unknown client")?;
            if !client
                .actions
                .contains(&mcp_gateway::security::policy::Action::CallUpstream)
            {
                return Err("Client requires the mcp_servers_call tool grant".into());
            }
            if client.upstreams.tools.is_none() && !client.upstreams.servers.is_empty() {
                return Err("First migrate the client's server-wide grants with mcp-servers restrict CLIENT".into());
            }
            let mut allowed = client.upstreams.servers.clone();
            let mut tools = client.upstreams.tools.clone().unwrap_or_default();
            if *op == "grant" {
                allowed.insert((*id).into());
                tools
                    .entry((*id).into())
                    .or_default()
                    .insert((*tool).into());
            } else if let Some(names) = tools.get_mut(*id) {
                names.remove(*tool);
            }
            let entry = document["clients"]
                .as_array_mut()
                .and_then(|entries| entries.iter_mut().find(|entry| entry["id"] == *principal))
                .ok_or("Unknown client")?;
            entry["allowed_servers"] = json!(allowed);
            entry["allowed_server_tools"] = json!(tools);
            (*op, *id, Some(*principal), Some(*tool))
        }
        _ => return Err(HELP.into()),
    };
    if op != "restrict" && !server_name(id) {
        return Err("Invalid upstream server identifier".into());
    }
    policy.commit_edit(&document, &marker, |phase| {
        audit.record_upstream_change(op, id, client, tool, phase, now())
    })?;
    Ok(json!({"id":id,"operation":op,"client":client,"tool":tool}))
}
