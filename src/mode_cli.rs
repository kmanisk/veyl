//! Local operator entry points for execution mode and client state.

pub(crate) mod transition;

use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::http::admission::Client;
use crate::http::operator::{Mode, PolicyFile, verify_approvals};

const USAGE: &str = "Usage: veyl mode [list] [--config PATH]\n       veyl mode standard|yolo [CLIENT | --all] [--config PATH] [--yes | --confirm-native]\n       veyl mode get|enable|disable [CLIENT] [--config PATH]\n       veyl mode migrate --config PATH\nWithout a client, mode selection updates default_mode and applies to all enabled clients (static and OAuth) in ~/.local/state/veyl. Targeted selection updates only the specified client (by exact ID or unambiguous name). YOLO requires local typed confirmation ('YOLO') or --yes and runs commands with the gateway user's OS access.";
const LEGACY_USAGE: &str = "Compatibility: veyl yolo disable|reset|status --client ID --config PATH. See veyl mode --help.";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    List,
    Get,
    Migrate,
    Select(Mode),
    SelectAll(Mode),
    SetDisabled(bool),
}

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    dispatch(args, false)
}

pub(crate) fn legacy(args: &[OsString]) -> Result<(), String> {
    dispatch(args, true)
}

fn dispatch(args: &[OsString], legacy: bool) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help") {
        println!("{}", if legacy { LEGACY_USAGE } else { USAGE });
        return Ok(());
    }
    let (operation, config, id, managed_flag) = parse(args, legacy)?;
    if managed_flag && config.is_some() {
        return Err("Do not combine --managed with --config".into());
    }
    if !legacy && managed_flag && config.is_none() {
        if crate::oauth_cli::managed::managed_exists()? {
            return dispatch_managed(operation, id);
        }
        return Err("No managed OAuth login profile".into());
    }
    if !legacy && config.is_none() {
        return dispatch_unified(operation, id);
    }
    let config = match config {
        Some(path) => path,
        None => crate::local_cli::optional_default_config()?.ok_or(USAGE)?,
    };
    if operation == Operation::Migrate {
        return transition::migrate(&config);
    }
    if let Operation::SelectAll(mode) = operation {
        transition::set_default_and_apply_all(&config, mode)?;
        let settings = settings(&config)?;
        println!("default_mode={}", settings.default_mode.as_str());
        for client in &settings.clients {
            show(&config, &client.id, false)?;
        }
        return Ok(());
    }
    if operation == Operation::List {
        let settings = settings(&config)?;
        for client in &settings.clients {
            println!(
                "{}\t{}\t{}",
                client.id,
                client.mode.public_label(),
                state(client)
            );
        }
        return Ok(());
    }
    let id = match id {
        Some(id) => id,
        None => select_client(&config)?,
    };
    if operation == Operation::Get {
        return show(&config, &id, legacy);
    }
    transition::apply(&config, &id, operation)?;
    show(&config, &id, legacy)
}

enum ResolvedTarget {
    Static(String),
    OAuth(String),
}

fn resolve_unified_target(
    query: &str,
    static_clients: &[Client],
    oauth_regs: &[serde_json::Value],
) -> Result<ResolvedTarget, String> {
    let mut matches = Vec::new();
    if static_clients.iter().any(|c| c.id == query) {
        matches.push(ResolvedTarget::Static(query.to_owned()));
    }
    let exact_oauth: Vec<_> = oauth_regs
        .iter()
        .filter(|r| r["client_id"].as_str() == Some(query))
        .collect();
    for r in exact_oauth {
        if let Some(cid) = r["client_id"].as_str() {
            matches.push(ResolvedTarget::OAuth(cid.to_owned()));
        }
    }
    if matches.is_empty() {
        for r in oauth_regs {
            if r["client_name"].as_str() == Some(query)
                && let Some(cid) = r["client_id"].as_str()
            {
                matches.push(ResolvedTarget::OAuth(cid.to_owned()));
            }
        }
    }
    match matches.len() {
        0 => Err(format!("Unknown client: {query}")),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => Err(format!(
            "Ambiguous client identifier '{query}'; specify exact client ID"
        )),
    }
}

fn switch_unified_oauth_mode(
    home: &Path,
    settings: &crate::http::admission::Configuration,
    target_id: Option<&str>,
    target_mode: mcp_gateway::core::oauth::ConnectionMode,
) -> Result<Vec<(String, String, bool)>, String> {
    use mcp_gateway::{core::oauth::ConnectionMode, http_common::oauth_http};
    use serde_json::json;

    let Some(oauth) = &settings.oauth else {
        return Ok(Vec::new());
    };
    if !oauth.state_dir.join("oauth-state.json").exists() {
        return Ok(Vec::new());
    }
    let live = crate::unified::is_serve_live(home)?;
    if target_mode == ConnectionMode::Yolo && (!settings.managed || settings.jobs.is_none()) {
        return Err("YOLO override requires managed job configuration".into());
    }
    let mut out = Vec::new();
    match target_id {
        None => {
            if live {
                let (status, body) = crate::unified::send_control_command(
                    home,
                    &json!({"action": "mode_all", "mode": target_mode.as_str(), "confirm": true}),
                )?;
                if status != 200 {
                    let msg = body["error"].as_str().unwrap_or("OAuth mode update rejected");
                    return Err(format!("Failed updating live OAuth clients: {msg}"));
                }
                if let Some(updated) = body["updated"].as_array() {
                    for u in updated {
                        out.push((
                            u["client_id"].as_str().unwrap_or("?").to_owned(),
                            u["previous_mode"].as_str().unwrap_or("standard").to_owned(),
                            u["reauthorization_required"].as_bool().unwrap_or(false),
                        ));
                    }
                }
            } else {
                for (cid, prev, reauth) in oauth_http::switch_all_stopped_clients_mode(
                    &oauth.state_dir,
                    &oauth.local_client,
                    target_mode,
                )? {
                    out.push((cid, prev.as_str().to_owned(), reauth));
                }
            }
        }
        Some(cid) => {
            if live {
                let (status, body) = crate::unified::send_control_command(
                    home,
                    &json!({"action": "mode", "client_id": cid, "mode": target_mode.as_str(), "confirm": true}),
                )?;
                if status != 200 {
                    let msg = body["error"].as_str().unwrap_or("OAuth mode update rejected");
                    return Err(format!("Failed updating live OAuth client {cid}: {msg}"));
                }
                out.push((
                    cid.to_owned(),
                    body["previous_mode"]
                        .as_str()
                        .unwrap_or("standard")
                        .to_owned(),
                    body["reauthorization_required"]
                        .as_bool()
                        .unwrap_or(false),
                ));
            } else {
                let (prev, reauth) = oauth_http::switch_stopped_client_mode(
                    &oauth.state_dir,
                    &oauth.local_client,
                    cid,
                    target_mode,
                )?;
                out.push((cid.to_owned(), prev.as_str().to_owned(), reauth));
            }
        }
    }
    Ok(out)
}

fn dispatch_unified(operation: Operation, id: Option<String>) -> Result<(), String> {
    use mcp_gateway::core::oauth::ConnectionMode;

    let home = crate::unified::home_dir()?;
    let status = crate::unified::ensure_reconciled(&home)?;
    let cfg = crate::unified::config_path(&home);

    if status == crate::unified::ReconcileStatus::FreshEmpty {
        return match operation {
            Operation::List => {
                println!("default_mode=standard");
                println!("No clients configured.");
                Ok(())
            }
            Operation::Get => Err("No clients configured (default_mode=standard)".into()),
            Operation::SelectAll(mode) => {
                let cfg = crate::unified::ensure_minimal_empty_registry(&home)?;
                transition::set_default_and_apply_all(&cfg, mode)?;
                let mode_str = if mode == Mode::NativeYolo {
                    "yolo"
                } else {
                    "standard"
                };
                println!("default_mode={mode_str}");
                Ok(())
            }
            Operation::Migrate => Err("No legacy policy to migrate".into()),
            _ => Err("No clients configured yet; run 'veyl up' first".into()),
        };
    }

    if operation == Operation::Migrate {
        return transition::migrate(&cfg);
    }

    let current = settings(&cfg)?;
    let (live, regs, _supports_yolo) =
        crate::unified::fetch_oauth_registrations(&home, &current)?;

    match operation {
        Operation::List => {
            println!(
                "default_mode={}",
                current.default_mode.as_str()
            );
            for client in &current.clients {
                println!(
                    "{}\t{}\t{}\ttype=static",
                    client.id,
                    client.mode.public_label(),
                    state(client)
                );
            }
            for reg in &regs {
                println!(
                    "{}\t{}\tactive_families={}\ttype=oauth\tname={}",
                    reg["client_id"].as_str().unwrap_or("?"),
                    reg["mode"].as_str().unwrap_or("standard"),
                    reg["active_families"].as_u64().unwrap_or(0),
                    reg["client_name"].as_str().unwrap_or("Unnamed"),
                );
            }
            if current.clients.is_empty() && regs.is_empty() {
                println!("No clients configured (gateway {}).", if live { "live" } else { "stopped" });
            }
            Ok(())
        }
        Operation::SelectAll(mode) => {
            let conn_mode = if mode == Mode::NativeYolo {
                ConnectionMode::Yolo
            } else {
                ConnectionMode::Standard
            };
            transition::set_default_and_apply_all(&cfg, mode)?;
            let oauth_changes = switch_unified_oauth_mode(&home, &current, None, conn_mode)?;
            let updated = settings(&cfg)?;
            println!("default_mode={}", updated.default_mode.as_str());
            for client in &updated.clients {
                show(&cfg, &client.id, false)?;
            }
            for (cid, prev, reauth) in oauth_changes {
                if conn_mode == ConnectionMode::Yolo {
                    println!("client={cid} type=oauth previous_mode={prev} mode=yolo reauthorization_required={reauth}");
                } else {
                    println!("client={cid} type=oauth previous_mode={prev} mode=standard immediate_downgrade=true");
                }
            }
            Ok(())
        }
        Operation::Get => {
            let target = match id {
                Some(q) => resolve_unified_target(&q, &current.clients, &regs)?,
                None => {
                    let total = current.clients.len() + regs.len();
                    if total == 0 {
                        return Err("No clients configured".into());
                    }
                    if current.clients.len() == 1 && regs.is_empty() {
                        ResolvedTarget::Static(current.clients[0].id.clone())
                    } else if regs.len() == 1 && current.clients.is_empty() {
                        ResolvedTarget::OAuth(
                            regs[0]["client_id"].as_str().unwrap_or_default().to_owned(),
                        )
                    } else {
                        return Err("Multiple clients configured; run 'veyl mode' to list them, then supply a client ID".into());
                    }
                }
            };
            match target {
                ResolvedTarget::Static(sid) => show(&cfg, &sid, false),
                ResolvedTarget::OAuth(oid) => {
                    let entry = regs
                        .into_iter()
                        .find(|r| r["client_id"].as_str() == Some(oid.as_str()))
                        .ok_or("Unknown OAuth client")?;
                    println!(
                        "client={} type=oauth mode={} active_families={} active_yolo_families={} client_name={}",
                        entry["client_id"].as_str().unwrap_or("?"),
                        entry["mode"].as_str().unwrap_or("standard"),
                        entry["active_families"].as_u64().unwrap_or(0),
                        entry["active_yolo_families"].as_u64().unwrap_or(0),
                        entry["client_name"].as_str().unwrap_or("Unnamed"),
                    );
                    Ok(())
                }
            }
        }
        Operation::Select(mode) => {
            let q = match id {
                Some(q) => q,
                None => return Err("Specify a client ID or omit client to apply globally".into()),
            };
            match resolve_unified_target(&q, &current.clients, &regs)? {
                ResolvedTarget::Static(sid) => {
                    transition::apply(&cfg, &sid, Operation::Select(mode))?;
                    show(&cfg, &sid, false)
                }
                ResolvedTarget::OAuth(oid) => {
                    let conn_mode = if mode == Mode::NativeYolo {
                        ConnectionMode::Yolo
                    } else {
                        ConnectionMode::Standard
                    };
                    for (cid, prev, reauth) in
                        switch_unified_oauth_mode(&home, &current, Some(&oid), conn_mode)?
                    {
                        if conn_mode == ConnectionMode::Yolo {
                            println!("client={cid} type=oauth previous_mode={prev} mode=yolo reauthorization_required={reauth}");
                        } else {
                            println!("client={cid} type=oauth previous_mode={prev} mode=standard immediate_downgrade=true");
                        }
                    }
                    Ok(())
                }
            }
        }
        Operation::SetDisabled(disabled) => {
            let sid = match id {
                Some(q) => match resolve_unified_target(&q, &current.clients, &regs)? {
                    ResolvedTarget::Static(sid) => sid,
                    ResolvedTarget::OAuth(_) => {
                        return Err("OAuth clients cannot be disabled with mode enable/disable; use 'veyl clients revoke <ID>'".into());
                    }
                },
                None => {
                    if current.clients.len() == 1 {
                        current.clients[0].id.clone()
                    } else if current.clients.is_empty() {
                        return Err("No static clients configured".into());
                    } else {
                        return Err("Multiple static clients configured; specify client ID to enable or disable".into());
                    }
                }
            };
            transition::apply(&cfg, &sid, Operation::SetDisabled(disabled))?;
            show(&cfg, &sid, false)
        }
        Operation::Migrate => transition::migrate(&cfg),
    }
}

fn dispatch_managed(operation: Operation, id: Option<String>) -> Result<(), String> {
    use mcp_gateway::core::oauth::ConnectionMode;
    match operation {
        Operation::List => {
            let (live, regs, _supports_yolo) = crate::oauth_cli::managed::managed_list()?;
            if regs.is_empty() {
                println!("No registered OAuth clients (managed OAuth gateway {}).", if live { "live" } else { "stopped" });
                return Ok(());
            }
            for reg in regs {
                println!(
                    "{}\t{}\tactive_families={}\tname={}",
                    reg["client_id"].as_str().unwrap_or("?"),
                    reg["mode"].as_str().unwrap_or("standard"),
                    reg["active_families"].as_u64().unwrap_or(0),
                    reg["client_name"].as_str().unwrap_or("Unnamed")
                );
            }
            Ok(())
        }
        Operation::Get => {
            let (_live, regs, _supports_yolo) = crate::oauth_cli::managed::managed_list()?;
            let entry = if let Some(target) = &id {
                regs.into_iter()
                    .find(|r| r["client_id"].as_str() == Some(target.as_str()))
                    .ok_or("Unknown OAuth client")?
            } else if regs.len() == 1 {
                regs.into_iter().next().expect("single registration")
            } else if regs.is_empty() {
                return Err("No connected OAuth clients".into());
            } else {
                return Err("Multiple OAuth clients connected; run veyl mode to list them, then supply a client ID".into());
            };
            println!(
                "client={} mode={} active_families={} active_yolo_families={} client_name={}",
                entry["client_id"].as_str().unwrap_or("?"),
                entry["mode"].as_str().unwrap_or("standard"),
                entry["active_families"].as_u64().unwrap_or(0),
                entry["active_yolo_families"].as_u64().unwrap_or(0),
                entry["client_name"].as_str().unwrap_or("Unnamed"),
            );
            Ok(())
        }
        Operation::Select(Mode::Standard) | Operation::SelectAll(Mode::Standard) => {
            let all = matches!(operation, Operation::SelectAll(_));
            let (changed, _live) =
                crate::oauth_cli::managed::managed_set_mode(id.as_deref(), all, ConnectionMode::Standard)?;
            for item in changed {
                println!(
                    "client={} previous_mode={} mode=standard immediate_downgrade=true",
                    item.client_id,
                    item.previous.as_str()
                );
            }
            Ok(())
        }
        Operation::Select(Mode::NativeYolo) | Operation::SelectAll(Mode::NativeYolo) => {
            let all = matches!(operation, Operation::SelectAll(_));
            let (changed, _live) =
                crate::oauth_cli::managed::managed_set_mode(id.as_deref(), all, ConnectionMode::Yolo)?;
            for item in changed {
                println!(
                    "client={} previous_mode={} mode=yolo reauthorization_required={}",
                    item.client_id,
                    item.previous.as_str(),
                    item.reauth_required
                );
            }
            Ok(())
        }
        _ => Err("Managed OAuth profiles support list, get, standard, and yolo".into()),
    }
}

fn settings(path: &Path) -> Result<crate::http::admission::Configuration, String> {
    let policy = PolicyFile::lock(path, false)?;
    let settings = policy.snapshot()?;
    verify_approvals(&settings)?;
    Ok(settings)
}

fn state(client: &Client) -> &'static str {
    if client.is_disabled() {
        "disabled"
    } else {
        "enabled"
    }
}

fn show(path: &Path, id: &str, _legacy: bool) -> Result<(), String> {
    let settings = settings(path)?;
    let client = settings.clients.iter().find(|client| client.id == id).ok_or("Unknown client")?;
    let mode = client.mode.public_label();
    println!(
        "client={id} client_state={} mode={mode} migration_required={} tool_grants={}",
        state(client),
        matches!(client.approval_mode, Some("yolo" | "broad_yolo" | "yolo_native" | "full")),
        client.tools.len()
    );
    Ok(())
}

fn select_client(path: &Path) -> Result<String, String> {
    let settings = settings(path)?;
    if let [client] = settings.clients.as_slice() {
        return Ok(client.id.clone());
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(
            "Multiple clients configured; run veyl mode to list them, then supply a client ID"
                .into(),
        );
    }
    let mut stderr = io::stderr().lock();
    for (index, client) in settings.clients.iter().enumerate() {
        writeln!(
            stderr,
            "{}: {} ({}, {})",
            index + 1,
            client.id,
            client.mode.public_label(),
            state(client)
        )
        .map_err(|error| error.to_string())?;
    }
    write!(stderr, "Select client (blank cancels): ").map_err(|error| error.to_string())?;
    stderr.flush().map_err(|error| error.to_string())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| error.to_string())?;
    let index = input
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or("No client selected")?;
    settings
        .clients
        .get(index)
        .map(|client| client.id.clone())
        .ok_or("Invalid client selection".into())
}

fn parse(
    args: &[OsString],
    legacy: bool,
) -> Result<(Operation, Option<PathBuf>, Option<String>, bool), String> {
    parse_with_confirmer(args, legacy, confirm_native)
}

fn parse_with_confirmer(
    args: &[OsString],
    legacy: bool,
    confirm_prompt: impl FnOnce() -> Result<(), String>,
) -> Result<(Operation, Option<PathBuf>, Option<String>, bool), String> {
    let usage = if legacy { LEGACY_USAGE } else { USAGE };
    let (command, skip_first) = match args.first() {
        Some(word) if (word == "--config" || word == "--managed") && !legacy => ("list", false),
        Some(word) => (word.to_str().ok_or(usage)?, true),
        None if !legacy => ("list", false),
        None => return Err(usage.into()),
    };
    let mut selected = match (legacy, command) {
        (false, "standard") => Some(Mode::Standard),
        (false, "yolo") => Some(Mode::NativeYolo),
        _ => None,
    };
    let mut config = None;
    let mut managed = false;
    let mut client = None;
    let mut confirm = false;
    let mut all = false;
    let mut rest = args[usize::from(skip_first)..].iter();
    while let Some(arg) = rest.next() {
        match arg.to_str() {
            Some("--config") if config.is_none() => {
                config = Some(PathBuf::from(rest.next().ok_or(usage)?))
            }
            Some("--managed") if !legacy && !managed => managed = true,
            Some("--client") if client.is_none() => {
                client = Some(argument(rest.next(), usage)?.to_owned());
            }
            Some("--mode") if command == "set" && selected.is_none() => {
                selected = Some(selection(argument(rest.next(), usage)?)?);
            }
            Some("--confirm-native" | "--yes") if !legacy && !confirm => confirm = true,
            Some("--all") if !legacy && !all => all = true,
            Some(value) if !value.starts_with('-') && client.is_none() => {
                client = Some(value.to_owned())
            }
            Some(value) if !value.starts_with('-') && command == "set" && selected.is_none() => {
                selected = Some(selection(value)?);
            }
            _ => return Err(usage.into()),
        }
    }
    let operation = match (legacy, command, selected) {
        (_, "get" | "status", None) => Operation::Get,
        (false, "list", None) if client.is_none() => Operation::List,
        (false, "migrate", None) if client.is_none() => Operation::Migrate,
        (false, "enable", None) => Operation::SetDisabled(false),
        (false, "disable", None) => Operation::SetDisabled(true),
        (true, "disable" | "reset" | "standard", None) => Operation::Select(Mode::Standard),
        (false, "set" | "standard" | "yolo", Some(mode)) => Operation::Select(mode),
        _ => return Err(usage.into()),
    };
    let operation = if all {
        match operation {
            Operation::Select(mode) if client.is_none() => Operation::SelectAll(mode),
            _ => return Err("--all requires a mode selection without a client ID".into()),
        }
    } else if !legacy && client.is_none() {
        match operation {
            Operation::Select(mode) => Operation::SelectAll(mode),
            other => other,
        }
    } else {
        operation
    };
    let yolo = matches!(operation, Operation::Select(Mode::NativeYolo) | Operation::SelectAll(Mode::NativeYolo));
    if confirm && !yolo || managed && config.is_some() {
        return Err(usage.into());
    }
    if legacy && config.is_none() {
        return Err(usage.into());
    }
    if yolo && !confirm {
        confirm_prompt()?;
    }
    Ok((operation, config, client, managed))
}

fn confirm_native() -> Result<(), String> {
    confirm_native_io(io::stdin().is_terminal() && io::stderr().is_terminal(), &mut io::stdin().lock())
}

fn confirm_native_io(interactive: bool, reader: &mut dyn io::BufRead) -> Result<(), String> {
    if !interactive {
        return Err("YOLO requires typed local confirmation or --yes. Commands have host-user access including Veyl state".into());
    }
    eprint!("YOLO grants native access as your Linux user, including private Veyl state. Type YOLO to confirm: ");
    io::stderr().flush().map_err(|_| "Cannot display confirmation")?;
    let mut answer = String::new();
    reader.read_line(&mut answer).map_err(|_| "Cannot read confirmation")?;
    if answer.trim() != "YOLO" {
        return Err("Cancelled; no mode changed".into());
    }
    Ok(())
}

fn argument<'a>(option: Option<&'a OsString>, usage: &str) -> Result<&'a str, String> {
    option
        .and_then(|arg| OsStr::to_str(arg))
        .filter(|arg| !arg.is_empty() && !arg.starts_with('-'))
        .ok_or_else(|| usage.to_owned())
}

fn selection(value: &str) -> Result<Mode, String> {
    match value {
        "standard" => Ok(Mode::Standard),
        "yolo" => Ok(Mode::NativeYolo),
        _ => Err("Choose Standard or YOLO".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn selection_requires_native_confirmation_and_rejects_full() {
        let non_tty = |values: &[&str], legacy| {
            parse_with_confirmer(&args(values), legacy, || {
                confirm_native_io(false, &mut io::empty())
            })
        };
        assert!(non_tty(&["yolo", "dev"], false).is_err());
        assert!(non_tty(&["full", "dev"], false).is_err());
        assert!(matches!(
            non_tty(&["yolo", "dev", "--confirm-native"], false),
            Ok((Operation::Select(Mode::NativeYolo), _, _, _))
        ));
        assert!(matches!(
            non_tty(&["standard", "--all"], false),
            Ok((Operation::SelectAll(Mode::Standard), _, _, _))
        ));
        assert!(matches!(non_tty(&["standard"], false), Ok((Operation::SelectAll(Mode::Standard), _, _, _))));
        assert!(matches!(non_tty(&["yolo", "--yes"], false), Ok((Operation::SelectAll(Mode::NativeYolo), _, _, _))));
        assert!(non_tty(&["standard", "--yes"], false).is_err());
        assert!(non_tty(&["yolo", "--yes", "--all", "dev"], false).is_err());
        assert!(non_tty(&["yolo", "--yes", "--managed", "--config", "/tmp/policy"], false).is_err());
        assert!(confirm_native_io(true, &mut io::Cursor::new(b"YOLO\n")).is_ok());
        assert!(confirm_native_io(true, &mut io::Cursor::new(b"yes\n")).is_err());
    }
}
