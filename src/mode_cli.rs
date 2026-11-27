//! Local operator entry points for execution mode and client state.

mod transition;

use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::http::admission::Client;
use crate::http::operator::{Mode, PolicyFile, verify_approvals};

const USAGE: &str = "Usage: veyl mode [list] [--config PATH | --managed]\n       veyl mode standard|yolo [CLIENT | --all] [--config PATH] [--confirm-native]\n       veyl mode get|enable|disable [CLIENT] [--config PATH]\n       veyl mode migrate --config PATH\nWithout --config, manages connected clients in the managed OAuth login profile when present. Native client configurations accept --config PATH. YOLO requires --confirm-native and runs commands with the gateway user’s OS access.";
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
    let config = match config {
        Some(path) => path,
        None => {
            if !legacy && managed_flag {
                if crate::oauth_cli::managed::managed_exists()? {
                    return dispatch_managed(operation, id);
                }
                return Err("No managed OAuth login profile".into());
            }
            if !legacy && crate::oauth_cli::managed::managed_exists()? {
                let native = crate::local_cli::optional_default_config()?;
                match (&operation, &id, native) {
                    (Operation::List, None, Some(native_path)) => {
                        let native_settings = settings(&native_path)?;
                        for client in &native_settings.clients {
                            println!(
                                "{}\t{}\t{}\tscope=native",
                                client.id,
                                client.mode.public_label(),
                                state(client)
                            );
                        }
                        return dispatch_managed(Operation::List, None);
                    }
                    (_, Some(target), Some(native_path)) => {
                        let (_, regs, _) = crate::oauth_cli::managed::managed_list()?;
                        if regs.iter().any(|r| r["client_id"].as_str() == Some(target.as_str())) {
                            return dispatch_managed(operation, id);
                        }
                        native_path
                    }
                    _ => return dispatch_managed(operation, id),
                }
            } else {
                crate::local_cli::optional_default_config()?.ok_or(USAGE)?
            }
        }
    };
    if managed_flag {
        return Err("Do not combine --managed with --config".into());
    }
    if operation == Operation::Migrate {
        return transition::migrate(&config);
    }
    if let Operation::SelectAll(mode) = operation {
        transition::apply_all(&config, mode)?;
        let settings = settings(&config)?;
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

fn dispatch_managed(operation: Operation, id: Option<String>) -> Result<(), String> {
    use mcp_gateway::core::oauth::ConnectionMode;
    match operation {
        Operation::List => {
            let (live, regs, _supports_yolo) = crate::oauth_cli::managed::managed_list()?;
            if regs.is_empty() {
                println!("No connected OAuth clients (gateway {}).", if live { "live" } else { "stopped" });
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
            Some("--confirm-native") if !confirm => confirm = true,
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
    } else {
        operation
    };
    let yolo = matches!(operation, Operation::Select(Mode::NativeYolo) | Operation::SelectAll(Mode::NativeYolo));
    if yolo && !confirm {
        return Err("YOLO requires --confirm-native. Commands have host-user access including Veyl state".into());
    }
    if confirm && !yolo {
        return Err(usage.into());
    }
    if legacy && config.is_none() {
        return Err(usage.into());
    }
    Ok((operation, config, client, managed))
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
        assert!(parse(&args(&["yolo", "dev"]), false).is_err());
        assert!(parse(&args(&["full", "dev"]), false).is_err());
        assert!(matches!(
            parse(&args(&["yolo", "dev", "--confirm-native"]), false),
            Ok((Operation::Select(Mode::NativeYolo), _, _, _))
        ));
        assert!(matches!(
            parse(&args(&["standard", "--all"]), false),
            Ok((Operation::SelectAll(Mode::Standard), _, _, _))
        ));
    }
}
