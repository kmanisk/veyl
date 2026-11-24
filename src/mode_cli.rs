//! Local operator entry points for execution mode and client state.

mod transition;

use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::http::admission::Client;
use crate::http::operator::{Mode, PolicyFile, verify_approvals};

const USAGE: &str = "Usage: veyl mode [list]\n       veyl mode standard|yolo|full [CLIENT] [--confirm-full]\n       veyl mode get|enable|disable [CLIENT]\n       veyl mode migrate\nAll commands accept --config PATH. With multiple clients, select interactively or supply a client ID. FULL requires --confirm-full.";
const LEGACY_USAGE: &str = "Compatibility: veyl yolo enable|disable|reset|status|set [--mode MODE] --client ID --config PATH. See veyl mode --help.";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    List,
    Get,
    Migrate,
    Select(Mode),
    SetDisabled(bool),
    EnableScoped,
    Reset,
    LegacyDowngrade,
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
    let (operation, config, id) = parse(args, legacy)?;
    if operation == Operation::Migrate {
        return transition::migrate(&config);
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
    transition::apply(&config, &id, operation, legacy)?;
    show(&config, &id, legacy)
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

fn show(path: &Path, id: &str, legacy: bool) -> Result<(), String> {
    let settings = settings(path)?;
    let client = settings
        .clients
        .iter()
        .find(|client| client.id == id)
        .ok_or("Unknown client")?;
    let mode = client.mode.public_label();
    if legacy {
        use mcp_gateway::security::policy::ExecutionMode;
        let (label, effective, yolo) = match client.mode {
            ExecutionMode::PersistentYolo => ("yolo", "legacy_scoped_yolo", "enabled"),
            ExecutionMode::BroadYolo => ("yolo", "broad_yolo", "enabled"),
            ExecutionMode::Disabled => ("disabled", "disabled", "disabled"),
            _ => (mode, mode, "disabled"),
        };
        println!(
            "client={id} client_state={} yolo={yolo} mode={label} effective_policy={effective} tool_grants={}",
            state(client),
            client.tools.len()
        );
    } else {
        println!(
            "client={id} client_state={} mode={mode} effective_policy={mode} native_tool_preset={} tool_grants={}",
            state(client),
            client.native_tool_preset,
            client.tools.len()
        );
    }
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

fn parse(args: &[OsString], legacy: bool) -> Result<(Operation, PathBuf, Option<String>), String> {
    let usage = if legacy { LEGACY_USAGE } else { USAGE };
    let command = match args.first() {
        Some(word) if word == "--config" && !legacy => "list",
        Some(word) => word.to_str().ok_or(usage)?,
        None => return Err(usage.into()),
    };
    let mut selected = match (legacy, command) {
        (false, "standard") => Some(Mode::Standard),
        (false, "yolo") => Some(Mode::BroadYolo),
        (false, "full") => Some(Mode::Full),
        _ => None,
    };
    let mut config = None;
    let mut client = None;
    let mut confirm = false;
    let mut rest = args[usize::from(args[0] != "--config")..].iter();
    while let Some(arg) = rest.next() {
        match arg.to_str() {
            Some("--config") if config.is_none() => {
                config = Some(PathBuf::from(rest.next().ok_or(usage)?))
            }
            Some("--client") if client.is_none() => {
                client = Some(argument(rest.next(), usage)?.to_owned());
            }
            Some("--mode") if command == "set" && selected.is_none() => {
                selected = Some(selection(argument(rest.next(), usage)?)?);
            }
            Some("--confirm-full") if !confirm => confirm = true,
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
        (true, "enable", None) => Operation::EnableScoped,
        (true, "disable", None) => Operation::LegacyDowngrade,
        (true, "reset" | "standard", None) => Operation::Reset,
        (_, "set" | "standard" | "yolo" | "full", Some(mode)) => Operation::Select(mode),
        _ => return Err(usage.into()),
    };
    if operation == Operation::Select(Mode::Full) && !confirm {
        return Err("FULL requires --confirm-full".into());
    }
    if confirm && operation != Operation::Select(Mode::Full) {
        return Err(usage.into());
    }
    Ok((operation, config.ok_or(usage)?, client))
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
        "yolo" => Ok(Mode::BroadYolo),
        "full" => Ok(Mode::Full),
        _ => Err("Choose Standard, YOLO, or FULL".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_canonical_and_compatibility_spelling() {
        for (legacy, arguments) in [
            (
                false,
                [
                    "set",
                    "--client",
                    "dev",
                    "--mode",
                    "yolo",
                    "--config",
                    "/tmp/config",
                ],
            ),
            (
                true,
                [
                    "set",
                    "--client",
                    "dev",
                    "--mode",
                    "yolo",
                    "--config",
                    "/tmp/config",
                ],
            ),
        ] {
            let (op, _, id) = parse(&args(&arguments), legacy).unwrap();
            assert!(op == Operation::Select(Mode::BroadYolo));
            assert_eq!(id.as_deref(), Some("dev"));
        }
        let (op, _, id) = parse(&args(&["get", "dev", "--config", "/tmp/config"]), false).unwrap();
        assert!(op == Operation::Get);
        assert_eq!(id.as_deref(), Some("dev"));
    }

    #[test]
    fn full_requires_confirmation_and_rejects_ambiguity() {
        assert!(
            parse(
                &args(&["set", "dev", "full", "--config", "/tmp/config"]),
                false
            )
            .is_err()
        );
        assert!(
            parse(
                &args(&[
                    "standard",
                    "dev",
                    "--confirm-full",
                    "--config",
                    "/tmp/config"
                ]),
                false
            )
            .is_err()
        );
        assert!(
            parse(
                &args(&["full", "dev", "--confirm-full", "--config", "/tmp/config"]),
                false
            )
            .is_ok()
        );
        assert!(
            parse(
                &args(&[
                    "set",
                    "dev",
                    "yolo",
                    "--mode",
                    "full",
                    "--config",
                    "/tmp/config"
                ]),
                false
            )
            .is_err()
        );
    }
}
