//! Systemd user-unit generation and explicit, file-only installation.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use mcp_gateway::security::linux_fs::{open_operator_dir, publish_new, reopen_regular};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::http::operator::{PolicyFile, verify_approvals};

const UNIT: &str = "mcp-gateway.service";
const HELP: &str = "usage: veyl service on [--config PATH] [--listen IP:PORT]\n\
                   mcp-gateway service print-unit [--config PATH] [--listen IP:PORT]\n\
                   mcp-gateway service install (--dry-run | --confirm) [--config PATH] [--listen IP:PORT]\n\
                   mcp-gateway service uninstall --confirm [--dry-run] [--config PATH] [--listen IP:PORT]\n\
                   mcp-gateway service <enable|disable|start|stop|restart> (--dry-run | --confirm) [--config PATH] [--listen IP:PORT]\n\
                   mcp-gateway service <status|diagnostics|validate>";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let action = args.first().and_then(|arg| arg.to_str()).ok_or(HELP)?;
    if action == "on" {
        // The verb is explicit operator consent. Use the same ownership,
        // configuration validation and lifecycle checks as the individual steps.
        let options = &args[1..];
        if options
            .iter()
            .any(|arg| arg == "--confirm" || arg == "--dry-run")
        {
            return Err(HELP.into());
        }
        for step in ["install", "start", "enable"] {
            let mut command = vec![OsString::from(step), "--confirm".into()];
            command.extend_from_slice(options);
            run(&command)?;
        }
        return Ok(());
    }
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| valid_path(path))
        .ok_or("HOME must be an absolute directory")?;
    let target = home.join(".config/systemd/user").join(UNIT);
    if matches!(action, "status" | "diagnostics") && args.len() == 1 {
        return status(&target, action == "diagnostics");
    }

    let mut dry_run = false;
    let mut confirm = false;
    let mut config = None;
    let mut listen = None;
    let mut args = args[1..].iter();
    while let Some(key) = args.next() {
        match key.to_str() {
            Some("--dry-run")
                if matches!(
                    action,
                    "install" | "uninstall" | "enable" | "disable" | "start" | "stop" | "restart"
                ) && !dry_run =>
            {
                dry_run = true;
            }
            Some("--confirm")
                if matches!(
                    action,
                    "install" | "uninstall" | "enable" | "disable" | "start" | "stop" | "restart"
                ) && !confirm =>
            {
                confirm = true;
            }
            Some("--config") if config.is_none() => {
                config = Some(PathBuf::from(args.next().ok_or(HELP)?))
            }
            Some("--listen") if listen.is_none() => {
                listen = Some(args.next().and_then(|value| value.to_str()).ok_or(HELP)?);
            }
            _ => return Err(HELP.into()),
        }
    }
    if !matches!(
        (action, dry_run, confirm),
        ("print-unit" | "validate", false, false)
            | (
                "enable" | "disable" | "start" | "stop" | "restart",
                false,
                true
            )
            | ("install", true, false)
            | ("install", false, true)
            | ("uninstall", _, true)
            | (
                "enable" | "disable" | "start" | "stop" | "restart",
                true,
                false
            )
    ) {
        return Err(HELP.into());
    }

    let config = config.unwrap_or_else(|| home.join(".config/mcp-gateway/clients.json"));
    let address: SocketAddrV4 = listen
        .unwrap_or("127.0.0.1:7331")
        .parse()
        .map_err(|_| "Expected a fixed IPv4 loopback listen address")?;
    let executable = env::current_exe().map_err(|_| "Gateway executable unavailable")?;
    let unit = render(&executable, &config, address)?;
    if action == "validate" {
        verify_approvals(&PolicyFile::preview(&config)?)?;
        println!("Configuration valid for {}", address);
        return Ok(());
    }
    if matches!(action, "enable" | "disable" | "start" | "stop" | "restart") {
        if matches!(action, "enable" | "start" | "restart") {
            if dry_run {
                verify_approvals(&PolicyFile::preview(&config)?)?;
            } else {
                let policy = PolicyFile::lock(&config, false)?;
                verify_approvals(&policy.snapshot()?)?;
            }
        }
        if dry_run {
            println!(
                "SERVICE_PLAN action={action} destination={} activation=none",
                target.display()
            );
            return Ok(());
        }
        return lifecycle(action, &target, unit.as_bytes());
    }
    if action == "uninstall" {
        return if dry_run {
            println!(
                "SERVICE_PLAN action=uninstall destination={} activation=none data=preserved",
                target.display()
            );
            Ok(())
        } else {
            uninstall(&target, unit.as_bytes())
        };
    }
    match (action, dry_run) {
        ("print-unit", _) => print!("{unit}"),
        (_, true) => {
            println!(
                "SERVICE_PLAN destination={} activation=none",
                target.display()
            );
            print!("{unit}");
        }
        (_, false) => {
            if rustix::process::geteuid().is_root() {
                return Err("Service installation requires the unprivileged gateway owner".into());
            }
            let policy = PolicyFile::lock(&config, false)?;
            verify_approvals(&policy.snapshot()?)?;
            let dir = unit_directory(&home)
                .map_err(|error| format!("User unit directory unavailable: {error}"))?;
            if owned_unit(&target, unit.as_bytes(), false).is_ok_and(|found| found) {
                println!(
                    "SERVICE_UNIT=UNCHANGED destination={} activation=none",
                    target.display()
                );
                return Ok(());
            }
            publish_new(&dir, OsStr::new(UNIT), unit.as_bytes())
                .map_err(|error| format!("User unit was not installed: {error}"))?;
            println!(
                "SERVICE_UNIT=WRITTEN destination={} activation=none",
                target.display()
            );
        }
    }
    Ok(())
}

/// Explicitly switch the matching installed unit to foreground operation.
/// Never stop an unrelated or overridden service.
pub(crate) fn portable(args: &[OsString]) -> Result<(), String> {
    let (mut config, mut listen) = (None, None);
    let mut options = args.iter();
    while let Some(arg) = options.next() {
        match arg.to_str() {
            Some("--config") if config.is_none() => {
                config = Some(PathBuf::from(options.next().ok_or(HELP)?))
            }
            Some("--listen") if listen.is_none() => {
                listen = Some(
                    options
                        .next()
                        .and_then(|v| v.to_str())
                        .ok_or(HELP)?
                        .parse::<SocketAddrV4>()
                        .map_err(|_| "Invalid IPv4 listener")?,
                )
            }
            _ => return Err(HELP.into()),
        }
    }
    let config = config.ok_or("Missing configuration")?;
    let listen = listen.ok_or("Missing listener")?;
    let executable = env::current_exe().map_err(|_| "Gateway executable unavailable")?;
    let expected = render(&executable, &config, listen)?;
    verify_approvals(&PolicyFile::preview(&config)?)?;
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| valid_path(p))
        .ok_or("HOME must be absolute")?;
    let target = home.join(".config/systemd/user").join(UNIT);
    if owned_unit(&target, expected.as_bytes(), false).map_err(|error| error.to_string())? {
        lifecycle("stop", &target, expected.as_bytes())?;
        lifecycle("disable", &target, expected.as_bytes())?;
        println!("Veyl user service stopped and disabled. Use veyl service on to restore it.");
    }
    crate::http::run(args.to_vec())
}

fn render(executable: &Path, config: &Path, address: SocketAddrV4) -> Result<String, String> {
    if *address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err("Service requires a fixed 127.0.0.1 port".into());
    }
    let executable = quote(executable)?;
    let config = quote(config)?;
    Ok(format!(
        "[Unit]\nDescription=Local Rust MCP gateway\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n\
         [Service]\nType=simple\nExecStart={executable} http --listen {address} --config {config}\n\
         Restart=on-failure\nRestartSec=2s\nTimeoutStopSec=20s\nKillMode=process\n\
         MemoryMax=512M\nTasksMax=128\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=full\n\
         UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH RUST_LOG\nStandardOutput=journal\nStandardError=journal\n\n\
         [Install]\nWantedBy=default.target\n"
    ))
}

fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
}

fn quote(path: &Path) -> Result<String, String> {
    let path = path
        .to_str()
        .filter(|_| valid_path(path))
        .filter(|value| !value.chars().any(char::is_control))
        .ok_or("Unit paths must be absolute UTF-8 paths without control characters")?;
    let escaped = path
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    Ok(format!("\"{escaped}\""))
}

fn checked(directory: impl AsFd) -> io::Result<()> {
    let stat = fs::fstat(directory)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory must be controlled by its owner",
        ));
    }
    Ok(())
}

fn unit_directory(home: &Path) -> io::Result<OwnedFd> {
    let mut directory = open_operator_dir(home)?;
    checked(&directory)?;
    for name in [".config", "systemd", "user"] {
        match fs::mkdirat(&directory, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => fs::fsync(&directory)?,
            Err(Errno::EXIST) => (),
            Err(error) => return Err(error.into()),
        }
        directory = fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        checked(&directory)?;
    }
    Ok(directory)
}

fn uninstall(path: &Path, expected: &[u8]) -> Result<(), String> {
    if rustix::process::geteuid().is_root() {
        return Err("Service uninstallation requires the unprivileged gateway owner".into());
    }
    if let Ok(properties) = query_unit()
        && properties["FragmentPath"]
            .as_str()
            .is_some_and(|fragment| Path::new(fragment) == path)
        && (!matches!(
            properties["ActiveState"].as_str(),
            Some("inactive" | "failed")
        ) || matches!(
            properties["UnitFileState"].as_str(),
            Some("enabled" | "enabled-runtime" | "linked" | "linked-runtime")
        ))
    {
        return Err("Stop and disable the Veyl unit before uninstalling it".into());
    }
    let result = owned_unit(path, expected, true)
        .map_err(|error| format!("User unit was not removed: {error}"))?;
    let state = if result { "REMOVED" } else { "ABSENT" };
    println!(
        "SERVICE_UNIT={state} destination={} activation=none data=preserved",
        path.display()
    );
    Ok(())
}

fn owned_unit(path: &Path, expected: &[u8], remove: bool) -> io::Result<bool> {
    let refuse = || io::Error::other("unit does not match the generated configuration");
    let directory = match open_operator_dir(path.parent().ok_or_else(refuse)?) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    checked(&directory)?;
    let handle = match fs::openat(
        &directory,
        UNIT,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(handle) => handle,
        Err(Errno::NOENT) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let metadata = fs::fstat(&handle)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 1
    {
        return Err(refuse());
    }

    let mut content = Vec::new();
    File::from(reopen_regular(handle, OFlags::RDONLY)?)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut content)?;
    let current = fs::statat(&directory, UNIT, AtFlags::SYMLINK_NOFOLLOW)?;
    let identity = |meta: &fs::Stat| {
        (
            meta.st_dev,
            meta.st_ino,
            meta.st_ctime,
            meta.st_ctime_nsec,
            meta.st_nlink,
        )
    };
    let legacy = std::str::from_utf8(expected)
        .map_err(|_| refuse())?
        .replace("ProtectSystem=full\n", "");
    if (content != expected && !(remove && content == legacy.as_bytes()))
        || identity(&metadata) != identity(&current)
    {
        return Err(refuse());
    }
    if remove {
        fs::unlinkat(&directory, UNIT, AtFlags::empty())?;
        fs::fsync(&directory)?;
    }
    Ok(true)
}

fn manager(args: &[&str]) -> Result<String, String> {
    let mut command = Command::new("/usr/bin/systemctl");
    command
        .args(["--user", "--no-pager", "--no-ask-password"])
        .args(args);
    let (status, bytes) = crate::linux_command::capture(
        &mut command,
        32_768,
        Duration::from_secs(if args[0] == "show" { 2 } else { 27 }),
    )
    .map_err(|error| format!("User systemd manager unavailable: {error}"))?;
    if !status.success() {
        return Err(format!(
            "User systemd rejected {} ({status}). Inspect service diagnostics.",
            args[0]
        ));
    }
    String::from_utf8(bytes).map_err(|_| "Invalid systemd reply".into())
}

fn query_unit() -> Result<Value, String> {
    let properties = "LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,MainPID,Result,NRestarts,MemoryCurrent,TasksCurrent";
    let output = manager(&["show", "--property", properties, UNIT])?;
    let properties: Vec<_> = properties.split(',').collect();
    let fields = output
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| properties.contains(key))
        .map(|(key, value)| (key.to_owned(), json!(value)))
        .collect();
    Ok(Value::Object(fields))
}

pub(crate) fn health() -> Value {
    let result = query_unit();
    match result {
        Ok(mut status) => {
            status.as_object_mut().unwrap().remove("FragmentPath");
            status.as_object_mut().unwrap().remove("DropInPaths");
            status
        }
        Err(_) => json!({"LoadState":"manager-unavailable"}),
    }
}

fn status(path: &Path, diagnostics: bool) -> Result<(), String> {
    let present = match path.symlink_metadata() {
        Ok(meta) if meta.is_file() => "present",
        Ok(_) => "unexpected-file-type",
        Err(error) if error.kind() == io::ErrorKind::NotFound => "missing",
        Err(_) => return Err("Cannot inspect user unit path".into()),
    };
    println!("unit_file={present} destination={}", path.display());
    if diagnostics {
        println!("{}", serde_json::to_string_pretty(&health()).unwrap());
        return Ok(());
    }
    if present == "missing" {
        return Ok(());
    }
    let fields = query_unit()?;
    for key in ["LoadState", "ActiveState", "SubState", "UnitFileState"] {
        println!("{key}={}", fields[key].as_str().unwrap_or_default());
    }
    Ok(())
}

fn unit_matches(properties: &Value, path: &Path) -> bool {
    properties["LoadState"] == "loaded"
        && properties["DropInPaths"] == ""
        && properties["FragmentPath"]
            .as_str()
            .is_some_and(|fragment| Path::new(fragment) == path)
}

fn lifecycle(action: &str, target: &Path, expected: &[u8]) -> Result<(), String> {
    if rustix::process::geteuid().is_root() {
        return Err("Use the existing unprivileged Veyl operator".into());
    }
    if !owned_unit(target, expected, false).map_err(|error| error.to_string())? {
        return Err("Install the Veyl user unit first".into());
    }
    let loaded = query_unit()?;
    if loaded["LoadState"] != "not-found" && !unit_matches(&loaded, target) {
        return Err("The user manager has a different or overridden service unit".into());
    }
    // Only reload to discover a newly installed file. Reject a shadowing
    // unit or effective drop-in before submitting any lifecycle operation.
    if loaded["LoadState"] == "not-found" {
        manager(&["daemon-reload"])?;
    }
    if !unit_matches(&query_unit()?, target) {
        return Err("The user manager did not load the expected Veyl unit".into());
    }
    manager(&[action, UNIT])?;
    status(target, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_fixed_loopback_unit_and_escapes_systemd_interpolation() {
        let unit = render(
            Path::new("/a path/mcp"),
            Path::new("/home/test/%h/$X/a\"b"),
            "127.0.0.1:7331".parse().unwrap(),
        )
        .unwrap();
        assert!(unit.contains("\"/a path/mcp\" http --listen 127.0.0.1:7331"));
        assert!(unit.contains(r#""/home/test/%%h/$$X/a\"b""#));
        assert!(unit.contains("KillMode=process"));
        assert!(
            render(
                Path::new("/a"),
                Path::new("/b"),
                "0.0.0.0:7331".parse().unwrap()
            )
            .is_err()
        );
    }
}
