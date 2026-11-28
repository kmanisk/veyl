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
const UNIT_VEYL: &str = "veyl.service";
const HELP: &str = "usage: veyl service install [--enable-now] [--dry-run] [--confirm | --yes] [--listen IP:PORT] [--funnel-socket PATH]\n\
                   veyl service uninstall [--confirm | --yes] [--dry-run]\n\
                   veyl service <enable|disable|start|stop|restart> [--now] [--dry-run] [--confirm | --yes]\n\
                   veyl service <status|diagnostics|print-unit|validate>\n\
                   Legacy unit compatibility: veyl service on|install|... --config PATH [--listen IP:PORT]";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let use_legacy = args.iter().any(|arg| arg == "--config")
        || args.first().is_some_and(|arg| arg == "on");
    if !use_legacy {
        return run_unified(args);
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
    let unit = render_existing(&target, &executable, &config, address)?;
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
    let has_legacy_flags = args.iter().any(|a| a == "--config" || a == "--listen");
    if !has_legacy_flags {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| valid_path(p))
            .ok_or("HOME must be absolute")?;
        let target = home.join(".config/systemd/user").join(UNIT_VEYL);
        if target.symlink_metadata().is_ok()
            && let Ok(exe) = verified_current_exe()
            && unit_is_owned_veyl(&target, &exe).unwrap_or(false)
        {
            let _ = manager(&["stop", UNIT_VEYL]);
            let _ = manager(&["disable", UNIT_VEYL]);
            println!("Veyl user service stopped and disabled.");
        }
        return crate::serve_cmd::serve(args);
    }
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
    verify_approvals(&PolicyFile::preview(&config)?)?;
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| valid_path(p))
        .ok_or("HOME must be absolute")?;
    let target = home.join(".config/systemd/user").join(UNIT);
    let expected = render_existing(&target, &executable, &config, listen)?;
    if owned_unit(&target, expected.as_bytes(), false).map_err(|error| error.to_string())? {
        lifecycle("stop", &target, expected.as_bytes())?;
        lifecycle("disable", &target, expected.as_bytes())?;
        println!("Veyl user service stopped and disabled. Use veyl service on to restore it.");
    }
    crate::http::run(args.to_vec())
}

/// Keep an exact previously generated unit usable through the migrated
/// gateway alias. Never accept an arbitrary symlink or altered unit.
fn render_existing(
    target: &Path,
    executable: &Path,
    config: &Path,
    address: SocketAddrV4,
) -> Result<String, String> {
    let standard = render(executable, config, address)?;
    if executable.file_name().is_some_and(|name| name == "veyl") {
        let alias = executable.with_file_name("mcp-gateway");
        if crate::update_cli::verified_gateway_alias(&alias)? {
            let legacy = render(&alias, config, address)?;
            if owned_unit(target, legacy.as_bytes(), false).is_ok_and(|found| found) {
                return Ok(legacy);
            }
        }
    }
    Ok(standard)
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
    owned_unit_named(path, UNIT, expected, remove)
}

fn owned_unit_named(path: &Path, unit_name: &str, expected: &[u8], remove: bool) -> io::Result<bool> {
    let refuse = || io::Error::other("unit does not match the generated configuration");
    let directory = match open_operator_dir(path.parent().ok_or_else(refuse)?) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    checked(&directory)?;
    let handle = match fs::openat(
        &directory,
        unit_name,
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
    let current = fs::statat(&directory, unit_name, AtFlags::SYMLINK_NOFOLLOW)?;
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
        fs::unlinkat(&directory, unit_name, AtFlags::empty())?;
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
    query_unit_named(UNIT)
}

fn query_unit_named(unit_name: &str) -> Result<Value, String> {
    let properties = "LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,MainPID,Result,NRestarts,MemoryCurrent,TasksCurrent";
    let output = manager(&["show", "--property", properties, unit_name])?;
    let properties: Vec<_> = properties.split(',').collect();
    let fields = output
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| properties.contains(key))
        .map(|(key, value)| (key.to_owned(), json!(value)))
        .collect();
    Ok(Value::Object(fields))
}

pub(crate) fn legacy_unit_is_active(home: &Path) -> Result<bool, String> {
    let legacy_unit = home.join(".config/systemd/user").join(UNIT);
    match legacy_unit.symlink_metadata() {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("Cannot inspect legacy service unit".into()),
    }
    match query_unit_named(UNIT) {
        Ok(state) => Ok(matches!(
            state["ActiveState"].as_str(),
            Some("active" | "activating" | "reloading")
        )),
        Err(_) => Ok(false),
    }
}

pub(crate) fn veyl_unit_is_active(home: &Path) -> Result<bool, String> {
    let unit = home.join(".config/systemd/user").join(UNIT_VEYL);
    match unit.symlink_metadata() {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("Cannot inspect veyl.service unit".into()),
    }
    match query_unit_named(UNIT_VEYL) {
        Ok(state) => Ok(matches!(
            state["ActiveState"].as_str(),
            Some("active" | "activating" | "reloading")
        )),
        Err(_) => Ok(false),
    }
}

fn verified_current_exe() -> Result<PathBuf, String> {
    let exe = env::current_exe().map_err(|_| "Gateway executable unavailable")?;
    let canonical = exe
        .canonicalize()
        .map_err(|_| "Gateway executable path unavailable")?;
    let meta = std::fs::symlink_metadata(&canonical)
        .map_err(|_| "Cannot inspect gateway executable")?;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !meta.file_type().is_file() || meta.permissions().mode() & 0o111 == 0 || meta.mode() & 0o022 != 0 {
        return Err("Gateway executable permissions are unsafe for systemd service use".into());
    }
    Ok(canonical)
}

fn render_veyl(
    executable: &Path,
    listen: Option<SocketAddrV4>,
    funnel_socket: Option<&Path>,
) -> Result<String, String> {
    let exe_quoted = quote(executable)?;
    let mut exec = format!("{exe_quoted} serve");
    if let Some(addr) = listen {
        if *addr.ip() != Ipv4Addr::LOCALHOST {
            return Err("Service listener must bind to 127.0.0.1".into());
        }
        exec.push_str(&format!(" --listen {addr}"));
    }
    if let Some(sock) = funnel_socket {
        let sock_quoted = quote(sock)?;
        exec.push_str(&format!(" --funnel-socket {sock_quoted}"));
    }
    Ok(format!(
        "[Unit]\nDescription=Veyl unified MCP gateway\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n\
         [Service]\nType=simple\nExecStart={exec}\n\
         Restart=on-failure\nRestartSec=2s\nTimeoutStopSec=20s\nKillMode=process\n\
         MemoryMax=512M\nTasksMax=128\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=full\n\
         UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH RUST_LOG\nStandardOutput=journal\nStandardError=journal\n\n\
         [Install]\nWantedBy=default.target\n"
    ))
}

fn unit_is_owned_veyl(path: &Path, executable: &Path) -> io::Result<bool> {
    let directory = match open_operator_dir(path.parent().ok_or_else(|| io::Error::other("bad unit parent"))?) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    checked(&directory)?;
    let handle = match fs::openat(
        &directory,
        UNIT_VEYL,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(h) => h,
        Err(Errno::NOENT) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let meta = fs::fstat(&handle)?;
    if FileType::from_raw_mode(meta.st_mode) != FileType::RegularFile
        || meta.st_uid != rustix::process::geteuid().as_raw()
        || meta.st_mode & 0o7777 != 0o600
        || meta.st_nlink != 1
    {
        return Err(io::Error::other("unit permissions/ownership invalid"));
    }
    let mut content = String::new();
    File::from(reopen_regular(handle, OFlags::RDONLY)?)
        .take(4097)
        .read_to_string(&mut content)?;
    let exe_q = quote(executable).map_err(io::Error::other)?;
    let Some(exec_line) = content.lines().find(|l| l.starts_with("ExecStart=")) else {
        return Err(io::Error::other("unit does not match generated veyl.service"));
    };
    let cmd = exec_line.trim_start_matches("ExecStart=");
    if !cmd.starts_with(&format!("{exe_q} serve")) {
        return Err(io::Error::other("unit ExecStart does not match verified veyl serve"));
    }
    // Check optional --listen / --funnel-socket args and match exact template.
    let tail = cmd[format!("{exe_q} serve").len()..].trim();
    let mut listen = None;
    let mut socket = None;
    let parts: Vec<&str> = if tail.is_empty() {
        Vec::new()
    } else {
        tail.split_whitespace().collect()
    };
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "--listen" if i + 1 < parts.len() && listen.is_none() => {
                listen = parts[i + 1].parse::<SocketAddrV4>().ok();
                if listen.is_none() {
                    return Err(io::Error::other("unit ExecStart has invalid listener"));
                }
                i += 2;
            }
            "--funnel-socket" if i + 1 < parts.len() && socket.is_none() => {
                let raw = parts[i + 1].trim_matches('"');
                socket = Some(PathBuf::from(raw));
                i += 2;
            }
            _ => return Err(io::Error::other("unit ExecStart contains unexpected arguments")),
        }
    }
    let expected = render_veyl(executable, listen, socket.as_deref()).map_err(io::Error::other)?;
    if content != expected {
        return Err(io::Error::other("unit does not match generated veyl.service"));
    }
    Ok(true)
}

pub(crate) fn install_and_start_unified(
    home: &Path,
    enable_now: bool,
    listen: Option<SocketAddrV4>,
    funnel_socket: Option<&Path>,
) -> Result<(), String> {
    if rustix::process::geteuid().is_root() {
        return Err("Service installation requires the unprivileged gateway owner".into());
    }
    if legacy_unit_is_active(home)? {
        return Err(
            "Legacy mcp-gateway.service is active; stop and disable it before starting veyl.service (preserved until you transition)"
                .into(),
        );
    }
    crate::unified::ensure_reconciled(home)?;
    let cfg = crate::unified::config_path(home);
    if !cfg.exists() {
        return Err("No unified policy found (~/.local/state/veyl/clients.json); run 'veyl up' first".into());
    }
    let policy = PolicyFile::lock(&cfg, false)?;
    verify_approvals(&policy.snapshot()?)?;
    drop(policy);

    let executable = verified_current_exe()?;
    let unit = render_veyl(&executable, listen, funnel_socket)?;
    let target = home.join(".config/systemd/user").join(UNIT_VEYL);
    let dir = unit_directory(home).map_err(|e| format!("User unit directory unavailable: {e}"))?;
    if !owned_unit_named(&target, UNIT_VEYL, unit.as_bytes(), false).is_ok_and(|f| f) {
        if target.symlink_metadata().is_ok() {
            return Err("Existing veyl.service does not match generated configuration; refusing overwrite".into());
        }
        publish_new(&dir, OsStr::new(UNIT_VEYL), unit.as_bytes())
            .map_err(|e| format!("User unit was not installed: {e}"))?;
        println!("SERVICE_UNIT=WRITTEN destination={}", target.display());
    } else {
        println!("SERVICE_UNIT=UNCHANGED destination={}", target.display());
    }
    manager(&["daemon-reload"])?;
    if enable_now {
        if crate::unified::is_serve_live(home).unwrap_or(false) && !veyl_unit_is_active(home)? {
            return Err("Foreground veyl serve is already running; stop it before starting veyl.service".into());
        }
        manager(&["enable", "--now", UNIT_VEYL])?;
        let state = query_unit_named(UNIT_VEYL)?;
        println!(
            "ActiveState={} UnitFileState={}",
            state["ActiveState"].as_str().unwrap_or_default(),
            state["UnitFileState"].as_str().unwrap_or_default()
        );
    } else {
        println!("Installed {}. Opt-in activation: run 'veyl service enable --now' or 'systemctl --user enable --now {}'.", UNIT_VEYL, UNIT_VEYL);
        println!("Optional: run 'loginctl enable-linger' separately if you want {} to stay active after logout.", UNIT_VEYL);
    }
    Ok(())
}

fn run_unified(args: &[OsString]) -> Result<(), String> {
    let action = args.first().and_then(|a| a.to_str()).ok_or(HELP)?;
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| valid_path(path))
        .ok_or("HOME must be an absolute directory")?;
    let target = home.join(".config/systemd/user").join(UNIT_VEYL);

    let mut dry_run = false;
    let mut enable_now = false;
    let mut now_flag = false;
    let mut enable_flag = false;
    let mut listen: Option<SocketAddrV4> = None;
    let mut funnel_socket: Option<PathBuf> = None;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.to_str() {
            Some("--dry-run") => dry_run = true,
            Some("--confirm" | "--yes") => {}
            Some("--enable-now") => enable_now = true,
            Some("--enable") => enable_flag = true,
            Some("--now") => now_flag = true,
            Some("--listen") if listen.is_none() => {
                let raw = rest.next().and_then(|v| v.to_str()).ok_or(HELP)?;
                listen = Some(raw.parse::<SocketAddrV4>().map_err(|_| "Expected 127.0.0.1:PORT")?);
            }
            Some("--funnel-socket") if funnel_socket.is_none() => {
                funnel_socket = Some(PathBuf::from(rest.next().ok_or(HELP)?));
            }
            _ => return Err(HELP.into()),
        }
    }
    if enable_flag && now_flag {
        enable_now = true;
    }

    match action {
        "status" | "diagnostics" => {
            let present = match target.symlink_metadata() {
                Ok(m) if m.is_file() => "present",
                Ok(_) => "unexpected-file-type",
                Err(e) if e.kind() == io::ErrorKind::NotFound => "missing",
                Err(_) => return Err("Cannot inspect user unit path".into()),
            };
            println!("unit={} unit_file={present} destination={}", UNIT_VEYL, target.display());
            if present != "missing" {
                let fields = query_unit_named(UNIT_VEYL)?;
                for key in ["LoadState", "ActiveState", "SubState", "UnitFileState"] {
                    println!("{key}={}", fields[key].as_str().unwrap_or_default());
                }
            }
            if action == "diagnostics" {
                let veyl_health = query_unit_named(UNIT_VEYL).unwrap_or_else(|_| json!({"LoadState":"unavailable"}));
                let legacy_health = query_unit_named(UNIT).unwrap_or_else(|_| json!({"LoadState":"unavailable"}));
                println!("{}", serde_json::to_string_pretty(&json!({"veyl": veyl_health, "legacy": legacy_health})).unwrap());
            }
            Ok(())
        }
        "print-unit" => {
            let exe = verified_current_exe()?;
            let unit = render_veyl(&exe, listen, funnel_socket.as_deref())?;
            print!("{unit}");
            Ok(())
        }
        "validate" => {
            crate::unified::ensure_reconciled(&home)?;
            let cfg = crate::unified::config_path(&home);
            verify_approvals(&PolicyFile::preview(&cfg)?)?;
            println!("Configuration valid for unified state ({})", cfg.display());
            Ok(())
        }
        "install" => {
            if dry_run {
                println!(
                    "SERVICE_PLAN unit={} destination={} enable_now={}",
                    UNIT_VEYL,
                    target.display(),
                    enable_now
                );
                return Ok(());
            }
            install_and_start_unified(&home, enable_now, listen, funnel_socket.as_deref())
        }
        "uninstall" => {
            if dry_run {
                println!(
                    "SERVICE_PLAN action=uninstall unit={} destination={} data=preserved",
                    UNIT_VEYL,
                    target.display()
                );
                return Ok(());
            }
            if rustix::process::geteuid().is_root() {
                return Err("Service uninstallation requires the unprivileged gateway owner".into());
            }
            let exe = verified_current_exe()?;
            match unit_is_owned_veyl(&target, &exe) {
                Ok(false) => {
                    println!("SERVICE_UNIT=ABSENT destination={} data=preserved", target.display());
                    return Ok(());
                }
                Ok(true) => {}
                Err(e) => return Err(format!("User unit was not removed: {e}")),
            }
            let _ = manager(&["stop", UNIT_VEYL]);
            let _ = manager(&["disable", UNIT_VEYL]);
            let dir = open_operator_dir(target.parent().ok_or("Missing systemd unit dir")?)
                .map_err(|_| "User unit directory unavailable")?;
            fs::unlinkat(&dir, UNIT_VEYL, AtFlags::empty())
                .and_then(|()| fs::fsync(&dir))
                .map_err(|_| "Failed removing veyl.service")?;
            let _ = manager(&["daemon-reload"]);
            println!("SERVICE_UNIT=REMOVED destination={} data=preserved", target.display());
            Ok(())
        }
        "enable" | "disable" | "start" | "stop" | "restart" => {
            let exe = verified_current_exe()?;
            if !unit_is_owned_veyl(&target, &exe).unwrap_or(false) {
                return Err("Install owned veyl.service first (run 'veyl service install')".into());
            }
            if matches!(action, "enable" | "start" | "restart") && legacy_unit_is_active(&home)? {
                return Err(
                    "Legacy mcp-gateway.service is active; stop and disable it before starting veyl.service"
                        .into(),
                );
            }
            if action == "enable" && (now_flag || enable_now) {
                manager(&["enable", "--now", UNIT_VEYL])?;
            } else {
                manager(&[action, UNIT_VEYL])?;
            }
            let fields = query_unit_named(UNIT_VEYL)?;
            for key in ["LoadState", "ActiveState", "SubState", "UnitFileState"] {
                println!("{key}={}", fields[key].as_str().unwrap_or_default());
            }
            Ok(())
        }
        _ => Err(HELP.into()),
    }
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

/// Resolve only the original generated unit and its exact installed binary.
pub(crate) fn update_target(
    home: &Path,
    config: Option<&Path>,
    executables: &[PathBuf],
) -> Result<Option<(PathBuf, bool)>, String> {
    update_target_with_query(home, config, executables, false, query_unit)
}


pub(crate) fn recovery_target(
    home: &Path,
    config: Option<&Path>,
    executables: &[PathBuf],
) -> Result<Option<(PathBuf, bool)>, String> {
    update_target_with_query(home, config, executables, true, query_unit)
}

fn update_target_with_query(
    home: &Path,
    config: Option<&Path>,
    executables: &[PathBuf],
    allow_failed: bool,
    query: impl FnOnce() -> Result<Value, String>,
) -> Result<Option<(PathBuf, bool)>, String> {
    let target = home.join(".config/systemd/user").join(UNIT);
    let unit_exists = match target.symlink_metadata() {
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(_) => return Err("Cannot inspect user unit path".into()),
    };
    let listener = "127.0.0.1:7331".parse::<SocketAddrV4>().unwrap();
    let state = match query() {
        Ok(state) => state,
        Err(e) if unit_exists => {
            return Err(format!("Cannot safely inspect managed Veyl unit: {e}"));
        }
        Err(_) => {
            if std::net::TcpStream::connect_timeout(&listener.into(), Duration::from_millis(200))
                .is_ok()
            {
                return Err("Stop the foreground Veyl instance before updating".into());
            }
            return Ok(None);
        }
    };
    if state["LoadState"] == "not-found" {
        if std::net::TcpStream::connect_timeout(&listener.into(), Duration::from_millis(200))
            .is_ok()
        {
            return Err("Stop the foreground Veyl instance before updating".into());
        }
        return Ok(None);
    }
    let config = config.ok_or("Existing service needs a recognized configuration")?;
    if !unit_matches(&state, &target) {
        return Err("Refusing to update an overridden or unknown service".into());
    }
    let executable = executables
        .iter()
        .find(|exe| {
            render(exe, config, listener)
                .is_ok_and(|unit| owned_unit(&target, unit.as_bytes(), false).unwrap_or(false))
        })
        .ok_or("Service is not the standard generated Veyl unit; update manually")?;
    match state["ActiveState"].as_str() {
        Some("failed") if allow_failed => Ok(Some((executable.clone(), false))),
        Some("inactive") => {
            if std::net::TcpStream::connect_timeout(&listener.into(), Duration::from_millis(200))
                .is_ok()
            {
                return Err("Stop the foreground Veyl instance before updating".into());
            }
            Ok(Some((executable.clone(), false)))
        }
        Some("active") if running_binary(&state, executable) => {
            Ok(Some((executable.clone(), true)))
        }
        _ => Err(
            "Service is not idle or its running executable does not match the installed file"
                .into(),
        ),
    }
}

fn running_binary(state: &Value, executable: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(pid) = state["MainPID"]
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&pid| pid > 1)
    else {
        return false;
    };
    std::fs::metadata(format!("/proc/{pid}/exe"))
        .ok()
        .zip(std::fs::metadata(executable).ok())
        .is_some_and(|(running, installed)| {
            (running.dev(), running.ino()) == (installed.dev(), installed.ino())
        })
}

pub(crate) fn update_stop() -> Result<(), String> {
    manager(&["stop", UNIT])?;
    let state = query_unit()?;
    // A failed unit may retain ActiveState=failed after a successful stop.
    // Rollback may proceed only when systemd confirms no main process.
    if !matches!(state["ActiveState"].as_str(), Some("inactive" | "failed"))
        || state["MainPID"] != "0"
    {
        return Err("Veyl service did not stop; refusing binary replacement".into());
    }
    if state["ActiveState"] == "failed" {
        // Clear start-limit-hit before rollback restarts the restored binary.
        let _ = manager(&["reset-failed", UNIT]);
    }
    Ok(())
}

pub(crate) fn update_start(executable: &Path) -> Result<(), String> {
    manager(&["start", UNIT])?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let listener = "127.0.0.1:7331".parse().unwrap();
    while std::time::Instant::now() < deadline {
        let state = query_unit()?;
        if state["ActiveState"] == "active"
            && running_binary(&state, executable)
            && std::net::TcpStream::connect_timeout(&listener, Duration::from_millis(200)).is_ok()
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err("Updated Veyl service did not become ready".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_manager_refuses_existing_unit() {
        let home = std::env::temp_dir().join(format!(
            "veyl-service-{}",
            crate::http::operator::revision().unwrap()
        ));
        let unit = home.join(".config/systemd/user").join(UNIT);
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(&unit, b"unit").unwrap();
        let result =
            update_target_with_query(&home, None, &[], false, || Err("manager unavailable".into()));
        assert!(
            result
                .unwrap_err()
                .contains("Cannot safely inspect managed Veyl unit")
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn unavailable_manager_without_unit_checks_listener() {
        let home = std::env::temp_dir().join(format!(
            "veyl-service-{}",
            crate::http::operator::revision().unwrap()
        ));
        let result =
            update_target_with_query(&home, None, &[], false, || Err("manager unavailable".into()));
        if std::net::TcpStream::connect_timeout(
            &"127.0.0.1:7331".parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            assert!(
                result
                    .unwrap_err()
                    .contains("Stop the foreground Veyl instance")
            );
        } else {
            assert_eq!(result.unwrap(), None);
        }
    }

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
