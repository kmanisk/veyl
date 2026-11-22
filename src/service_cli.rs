//! Systemd user-unit generation and explicit, file-only installation.

use std::env;
use std::ffi::{OsStr, OsString};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use mcp_gateway::security::linux_fs::{open_operator_dir, publish_new};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, Mode, OFlags};
use rustix::io::Errno;

use crate::http::operator::{PolicyFile, verify_approvals};

const UNIT: &str = "mcp-gateway.service";
const HELP: &str = "usage: mcp-gateway service print-unit [--config PATH] [--listen IP:PORT]\n\
                   mcp-gateway service install (--dry-run | --confirm) [--config PATH] [--listen IP:PORT]\n\
                   mcp-gateway service status";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let action = args.first().and_then(|arg| arg.to_str()).ok_or(HELP)?;
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| valid_path(path))
        .ok_or("HOME must be an absolute directory")?;
    let target = home.join(".config/systemd/user").join(UNIT);
    if action == "status" && args.len() == 1 {
        return status(&target);
    }

    let mut plan = None;
    let mut config = None;
    let mut listen = None;
    let mut args = args[1..].iter();
    while let Some(key) = args.next() {
        match key.to_str() {
            Some("--dry-run") if action == "install" && plan.is_none() => plan = Some(false),
            Some("--confirm") if action == "install" && plan.is_none() => plan = Some(true),
            Some("--config") if config.is_none() => {
                config = Some(PathBuf::from(args.next().ok_or(HELP)?))
            }
            Some("--listen") if listen.is_none() => {
                listen = Some(args.next().and_then(|value| value.to_str()).ok_or(HELP)?);
            }
            _ => return Err(HELP.into()),
        }
    }
    if !(action == "print-unit" || action == "install" && plan.is_some()) {
        return Err(HELP.into());
    }

    let config = config.unwrap_or_else(|| home.join(".config/mcp-gateway/clients.json"));
    let address: SocketAddrV4 = listen
        .unwrap_or("127.0.0.1:7331")
        .parse()
        .map_err(|_| "Expected a fixed IPv4 loopback listen address")?;
    let executable = env::current_exe().map_err(|_| "Gateway executable unavailable")?;
    let unit = render(&executable, &config, address)?;
    match plan {
        None => print!("{unit}"),
        Some(false) => {
            println!(
                "SERVICE_PLAN destination={} activation=none",
                target.display()
            );
            print!("{unit}");
        }
        Some(true) => {
            if rustix::process::geteuid().is_root() {
                return Err("Service installation requires the unprivileged gateway owner".into());
            }
            let policy = PolicyFile::lock(&config, false)?;
            verify_approvals(&policy.snapshot()?)?;
            let dir = unit_directory(&home)
                .map_err(|error| format!("User unit directory unavailable: {error}"))?;
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
         MemoryMax=512M\nTasksMax=128\nUMask=0077\nNoNewPrivileges=yes\n\
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

fn status(path: &Path) -> Result<(), String> {
    let present = match path.symlink_metadata() {
        Ok(meta) if meta.is_file() => "present",
        Ok(_) => "unexpected-file-type",
        Err(error) if error.kind() == io::ErrorKind::NotFound => "missing",
        Err(_) => return Err("Cannot inspect user unit path".into()),
    };
    println!("unit_file={present} destination={}", path.display());
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "--user",
            "--no-pager",
            "show",
            "--property=LoadState,ActiveState,SubState",
            UNIT,
        ])
        .output()
        .map_err(|_| "User systemd manager query unavailable")?;
    if !output.status.success() {
        return Err("User systemd manager query failed".into());
    }
    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
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
