//! Preview a loopback Serve route using an operator-provided state snapshot.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use mcp_gateway::security::linux_fs::{open_absolute_dir, reopen_regular};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use serde_json::{Map, Value, json};

use crate::http::admission::{parse_clients, read_config};
use crate::http::operator::verify_approvals;
use crate::protected_paths::validate_path;

const HELP: &str =
    "usage: veyl serve plan --config PATH [--listen 127.0.0.1:PORT] [--state-file PATH]";
const SNAPSHOT_LIMIT: u64 = 1_048_576;

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] || args == ["plan", "--help"] {
        println!("{HELP}");
        return Ok(());
    }
    // Preserve the legacy snapshot-only plan for configurations without Serve settings.
    if args.first().is_none_or(|arg| arg != "plan")
        || args.iter().any(|arg| arg == "--live")
        || args.windows(2).any(|pair| {
            pair[0] == "--config"
                && read_config(Path::new(&pair[1]))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .is_some_and(|doc| doc.get("tailscale_serve").is_some())
        })
    {
        return crate::tailnet::run(args);
    }
    let (mut config, mut snapshot, mut listen) = (None, None, None);
    let mut options = args[1..].iter();
    while let Some(option) = options.next() {
        match option.to_str() {
            Some("--config") if config.is_none() => {
                config = Some(PathBuf::from(options.next().ok_or(HELP)?));
            }
            Some("--state-file") if snapshot.is_none() => {
                snapshot = Some(PathBuf::from(options.next().ok_or(HELP)?));
            }
            Some("--listen") if listen.is_none() => {
                listen = Some(
                    options
                        .next()
                        .and_then(|value| value.to_str())
                        .ok_or(HELP)?,
                );
            }
            _ => return Err(HELP.into()),
        }
    }
    let config = config.ok_or(HELP)?;
    validate_path(&config)?;
    verify_approvals(&parse_clients(&config, &read_config(&config)?)?)?;
    let address: SocketAddrV4 = listen
        .unwrap_or("127.0.0.1:7331")
        .parse()
        .map_err(|_| "Serve requires a fixed IPv4 loopback address")?;
    if *address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err("Serve requires a fixed 127.0.0.1 port".into());
    }
    let snapshot = snapshot.as_deref().map(read_snapshot).transpose()?;
    let routes = snapshot.as_ref().and_then(|value| value.get("Web"));
    let mut web = Map::new();
    let mut collision = false;
    if let Some(routes) = routes {
        for (destination, route) in routes.as_object().ok_or("Invalid Web state")? {
            let paths = route
                .get("Handlers")
                .and_then(Value::as_object)
                .ok_or("Invalid Web handler state")?;
            collision |= paths.contains_key("/mcp");
            web.insert(
                destination.to_owned(),
                json!(paths.keys().collect::<Vec<_>>()),
            );
        }
    }
    let tcp: Vec<_> = match snapshot.as_ref().and_then(|value| value.get("TCP")) {
        Some(ports) => ports
            .as_object()
            .ok_or("Invalid TCP state")?
            .keys()
            .collect(),
        None => Vec::new(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "action": "plan",
            "target": format!("http://{address}/mcp"),
            "path": "/mcp",
            "apply": false,
            "public_ingress": false,
            "preserve_existing_routes": true,
            "snapshot_reviewed": snapshot.is_some(),
            "mcp_route_already_present": collision,
            "Web": web,
            "TCP": tcp,
        }))
        .map_err(|_| "Cannot encode Serve plan")?
    );
    Ok(())
}

pub(crate) fn read_snapshot(path: &Path) -> Result<Value, String> {
    validate_path(path)?;
    let parent = open_absolute_dir(path.parent().ok_or("Invalid Serve snapshot path")?)
        .map_err(|_| "Serve snapshot directory unavailable")?;
    let handle = fs::openat2(
        parent,
        path.file_name().ok_or("Invalid Serve snapshot path")?,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| "Serve snapshot unavailable")?;
    let file =
        File::from(reopen_regular(handle, OFlags::RDONLY).map_err(|_| "Invalid Serve snapshot")?);
    let mut bytes = Vec::new();
    file.take(SNAPSHOT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read Serve snapshot")?;
    if bytes.len() as u64 > SNAPSHOT_LIMIT {
        return Err("Serve snapshot exceeds size limit".into());
    }
    let snapshot: Value = serde_json::from_slice(&bytes).map_err(|_| "Invalid Serve snapshot")?;
    if !snapshot.is_object() {
        return Err("Expected a Serve snapshot object".into());
    }
    Ok(snapshot)
}
