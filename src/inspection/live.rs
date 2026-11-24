//! Fixed read-only desktop/service probes, adapted from BridgeDev's
//! system-inspect.ts behavior. No caller-controlled argv or environment.
use serde_json::{Value, json};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::{path::PathBuf, process::Command, time::Duration};
static PROBE: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn runtime() -> Option<PathBuf> {
    let uid = rustix::process::geteuid().as_raw();
    let path = PathBuf::from(format!("/run/user/{uid}"));
    let meta = std::fs::symlink_metadata(&path).ok()?;
    (meta.is_dir() && meta.uid() == uid && meta.mode() & 0o077 == 0).then_some(path)
}
fn unavailable(reason: &str) -> Value {
    json!({"available":false,"reason":reason})
}
fn run(bin: &str, args: &[&str], sway: Option<&std::path::Path>) -> Result<Vec<u8>, Value> {
    let _guard = PROBE
        .try_lock()
        .map_err(|_| unavailable("Another live probe is running"))?;
    let mut command = Command::new(bin);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/");
    if let Some(dir) = runtime() {
        command.env("XDG_RUNTIME_DIR", &dir).env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/bus", dir.display()),
        );
        command.env(
            "PULSE_SERVER",
            format!("unix:{}/pulse/native", dir.display()),
        );
    }
    if let Some(socket) = sway {
        command.env("SWAYSOCK", socket);
    }
    match crate::linux_command::capture(&mut command, 65536, Duration::from_millis(2000)) {
        Ok((status, bytes)) if status.success() => Ok(bytes),
        Ok((status, _)) => {
            Err(json!({"available":false,"reason":"Probe failed","exit_code":status.code()}))
        }
        Err(e) => Err(unavailable(if e.kind() == std::io::ErrorKind::TimedOut {
            "Probe timed out"
        } else {
            "Probe unavailable or output limit exceeded"
        })),
    }
}
fn json_probe(
    bin: &str,
    args: &[&str],
    sway: Option<&std::path::Path>,
    fields: &[&str],
    limit: usize,
) -> Value {
    let bytes = match run(bin, args, sway) {
        Ok(v) => v,
        Err(v) => return v,
    };
    let Ok(Value::Array(rows)) = serde_json::from_slice::<Value>(&bytes) else {
        return unavailable("Invalid JSON response");
    };
    let items: Vec<_> = rows
        .iter()
        .take(limit)
        .map(|v| {
            let mut item = serde_json::Map::new();
            for key in fields {
                if let Some(value) = v.get(*key) {
                    item.insert((*key).into(), value.clone());
                }
            }
            Value::Object(item)
        })
        .collect();
    json!({"available":true,"items":items,"truncated":rows.len()>limit})
}
fn sway_socket() -> Option<PathBuf> {
    let dir = runtime()?;
    let uid = rustix::process::geteuid().as_raw();
    let prefix = format!("sway-ipc.{uid}.");
    let mut sockets = Vec::new();
    for entry in std::fs::read_dir(&dir).ok()?.take(256) {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(".sock"))
            .is_some_and(|s| s.parse::<u32>().is_ok())
        {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if meta.file_type().is_socket() && meta.uid() == uid {
            sockets.push(entry.path());
        }
    }
    if sockets.len() == 1 {
        sockets.pop()
    } else {
        None
    }
}
pub(super) fn sway() -> Value {
    let Some(socket) = sway_socket() else {
        return unavailable("No unique owned Sway IPC socket");
    };
    json!({"source":"swaymsg read-only IPC","workspaces":json_probe("/usr/bin/swaymsg",&["-r","-t","get_workspaces"],Some(&socket),&["name","num","focused","visible","output"],20),
        "outputs":json_probe("/usr/bin/swaymsg",&["-r","-t","get_outputs"],Some(&socket),&["name","active","current_mode","scale","transform","rect"],8)})
}
pub(super) fn audio() -> Value {
    // pactl JSON avoids parsing localized wpctl tree output; works with
    // PipeWire-Pulse or PulseAudio. No arbitrary server address.
    let Some(dir) = runtime() else {
        return unavailable("No owned user runtime directory");
    };
    let socket = dir.join("pulse/native");
    if !std::fs::symlink_metadata(&socket)
        .is_ok_and(|m| m.file_type().is_socket() && m.uid() == rustix::process::geteuid().as_raw())
    {
        return unavailable("No owned local PulseAudio-compatible socket");
    }
    json!({"source":"pactl JSON","sinks":json_probe("/usr/bin/pactl",&["--format=json","list","sinks"],None,&["index","name","description","state","mute","volume"],24),
        "sources":json_probe("/usr/bin/pactl",&["--format=json","list","sources"],None,&["index","name","description","state","mute","volume"],24)})
}
fn failed(user: bool) -> Value {
    let args = if user {
        vec!["--user", "--failed", "--no-pager", "--plain", "--no-legend"]
    } else {
        vec!["--failed", "--no-pager", "--plain", "--no-legend"]
    };
    let bytes = match run("/usr/bin/systemctl", &args, None) {
        Ok(v) => v,
        Err(v) => return v,
    };
    let text = String::from_utf8_lossy(&bytes);
    let items: Vec<_> = text
        .lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            Some(json!({"unit":f.next()?,"load":f.next()?,"active":f.next()?,"sub":f.next()?}))
        })
        .take(32)
        .collect();
    json!({"available":true,"items":items,"truncated":text.lines().count()>32})
}
pub(super) fn services() -> Value {
    json!({"veyl":crate::service_cli::health(),"user_failed":failed(true),"system_failed":failed(false)})
}
pub(super) fn bluetooth() -> Value {
    if run(
        "/usr/bin/systemctl",
        &["is-active", "bluetooth.service"],
        None,
    )
    .is_err()
    {
        return unavailable("Bluetooth service is not active");
    }
    let bytes = match run("/usr/bin/bluetoothctl", &["devices", "Connected"], None) {
        Ok(v) => v,
        Err(v) => return v,
    };
    let text = String::from_utf8_lossy(&bytes);
    // Connected device names only; omit hardware identifiers and journal contents.
    let names: Vec<_> = text
        .lines()
        .filter_map(|line| {
            line.strip_prefix("Device ")?
                .split_once(' ')
                .map(|(_, name)| name.chars().take(120).collect::<String>())
        })
        .take(24)
        .collect();
    json!({"available":true,"connected_names":names})
}
