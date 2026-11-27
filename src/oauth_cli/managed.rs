//! Managed foreground direct OAuth lifecycle. The low-level scoped
//! onboarding code remains the authority for permission and tunnel checks.
use super::onboarding;
use mcp_gateway::{core::oauth::ConnectionMode, http_common::oauth_http};
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, FlockOperation, Mode, OFlags},
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    io::{self, BufRead, BufReader, IsTerminal, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const LOGIN_HELP: &str = "Usage: veyl login [--root DIR] [--yes] [--no-ui]\nCreate or resume one private OAuth profile over a foreground Tailscale Funnel (Standard read-only default; per-connection YOLO selectable locally during approval). Requires tailscaled running with MagicDNS, HTTPS certificates, and Tailscale Funnel ACL permission on port 8443 or 10000. Ctrl-C stops the route without revoking access. Use veyl logout to revoke.";
const LOGOUT_HELP: &str = "Usage: veyl logout [--client ID | --all] [--yes]\nRevoke one remote OAuth connection (--client ID) or explicitly revoke all connections in the managed OAuth profile and stop its foreground route (--all). Workspace, profile and audit are retained; existing native clients are unaffected.";

fn confirm(message: &str, yes: bool) -> Result<(), String> {
    if yes {
        return Ok(());
    }
    eprint!("{message} [y/N] ");
    io::stderr()
        .flush()
        .map_err(|_| "Cannot display confirmation")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| "Cannot read confirmation")?;
    if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        return Err("Cancelled; no public route or grants changed".into());
    }
    Ok(())
}

fn select_workspace(default: PathBuf, base: &Path) -> Result<PathBuf, String> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(default);
    }
    loop {
        eprintln!("Workspace directory [default: {}]:", default.display());
        eprint!("Path (Enter for default): ");
        io::stderr()
            .flush()
            .map_err(|_| "Cannot display workspace prompt")?;
        let mut line = String::new();
        if io::stdin()
            .read_line(&mut line)
            .map_err(|_| "Cannot read workspace selection")?
            == 0
        {
            return Ok(default);
        }
        let chosen = line.trim();
        let candidate = if chosen.is_empty() {
            default.clone()
        } else {
            let path = PathBuf::from(chosen);
            if !path.is_absolute() {
                eprintln!("Use an absolute directory path.");
                continue;
            }
            path
        };
        let Ok(canonical) = candidate.canonicalize() else {
            eprintln!("Directory unavailable: {}", candidate.display());
            continue;
        };
        if canonical.starts_with(base) || base.starts_with(&canonical) || !canonical.is_dir() {
            eprintln!("Choose an existing directory separate from ~/.veyl-login.");
            continue;
        }
        return Ok(canonical);
    }
}

fn validate_control_socket(control_path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(control_path).map_err(|_| {
        "Managed gateway starting or stopping; retry after it settles".to_owned()
    })?;
    if !meta.file_type().is_socket()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o777 != 0o600
    {
        return Err("Unsafe managed control socket".into());
    }
    Ok(())
}

fn send_control_command(control_path: &Path, payload: &Value) -> Result<(u16, Value), String> {
    validate_control_socket(control_path)?;
    let mut stream = UnixStream::connect(control_path)
        .map_err(|_| "Cannot reach managed gateway control socket".to_owned())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let line = format!("{payload}\n");
    stream
        .write_all(line.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|_| "Cannot write control command".to_owned())?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|_| "No reply from managed gateway".to_owned())?;
    let parsed: Value =
        serde_json::from_str(reply.trim()).map_err(|_| "Invalid gateway control reply")?;
    let status = parsed["status"]
        .as_u64()
        .and_then(|s| u16::try_from(s).ok())
        .ok_or("Missing status in control reply")?;
    Ok((status, parsed["body"].clone()))
}

fn is_live(dir: &OwnedFd) -> Result<bool, String> {
    match fs::flock(dir, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            let _ = fs::flock(dir, FlockOperation::Unlock);
            Ok(false)
        }
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(true),
        Err(_) => Err("Managed gateway lock unavailable".into()),
    }
}

fn fetch_registrations(base: &Path, profile: &Path, dir: &OwnedFd) -> Result<(bool, Vec<Value>, bool), String> {
    let control_path = base.join("control.sock");
    if is_live(dir)? {
        let (status, body) = send_control_command(&control_path, &json!({"action": "list"}))?;
        if status != 200 {
            return Err("Cannot inspect live OAuth registrations".into());
        }
        let regs = body["registrations"]
            .as_array()
            .cloned()
            .ok_or("Invalid registration list")?;
        let supports_yolo = body["supports_yolo"].as_bool().unwrap_or(false);
        return Ok((true, regs, supports_yolo));
    }
    let state = oauth_http::inspect_stopped_state(&profile.join("oauth"))?;
    let regs = state["registrations"]
        .as_array()
        .cloned()
        .ok_or("Invalid registration list")?;
    let config_path = profile.join("clients.json");
    let supports_yolo = crate::http::operator::PolicyFile::lock(&config_path, false)
        .and_then(|policy| policy.snapshot())
        .ok()
        .filter(|settings| settings.managed && settings.jobs.is_some())
        .is_some();
    Ok((false, regs, supports_yolo))
}

pub(crate) fn managed_exists() -> Result<bool, String> {
    let base = base_path()?;
    exists(&base.join("profile"))
}

pub(crate) fn managed_list() -> Result<(bool, Vec<Value>, bool), String> {
    let base = base_path()?;
    let profile = base.join("profile");
    if !exists(&profile)? {
        return Err("No managed OAuth login profile".into());
    }
    let dir = open_base(&base, false)?;
    let _operation = operation_lock(&dir)?;
    onboarding::private_directory(&profile, true)?;
    fetch_registrations(&base, &profile, &dir)
}

pub(crate) struct ModeChange {
    pub client_id: String,
    pub previous: ConnectionMode,
    pub reauth_required: bool,
}

pub(crate) fn managed_set_mode(
    client_id: Option<&str>,
    all: bool,
    target: ConnectionMode,
) -> Result<(Vec<ModeChange>, bool), String> {
    let base = base_path()?;
    let profile = base.join("profile");
    if !exists(&profile)? {
        return Err("No managed OAuth login profile".into());
    }
    let dir = open_base(&base, false)?;
    let _operation = operation_lock(&dir)?;
    onboarding::private_directory(&profile, true)?;
    let (live, regs, supports_yolo) = fetch_registrations(&base, &profile, &dir)?;
    if target == ConnectionMode::Yolo && !supports_yolo {
        return Err("Native YOLO requires a managed profile with a private job store".into());
    }
    let ids: Vec<String> = if all {
        if regs.is_empty() {
            return Err("No registered OAuth clients in managed profile".into());
        }
        regs.iter()
            .filter_map(|r| r["client_id"].as_str().map(str::to_owned))
            .collect()
    } else if let Some(id) = client_id {
        if !regs.iter().any(|r| r["client_id"].as_str() == Some(id)) {
            return Err(format!("Unknown OAuth client: {id}"));
        }
        vec![id.to_owned()]
    } else if regs.len() == 1 {
        vec![regs[0]["client_id"].as_str().ok_or("Missing client_id")?.to_owned()]
    } else if regs.is_empty() {
        return Err("No registered OAuth clients in managed profile".into());
    } else if io::stdin().is_terminal() && io::stderr().is_terminal() {
        let mut stderr = io::stderr().lock();
        for (idx, reg) in regs.iter().enumerate() {
            writeln!(
                stderr,
                "{}: {} ({}, mode={})",
                idx + 1,
                reg["client_id"].as_str().unwrap_or("?"),
                reg["client_name"].as_str().unwrap_or("Unnamed"),
                reg["mode"].as_str().unwrap_or("standard")
            )
            .map_err(|e| e.to_string())?;
        }
        write!(stderr, "Select client (blank cancels): ").map_err(|e| e.to_string())?;
        stderr.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
        let idx = line
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .ok_or("No client selected")?;
        let picked = regs
            .get(idx)
            .and_then(|r| r["client_id"].as_str())
            .ok_or("Invalid client selection")?;
        vec![picked.to_owned()]
    } else {
        return Err(
            "Multiple OAuth clients connected; run veyl mode to list them, then supply a client ID"
                .into(),
        );
    };
    let mut results = Vec::with_capacity(ids.len());
    let control_path = base.join("control.sock");
    for id in ids {
        if live {
            let (status, body) = send_control_command(
                &control_path,
                &json!({"action": "mode", "client_id": id, "mode": target.as_str(), "confirm": true}),
            )?;
            if status != 200 {
                let err = body["error"].as_str().unwrap_or("mode switch rejected");
                return Err(format!("Failed to switch {id}: {err}"));
            }
            let prev = body["previous_mode"]
                .as_str()
                .and_then(ConnectionMode::parse)
                .unwrap_or(ConnectionMode::Standard);
            let reauth = body["reauthorization_required"].as_bool().unwrap_or(false);
            results.push(ModeChange {
                client_id: id,
                previous: prev,
                reauth_required: reauth,
            });
        } else {
            let (prev, reauth) = oauth_http::switch_stopped_client_mode(
                &profile.join("oauth"),
                "oauth-preview",
                &id,
                target,
            )?;
            results.push(ModeChange {
                client_id: id,
                previous: prev,
                reauth_required: reauth,
            });
        }
    }
    Ok((results, live))
}

fn base_path() -> Result<PathBuf, String> {
    if rustix::process::geteuid().is_root() {
        return Err("Use your normal user, not root".into());
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or("HOME must be absolute")?;
    onboarding::private_directory(&home, false)?;
    if home.canonicalize().map_err(|_| "HOME unavailable")? != home {
        return Err("HOME must be canonical".into());
    }
    Ok(home.join(crate::protected_paths::MANAGED_LOGIN_DIR))
}

fn exists(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("Cannot inspect managed profile".into()),
    }
}

fn open_base(base: &Path, create: bool) -> Result<OwnedFd, String> {
    if create && !exists(base)? {
        let parent = onboarding::private_directory(base.parent().ok_or("Missing HOME")?, false)?;
        match fs::mkdirat(&parent, crate::protected_paths::MANAGED_LOGIN_DIR, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err("Cannot initialize managed directory".into()),
        }
        fs::fsync(&parent).map_err(|_| "Cannot sync HOME")?;
    }
    onboarding::private_directory(base, true)
}

fn operation_lock(dir: &OwnedFd) -> Result<OwnedFd, String> {
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let name = ".operation-lock";
    let file = match fs::openat(
        dir,
        name,
        flags | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => {
            fs::fchmod(&fd, Mode::from_raw_mode(0o600))
                .map_err(|_| "Cannot secure operation lock")?;
            fd
        }
        Err(rustix::io::Errno::EXIST) => {
            fs::openat(dir, name, flags, Mode::empty()).map_err(|_| "Unsafe operation lock")?
        }
        Err(_) => return Err("Cannot create operation lock".into()),
    };
    let st = fs::fstat(&file).map_err(|_| "Cannot inspect operation lock")?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || st.st_uid != rustix::process::geteuid().as_raw()
        || st.st_nlink != 1
        || st.st_mode & 0o7777 != 0o600
    {
        return Err("Unsafe operation lock".into());
    }
    fs::flock(&file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| "Another login/logout operation is in progress")?;
    let current = fs::statat(dir, name, fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "Operation lock missing")?;
    if (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino) {
        return Err("Operation lock replaced".into());
    }
    Ok(file)
}

fn lifecycle_lock(dir: &OwnedFd) -> Result<bool, String> {
    match fs::flock(dir, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(false),
        Err(_) => Err("Managed gateway lock unavailable".into()),
    }
}

fn remove_socket(path: &Path) -> Result<(), String> {
    if !exists(path)? {
        return Ok(());
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| "Cannot inspect control socket")?;
    if !meta.file_type().is_socket() || meta.uid() != rustix::process::geteuid().as_raw() {
        return Err("Unsafe managed control socket; not removed".into());
    }
    std::fs::remove_file(path).map_err(|_| "Cannot remove managed control socket".into())
}

struct SocketCleanup(PathBuf);
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = remove_socket(&self.0);
    }
}

fn logout_pending(dir: &OwnedFd) -> Result<(), String> {
    let name = ".logout-pending";
    let flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    match fs::openat(
        dir,
        name,
        flags | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => {
            fs::fchmod(&fd, Mode::from_raw_mode(0o600))
                .map_err(|_| "Cannot secure logout intent")?;
            fs::fsync(&fd)
                .and_then(|_| fs::fsync(dir))
                .map_err(|_| "Cannot persist logout intent")?;
        }
        Err(rustix::io::Errno::EXIST) => {
            let st = fs::statat(dir, name, fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| "Logout intent unavailable")?;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
                || st.st_uid != rustix::process::geteuid().as_raw()
                || st.st_nlink != 1
                || st.st_mode & 0o7777 != 0o600
                || st.st_size != 0
            {
                return Err("Unsafe logout intent".into());
            }
        }
        Err(_) => return Err("Cannot publish logout intent".into()),
    }
    Ok(())
}

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    let Some(action) = args.first() else {
        return Err(LOGIN_HELP.into());
    };
    let login = action == "login";
    let help = if login { LOGIN_HELP } else { LOGOUT_HELP };
    if args.len() == 2 && args[1] == "--help" {
        println!("{help}");
        return Ok(());
    }
    let mut yes = false;
    let mut no_ui = false;
    let mut root = None;
    let mut socket = None;
    let mut client = None;
    let mut all = false;
    let mut options = args[1..].iter();
    while let Some(arg) = options.next() {
        match arg.to_str() {
            Some("--yes") if !yes => yes = true,
            Some("--no-ui") if login && !no_ui => no_ui = true,
            Some("--root") if login && root.is_none() => {
                root = Some(PathBuf::from(options.next().ok_or(help)?))
            }
            Some("--funnel-socket") if login && socket.is_none() => {
                socket = Some(options.next().ok_or(help)?.clone())
            }
            Some("--client") if !login && client.is_none() && !all => {
                let value = options.next().and_then(|v| v.to_str()).filter(|s| !s.is_empty()).ok_or(help)?;
                client = Some(value.to_owned());
            }
            Some("--all") if !login && !all && client.is_none() => all = true,
            _ => return Err(help.into()),
        }
    }
    let base = base_path()?;
    let profile = base.join("profile");
    let control_path = base.join("control.sock");
    if login {
        let initialize = !exists(&profile)?;
        if !initialize && root.is_some() {
            return Err(
                "Managed profile already exists; login resumes its exact saved workspace".into(),
            );
        }
        let workspace = if initialize {
            let chosen = match root {
                Some(explicit) => explicit,
                None => select_workspace(
                    std::env::current_dir().map_err(|_| "Cannot determine workspace")?,
                    &base,
                )?,
            };
            let chosen = chosen.canonicalize().map_err(|_| "Workspace unavailable")?;
            if chosen.starts_with(&base) || base.starts_with(&chosen) || !chosen.is_dir() {
                return Err(
                    "Choose an existing workspace separate from the managed profile".into(),
                );
            }
            confirm(
                &format!(
                    "Expose a Standard read-only OAuth MCP endpoint for {} through Tailscale Funnel? (Per-connection YOLO can be selected during local approval.)",
                    chosen.display()
                ),
                yes,
            )?;
            Some(chosen)
        } else {
            None
        };
        let dir = open_base(&base, true)?;
        let operation = operation_lock(&dir)?;
        if exists(&base.join(".logout-pending"))? {
            return Err(
                "Logout was interrupted; run veyl logout to complete revocation first".into(),
            );
        }
        if !lifecycle_lock(&dir)? {
            return Err("Managed Veyl login is already running".into());
        }
        // Recheck after acquiring the locks; concurrent login must not create
        // a second profile or silently resume another root.
        if initialize == exists(&profile)? {
            return Err("Managed profile changed; inspect before retrying login".into());
        }
        remove_socket(&control_path)?;
        let control =
            UnixListener::bind(&control_path).map_err(|_| "Cannot bind private logout socket")?;
        let _cleanup = SocketCleanup(control_path.clone());
        std::fs::set_permissions(&control_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "Cannot secure logout socket")?;
        control
            .set_nonblocking(true)
            .map_err(|_| "Cannot configure logout socket")?;
        let mut low = vec![
            OsString::from(if initialize { "setup" } else { "run" }),
            "--profile".into(),
            profile.into_os_string(),
            "--funnel".into(),
            "--managed-login".into(),
        ];
        if let Some(root) = workspace {
            low.extend(["--root".into(), root.into_os_string()]);
        }
        if !no_ui {
            low.push("--open-ui".into());
        }
        if let Some(socket) = socket {
            low.extend(["--funnel-socket".into(), socket]);
        }
        drop(operation);
        // The directory lifetime lock remains held through listener shutdown.
        let result = onboarding::run_with_control(&low, Some(control));
        drop(_cleanup);
        drop(dir);
        result
    } else {
        if !exists(&profile)? {
            return Err("No managed OAuth login profile".into());
        }
        let dir = open_base(&base, false)?;
        let _operation = operation_lock(&dir)?;
        onboarding::private_directory(&profile, true)?;
        enum LogoutTarget {
            Single(String),
            All,
        }
        let target = if all {
            LogoutTarget::All
        } else if let Some(id) = client {
            LogoutTarget::Single(id)
        } else if exists(&base.join(".logout-pending"))? {
            LogoutTarget::All
        } else {
            let (_live, regs, _yolo) = fetch_registrations(&base, &profile, &dir)?;
            if regs.len() <= 1 {
                LogoutTarget::All
            } else if !yes && io::stdin().is_terminal() && io::stderr().is_terminal() {
                let mut stderr = io::stderr().lock();
                for (idx, reg) in regs.iter().enumerate() {
                    writeln!(
                        stderr,
                        "{}: {} ({}, mode={})",
                        idx + 1,
                        reg["client_id"].as_str().unwrap_or("?"),
                        reg["client_name"].as_str().unwrap_or("Unnamed"),
                        reg["mode"].as_str().unwrap_or("standard")
                    )
                    .map_err(|e| e.to_string())?;
                }
                writeln!(stderr, "all: Revoke every connection and stop the managed route")
                    .map_err(|e| e.to_string())?;
                write!(stderr, "Select connection to log out: ").map_err(|e| e.to_string())?;
                stderr.flush().map_err(|e| e.to_string())?;
                let mut line = String::new();
                io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
                let trimmed = line.trim();
                if matches!(trimmed, "all" | "ALL" | "a") {
                    LogoutTarget::All
                } else {
                    let idx = trimmed
                        .parse::<usize>()
                        .ok()
                        .and_then(|n| n.checked_sub(1))
                        .ok_or("Cancelled; no grants revoked")?;
                    let picked = regs
                        .get(idx)
                        .and_then(|r| r["client_id"].as_str())
                        .ok_or("Invalid client selection")?;
                    LogoutTarget::Single(picked.to_owned())
                }
            } else {
                return Err("Multiple OAuth clients connected; specify --client ID or --all".into());
            }
        };
        match target {
            LogoutTarget::Single(id) => {
                let (live, regs, _yolo) = fetch_registrations(&base, &profile, &dir)?;
                if !regs.iter().any(|r| r["client_id"].as_str() == Some(id.as_str())) {
                    return Err(format!("Unknown OAuth client: {id}"));
                }
                confirm(
                    &format!("Revoke OAuth client {id}? Remaining connections stay active."),
                    yes,
                )?;
                if live {
                    let (status, body) = send_control_command(
                        &control_path,
                        &json!({"action": "revoke", "client_id": id, "confirm": true}),
                    )?;
                    if status != 200 || body["revoked"] != true {
                        return Err("Failed to revoke OAuth client cleanly".into());
                    }
                    println!(
                        "Logged out OAuth client {id}; remaining connections and route remain active."
                    );
                } else {
                    if !oauth_http::revoke_stopped_client(&profile.join("oauth"), "oauth-preview", &id)? {
                        return Err(format!("Unknown OAuth client: {id}"));
                    }
                    println!(
                        "Logged out OAuth client {id}; remaining registrations preserved."
                    );
                }
                Ok(())
            }
            LogoutTarget::All => {
                confirm(
                    "Revoke every connection in this managed OAuth profile and stop its route?",
                    yes,
                )?;
                logout_pending(&dir)?;
                if is_live(&dir)? {
                    validate_control_socket(&control_path)?;
                    let stream = UnixStream::connect(&control_path).map_err(|_| {
                        "Cannot request managed gateway shutdown; retry after it stops"
                    })?;
                    drop(stream);
                    let deadline = Instant::now() + Duration::from_secs(20);
                    while !lifecycle_lock(&dir)? {
                        if Instant::now() >= deadline {
                            return Err(
                                "Managed shutdown not confirmed; logout remains pending".into(),
                            );
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                }
                // No cooperating login can start until the operation lock is released.
                // The OAuth store also independently refuses any live owner.
                oauth_http::revoke_stopped_profile(&profile.join("oauth"), "oauth-preview")?;
                remove_socket(&control_path)?;
                fs::unlinkat(&dir, ".logout-pending", fs::AtFlags::empty())
                    .map_err(|_| "Revoked, but logout intent cleanup failed")?;
                fs::fsync(&dir).map_err(|_| "Revoked, but logout cleanup sync failed")?;
                println!(
                    "Logged out. Managed OAuth registrations and grants revoked; workspace and audit retained."
                );
                Ok(())
            }
        }
    }
}
