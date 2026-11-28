//! Single authoritative unified state (~/.local/state/veyl), transactional
//! legacy migration/reconciliation, lifetime locking, and runtime control.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mcp_gateway::http_common::oauth_http;
use mcp_gateway::security::audit::{AuditPhase, AuditSink};
use mcp_gateway::security::durable_id::DurableObjectId;
use mcp_gateway::security::linux_fs::{open_absolute_dir, open_operator_dir, publish_new};
use rustix::fd::OwnedFd;
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::http::admission::{Configuration, parse_clients};
use crate::http::operator::{PolicyFile, parse_document, verify_approvals};

pub(crate) fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "HOME must be an absolute directory".to_owned())
}

pub(crate) fn state_root(home: &Path) -> PathBuf {
    home.join(".local/state/veyl")
}

pub(crate) fn config_path(home: &Path) -> PathBuf {
    state_root(home).join("clients.json")
}

pub(crate) fn legacy_static_config(home: &Path) -> PathBuf {
    home.join(".config/mcp-gateway/clients.json")
}

pub(crate) fn legacy_managed_profile(home: &Path) -> PathBuf {
    home.join(crate::protected_paths::MANAGED_LOGIN_DIR).join("profile")
}

pub(crate) fn control_socket_path(home: &Path) -> PathBuf {
    state_root(home).join("control.sock")
}

pub(crate) fn runtime_status_path(home: &Path) -> PathBuf {
    state_root(home).join(".runtime-status.json")
}

pub(crate) fn serve_lock_path(home: &Path) -> PathBuf {
    state_root(home).join(".serve.lock")
}

pub(crate) fn migration_pending_path(home: &Path) -> PathBuf {
    state_root(home).join(".migration-pending")
}

fn path_exists_nofollow(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(format!("Cannot inspect {}", path.display())),
    }
}

fn ensure_private_state_dir(home: &Path) -> Result<OwnedFd, String> {
    let mut parent = open_operator_dir(home).map_err(|_| "HOME must be a real directory")?;
    let uid = rustix::process::geteuid().as_raw();
    for segment in [".local", "state", "veyl"] {
        let meta = fs::fstat(&parent).map_err(|_| "Cannot inspect state parent directory")?;
        if meta.st_uid != uid || meta.st_mode & 0o022 != 0 {
            return Err("State parent directories must be owned and private".into());
        }
        match fs::mkdirat(&parent, segment, Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                fs::fsync(&parent).map_err(|_| "Cannot sync state parent directory")?;
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(format!("Cannot create {}", segment)),
        }
        parent = fs::openat(
            &parent,
            segment,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| format!("{} must be a real private directory", segment))?;
        if segment == "veyl" {
            let meta = fs::fstat(&parent).map_err(|_| "Cannot inspect Veyl state directory")?;
            if meta.st_uid != uid || meta.st_mode & 0o7777 != 0o700 {
                return Err("~/.local/state/veyl must be owned with mode 0700".into());
            }
        }
    }
    Ok(parent)
}

fn open_private_lock(dir: &OwnedFd, name: &str) -> Result<OwnedFd, String> {
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = match fs::openat(
        dir,
        name,
        flags | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => {
            fs::fchmod(&fd, Mode::from_raw_mode(0o600))
                .map_err(|_| "Cannot secure lock file")?;
            fd
        }
        Err(rustix::io::Errno::EXIST) => {
            fs::openat(dir, name, flags, Mode::empty()).map_err(|_| "Unsafe lock file")?
        }
        Err(_) => return Err(format!("Cannot open lock file {name}")),
    };
    let st = fs::fstat(&file).map_err(|_| "Cannot inspect lock file")?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || st.st_uid != rustix::process::geteuid().as_raw()
        || st.st_nlink != 1
        || st.st_mode & 0o7777 != 0o600
    {
        return Err(format!("Unsafe lock file {name}"));
    }
    Ok(file)
}

pub(crate) fn acquire_serve_lock(home: &Path) -> Result<OwnedFd, String> {
    let dir = ensure_private_state_dir(home)?;
    let lock = open_private_lock(&dir, ".serve.lock")?;
    match fs::flock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(lock),
        Err(rustix::io::Errno::WOULDBLOCK) => {
            Err("Veyl gateway is already running (lifetime lock active)".into())
        }
        Err(_) => Err("Cannot lock Veyl runtime".into()),
    }
}

pub(crate) fn is_serve_live(home: &Path) -> Result<bool, String> {
    let lock_path = serve_lock_path(home);
    if !path_exists_nofollow(&lock_path)? {
        return Ok(false);
    }
    let dir = open_operator_dir(&state_root(home)).map_err(|_| "Cannot inspect state dir")?;
    let lock = open_private_lock(&dir, ".serve.lock")?;
    match fs::flock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            let _ = fs::flock(&lock, FlockOperation::Unlock);
            Ok(false)
        }
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(true),
        Err(_) => Err("Cannot inspect Veyl runtime lock".into()),
    }
}

pub(crate) fn read_runtime_status(home: &Path) -> Result<Option<Value>, String> {
    if !is_serve_live(home)? {
        return Ok(None);
    }
    let status_path = runtime_status_path(home);
    if !path_exists_nofollow(&status_path)? {
        return Ok(None);
    }
    let meta = std::fs::symlink_metadata(&status_path)
        .map_err(|_| "Cannot inspect runtime status".to_owned())?;
    if !meta.file_type().is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o600
        || meta.len() > 16_384
    {
        return Ok(None);
    }
    let bytes = std::fs::read(&status_path).map_err(|_| "Cannot read runtime status".to_owned())?;
    Ok(serde_json::from_slice(&bytes).ok())
}

fn validate_control_socket(control_path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(control_path)
        .map_err(|_| "Gateway control socket unavailable (gateway may be starting or stopped)".to_owned())?;
    if !meta.file_type().is_socket()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o777 != 0o600
    {
        return Err("Unsafe gateway control socket".into());
    }
    Ok(())
}

pub(crate) fn bind_control_socket(home: &Path) -> Result<(UnixListener, SocketCleanup), String> {
    let control_path = control_socket_path(home);
    remove_socket(&control_path)?;
    let listener = UnixListener::bind(&control_path)
        .map_err(|_| "Cannot bind private gateway control socket")?;
    let cleanup = SocketCleanup(control_path.clone());
    std::fs::set_permissions(&control_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "Cannot secure gateway control socket")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "Cannot configure gateway control socket")?;
    Ok((listener, cleanup))
}

fn remove_socket(path: &Path) -> Result<(), String> {
    if !path_exists_nofollow(path)? {
        return Ok(());
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| "Cannot inspect control socket")?;
    if !meta.file_type().is_socket() || meta.uid() != rustix::process::geteuid().as_raw() {
        return Err("Unsafe control socket; not removed".into());
    }
    std::fs::remove_file(path).map_err(|_| "Cannot remove control socket".into())
}

pub(crate) struct SocketCleanup(PathBuf);
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = remove_socket(&self.0);
    }
}

pub(crate) fn send_control_command(home: &Path, payload: &Value) -> Result<(u16, Value), String> {
    let control_path = control_socket_path(home);
    validate_control_socket(&control_path)?;
    let mut stream = UnixStream::connect(&control_path)
        .map_err(|_| "Cannot reach gateway control socket".to_owned())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut line = serde_json::to_string(payload).map_err(|_| "Invalid control payload")?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|_| "Cannot send control command".to_owned())?;
    let reader = BufReader::new(stream);
    let mut reply = String::new();
    reader
        .take(65_536)
        .read_line(&mut reply)
        .map_err(|_| "Cannot read control response".to_owned())?;
    let parsed: Value =
        serde_json::from_str(reply.trim()).map_err(|_| "Invalid control response".to_owned())?;
    let status = parsed["status"]
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .ok_or("Invalid control status")?;
    Ok((status, parsed["body"].clone()))
}

pub(crate) fn shutdown_live_foreground(home: &Path) -> Result<bool, String> {
    if !is_serve_live(home)? {
        return Ok(false);
    }
    let control_path = control_socket_path(home);
    validate_control_socket(&control_path)?;
    let mut stream = UnixStream::connect(&control_path)
        .map_err(|_| "Cannot connect to gateway control socket for shutdown")?;
    stream
        .write_all(b"{\"action\":\"shutdown\"}\n")
        .map_err(|_| "Cannot deliver shutdown request")?;
    drop(stream);
    let deadline = Instant::now() + Duration::from_secs(20);
    while is_serve_live(home)? {
        if Instant::now() >= deadline {
            return Err("Timed out waiting for Veyl gateway shutdown".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = remove_socket(&control_path);
    Ok(true)
}

fn check_legacy_processes(home: &Path) -> Result<(), String> {
    if crate::service_cli::legacy_unit_is_active(home)? {
        return Err(
            "Legacy service mcp-gateway.service is active; run 'veyl service stop --confirm --config ~/.config/mcp-gateway/clients.json' or stop mcp-gateway.service before migrating"
                .into(),
        );
    }
    let managed_base = home.join(crate::protected_paths::MANAGED_LOGIN_DIR);
    if path_exists_nofollow(&managed_base)? && crate::oauth_cli::managed::is_live_dir(&managed_base)? {
        return Err(
            "Legacy managed OAuth gateway (~/.veyl-login) is active; stop it before migrating"
                .into(),
        );
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconcileStatus {
    FreshEmpty,
    Ready,
    Migrated,
}

fn read_verified_source_doc(path: &Path) -> Result<(Vec<u8>, Value, Configuration), String> {
    if path.canonicalize().map_err(|_| format!("Missing {}", path.display()))? != path {
        return Err(format!("Policy path {} must be canonical without symlinks", path.display()));
    }
    let policy = PolicyFile::lock(path, false)?;
    let bytes = policy.bytes()?;
    let document = parse_document(&bytes)?;
    let settings = parse_clients(path, &bytes)?;
    verify_approvals(&settings)?;
    Ok((bytes, document, settings))
}

fn compute_legacy_oauth_bindings(
    old_config_path: &Path,
    old_settings: &Configuration,
    local_client: &str,
    workspace: &Path,
) -> Result<(String, String), String> {
    let root_meta = std::fs::symlink_metadata(workspace).map_err(|_| "OAuth workspace unavailable")?;
    if !root_meta.is_dir() {
        return Err("OAuth workspace unavailable".into());
    }
    let root_fd = open_absolute_dir(workspace).map_err(|_| "OAuth workspace unavailable")?;
    let root_stat = rustix::fs::fstat(&root_fd).map_err(|_| "OAuth workspace unavailable")?;
    let durable_id = DurableObjectId::probe(&root_fd, &root_stat)
        .map_err(|_| "OAuth workspace filesystem identity unavailable")?;
    let cfg_canon = old_config_path
        .canonicalize()
        .map_err(|_| "OAuth profile path unavailable")?;
    let v2 = format!(
        "{:x}",
        Sha256::digest(
            json!([
                "veyl-native-oauth-v2",
                old_settings.digest,
                &cfg_canon,
                local_client,
                workspace,
                &durable_id
            ])
            .to_string()
            .as_bytes()
        )
    );
    let v1 = format!(
        "{:x}",
        Sha256::digest(
            json!([
                "veyl-native-oauth-v1",
                old_settings.digest,
                cfg_canon,
                local_client,
                workspace,
                root_meta.dev(),
                root_meta.ino()
            ])
            .to_string()
            .as_bytes()
        )
    );
    Ok((v2, v1))
}

// An initialized but unused legacy job store has no receipts to import.
// Its signing key belongs to that store; never replace a primary store's key.
fn empty_legacy_job_store(path: &Path) -> Result<bool, String> {
    if !path_exists_nofollow(path)? {
        return Ok(true);
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| "Cannot inspect legacy job store")?;
    let uid = rustix::process::geteuid().as_raw();
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
        return Err("Unsafe legacy job store".into());
    }
    let mut empty = true;
    for entry in std::fs::read_dir(path).map_err(|_| "Cannot read legacy job store")? {
        let entry = entry.map_err(|_| "Cannot iterate legacy job store")?;
        let expected_len = match entry.file_name().to_str() {
            Some(".lock") => 0,
            Some(".receipt-key") => 32,
            _ => {
                empty = false;
                continue;
            }
        };
        let meta = std::fs::symlink_metadata(entry.path())
            .map_err(|_| "Cannot inspect legacy job metadata")?;
        if !meta.is_file() || meta.uid() != uid || meta.nlink() != 1
            || meta.mode() & 0o7777 != 0o600 || meta.len() != expected_len
        {
            return Err("Unsafe legacy job metadata".into());
        }
    }
    Ok(empty)
}

fn copy_directory_contents_no_overwrite(
    src_dir: &Path,
    dst_dir: &Path,
    refuse_collision: bool,
) -> Result<(), String> {
    if !path_exists_nofollow(src_dir)? {
        return Ok(());
    }
    let src_meta = std::fs::symlink_metadata(src_dir).map_err(|_| "Cannot inspect source dir")?;
    if !src_meta.file_type().is_dir() || src_meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(format!("Unsafe source directory {}", src_dir.display()));
    }
    std::fs::create_dir_all(dst_dir).map_err(|_| "Cannot create destination subdir")?;
    std::fs::set_permissions(dst_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| "Cannot secure destination subdir")?;
    for entry in std::fs::read_dir(src_dir).map_err(|_| "Cannot read source dir")? {
        let entry = entry.map_err(|_| "Cannot iterate source dir")?;
        let name = entry.file_name();
        let src_item = entry.path();
        let meta = std::fs::symlink_metadata(&src_item).map_err(|_| "Cannot inspect item")?;
        if meta.file_type().is_symlink() || meta.uid() != rustix::process::geteuid().as_raw() {
            return Err(format!("Refusing symlink or untrusted entry {}", src_item.display()));
        }
        let dst_item = dst_dir.join(&name);
        if meta.file_type().is_dir() {
            copy_directory_contents_no_overwrite(&src_item, &dst_item, refuse_collision)?;
        } else if meta.file_type().is_file() {
            if dst_item.exists() {
                if refuse_collision {
                    return Err(format!(
                        "Migration collision on existing file {}; resolve manually",
                        dst_item.display()
                    ));
                }
                continue;
            }
            let bytes = std::fs::read(&src_item).map_err(|_| "Cannot read source file")?;
            std::fs::write(&dst_item, bytes).map_err(|_| "Cannot write migrated file")?;
            std::fs::set_permissions(&dst_item, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "Cannot secure migrated file")?;
        }
    }
    Ok(())
}

fn convert_client_entry_to_schema4(
    entry: &Value,
    client: &crate::http::admission::Client,
    version: Option<u64>,
) -> Result<(Value, bool), String> {
    let mut obj = entry
        .as_object()
        .ok_or("Invalid client entry")?
        .clone();
    if version == Some(4) {
        return Ok((Value::Object(obj), false));
    }
    // Preserve static IDs, token verifiers, explicit grants, disabled state, and roots
    // without silently escalating any legacy sandboxed YOLO to Native YOLO.
    let was_privileged = obj
        .get("mode")
        .and_then(Value::as_str)
        .is_some_and(|m| m != "standard" && m != "disabled");
    obj.remove("yolo_revision");
    obj.remove("native_tool_preset");
    obj.remove("yolo_roots");
    obj.remove("yolo_shared_roots");
    obj.insert("mode".into(), "standard".into());
    obj.insert("disabled".into(), client.is_disabled().into());
    if !obj.contains_key("extra_roots") {
        obj.insert("extra_roots".into(), json!([]));
    }
    Ok((Value::Object(obj), was_privileged))
}

fn build_oauth_section_from_profile(
    profile_doc: &Value,
    profile_settings: &Configuration,
    oauth_state_dir: &Path,
) -> Result<Value, String> {
    let profile_client = profile_settings
        .clients
        .first()
        .ok_or("Legacy OAuth profile is missing its scoped anchor client")?;
    let tools = &profile_client.tools;
    let workspace_edit = tools.contains(&crate::tools::registry::Tool::WriteFile);
    let workspace_tools = workspace_edit && tools.contains(&crate::tools::registry::Tool::SearchFiles);
    let workspace_jobs = profile_doc
        .get("job_profiles")
        .and_then(Value::as_object)
        .is_some_and(|m| !m.is_empty())
        && (tools.contains(&crate::tools::registry::Tool::JobStart)
            || profile_settings.clients[0].id == "oauth-preview");
    let workspace_commands =
        tools.contains(&crate::tools::registry::Tool::ExecCommand)
            && tools.contains(&crate::tools::registry::Tool::TaskRun);
    let workspace_interactive = [
        crate::tools::registry::Tool::ProcessStart,
        crate::tools::registry::Tool::ProcessInput,
        crate::tools::registry::Tool::ProcessResize,
        crate::tools::registry::Tool::ShellStatus,
        crate::tools::registry::Tool::ShellReset,
    ]
    .iter()
    .all(|t| tools.contains(t));
    let workspace_upstreams = !profile_settings.upstreams.empty()
        && tools.contains(&crate::tools::registry::Tool::UpstreamsCall);
    let mut section = json!({
        "enabled": true,
        "state_dir": oauth_state_dir,
        "local_client": profile_client.id,
        "workspace_edit": workspace_edit,
        "workspace_tools": workspace_tools,
        "workspace_jobs": workspace_jobs,
        "workspace_commands": workspace_commands,
        "workspace_interactive": workspace_interactive,
        "workspace_upstreams": workspace_upstreams,
        "funnel_advanced": workspace_jobs || workspace_upstreams,
    });
    if workspace_upstreams {
        let exact = profile_client.upstreams.tools.as_ref()
            .ok_or("Legacy OAuth provider grants must be exact before migration")?;
        section["allowed_server_tools"] = json!(exact);
    }
    Ok(section)
}

pub(crate) fn ensure_reconciled(home: &Path) -> Result<ReconcileStatus, String> {
    ensure_reconciled_with_issuer(home, false)
}

/// Explicit cutover preserves the saved OAuth issuer and retires only legacy
/// public bearer configuration. No Tailscale routes are changed here.
pub(crate) fn ensure_reconciled_with_issuer(home: &Path, adopt_oauth_issuer: bool) -> Result<ReconcileStatus, String> {
    let target_dir = state_root(home);
    let target_cfg = config_path(home);
    let legacy_static = legacy_static_config(home);
    let legacy_profile_dir = legacy_managed_profile(home);
    let legacy_profile_cfg = legacy_profile_dir.join("clients.json");
    let legacy_oauth_dir = legacy_profile_dir.join("oauth");

    let target_exists = path_exists_nofollow(&target_cfg)?;
    let legacy_static_exists = path_exists_nofollow(&legacy_static)?;
    let legacy_oauth_exists = path_exists_nofollow(&legacy_profile_cfg)?
        && path_exists_nofollow(&legacy_oauth_dir.join("oauth-state.json"))?;

    if path_exists_nofollow(&migration_pending_path(home))? {
        return Err(
            "Interrupted unified registry migration detected (~/.local/state/veyl/.migration-pending); resolve or clear incomplete staged files before retrying"
                .into(),
        );
    }

    if !target_exists && !legacy_static_exists && !legacy_oauth_exists {
        return Ok(ReconcileStatus::FreshEmpty);
    }

    let managed_logout_pending = home
        .join(crate::protected_paths::MANAGED_LOGIN_DIR)
        .join(".logout-pending");
    if legacy_oauth_exists && path_exists_nofollow(&managed_logout_pending)? {
        return Err(
            "Legacy ~/.veyl-login has an interrupted logout; run 'veyl logout' cleanly before migrating"
                .into(),
        );
    }

    // Read target if present to check whether anything needs reconciliation.
    if target_exists {
        let (_, target_doc, _) = read_verified_source_doc(&target_cfg)?;
        let migrated_static = target_doc["migrated_from"]["static_source"].as_str();
        let migrated_managed = target_doc["migrated_from"]["managed_source"].as_str();
        if legacy_static_exists
            && migrated_static != legacy_static.to_str()
        {
            return Err(
                "Conflicting static policies exist in ~/.local/state/veyl and ~/.config/mcp-gateway; resolve before proceeding"
                    .into(),
            );
        }
        let target_has_oauth = target_doc.get("oauth").is_some()
            || path_exists_nofollow(&target_dir.join("oauth/oauth-state.json"))?;
        if legacy_oauth_exists {
            if target_has_oauth {
                if migrated_managed == legacy_profile_cfg.to_str() {
                    return Ok(ReconcileStatus::Ready);
                }
                return Err(
                    "Existing OAuth state in ~/.local/state/veyl conflicts with legacy ~/.veyl-login/profile"
                        .into(),
                );
            }
            // Merge legacy OAuth profile into existing native ~/.local/state/veyl!
        } else {
            return Ok(ReconcileStatus::Ready);
        }
    }

    // Refuse live legacy services / active runtime during migration.
    check_legacy_processes(home)?;
    if is_serve_live(home).unwrap_or(false) {
        return Err("Stop running Veyl gateway before migrating state".into());
    }

    let state_fd = ensure_private_state_dir(home)?;
    let _reconcile_lock = open_private_lock(&state_fd, ".reconcile.lock")?;
    fs::flock(&_reconcile_lock, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| "Another migration or state reconciliation is in progress")?;

    // Inspect and validate ALL source configurations in place before writing anything.
    let static_source = if target_exists {
        Some((target_cfg.clone(), read_verified_source_doc(&target_cfg)?))
    } else if legacy_static_exists {
        Some((legacy_static.clone(), read_verified_source_doc(&legacy_static)?))
    } else {
        None
    };

    let oauth_source = if legacy_oauth_exists {
        let (bytes, doc, settings) = read_verified_source_doc(&legacy_profile_cfg)?;
        let audit_path = settings
            .audit_log
            .as_deref()
            .ok_or("Legacy OAuth profile missing audit ledger")?;
        AuditSink::inspect(audit_path, false)
            .map_err(|_| "Legacy OAuth profile audit ledger failed verification")?;
        let origin = oauth_http::persisted_origin(&legacy_oauth_dir)?;
        let oauth_summary = oauth_http::inspect_stopped_state(&legacy_oauth_dir)?;
        let local_client = settings
            .clients
            .first()
            .map(|c| c.id.as_str())
            .ok_or("Legacy OAuth profile missing anchor client")?;
        let workspace = &settings.clients[0].root;
        let old_bindings = compute_legacy_oauth_bindings(
            &legacy_profile_cfg,
            &settings,
            local_client,
            workspace,
        )?;
        Some((
            bytes,
            doc,
            settings,
            origin,
            oauth_summary,
            old_bindings,
        ))
    } else {
        None
    };

    // Detect identity & tunnel issuer conflicts before creating intent marker.
    let mut adopted_tailnet = None;
    if let (Some((_, (_, static_doc, static_settings))), Some((_, _, oauth_settings, origin, oauth_summary, _))) =
        (&static_source, &oauth_source)
    {
        let oauth_local = &oauth_settings.clients[0].id;
        let mut reg_ids = HashSet::new();
        if let Some(regs) = oauth_summary["registrations"].as_array() {
            for r in regs {
                if let Some(id) = r["client_id"].as_str() {
                    reg_ids.insert(id.to_owned());
                }
            }
        }
        for c in &static_settings.clients {
            if c.id == *oauth_local || reg_ids.contains(&c.id) {
                return Err(format!(
                    "Client identity collision during migration for ID '{}'",
                    c.id
                ));
            }
        }
        if let Some(tail) = &static_settings.tailnet {
            let uri: hyper::Uri = origin.parse().map_err(|_| "Invalid legacy OAuth origin")?;
            let origin_host = uri.host().unwrap_or_default();
            let origin_port = uri.port_u16().unwrap_or(443);
            if tail.hostname != origin_host {
                return Err(format!(
                    "Tailscale hostname conflict: static config uses '{}', OAuth issuer uses '{}'",
                    tail.hostname, origin_host
                ));
            }
            if tail.mcp_https_port != origin_port {
                if !adopt_oauth_issuer {
                    return Err(format!(
                        "Tailscale Funnel port conflict: static config uses {}, OAuth issuer uses {}; use 'veyl up --adopt-oauth-issuer' after retiring the old owned routes",
                        tail.mcp_https_port, origin_port
                    ));
                }
                if uri.scheme_str() != Some("https") || !matches!(origin_port, 8443 | 10000) {
                    return Err("Saved OAuth issuer is not a supported dedicated Tailscale HTTPS origin".into());
                }
                let admin_port = if tail.admin_https_port == origin_port { 9443 } else { tail.admin_https_port };
                adopted_tailnet = Some(json!({
                    "hostname": origin_host,
                    "mcp_https_port": origin_port,
                    "admin_https_port": admin_port,
                }));
            }
        }
        let _ = static_doc;
    }

    // Check job & goal collisions cleanly BEFORE mutating state dir.
    let mut merge_oauth_jobs = false;
    if let (Some((src_path, (_, _, static_settings))), Some((_, _, oauth_settings, _, _, _))) =
        (&static_source, &oauth_source)
    {
        if let Some(oauth_jobs) = oauth_settings.job_state_path() {
            merge_oauth_jobs = !empty_legacy_job_store(oauth_jobs)?;
            if merge_oauth_jobs {
                let static_jobs = static_settings.job_state_path()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| target_dir.join("jobs"));
                for entry in std::fs::read_dir(oauth_jobs)
                    .map_err(|_| "Cannot inspect legacy job receipts")?
                {
                    let entry = entry.map_err(|_| "Cannot iterate legacy job receipts")?;
                    let candidate = static_jobs.join(entry.file_name());
                    if path_exists_nofollow(&candidate)? {
                        return Err(format!(
                            "Job receipt collision on {} during migration",
                            candidate.display()
                        ));
                    }
                }
            }
        }
        let static_goals = src_path
            .parent()
            .map(|p| p.join(".clients.json.goals"));
        let oauth_goals = legacy_profile_dir.join(".clients.json.goals");
        if let Some(sg) = static_goals
            && sg.exists()
            && oauth_goals.exists()
        {
            for entry in std::fs::read_dir(&oauth_goals).into_iter().flatten().flatten() {
                if sg.join(entry.file_name()).exists() {
                    return Err(format!(
                        "Goal state collision on {} during migration",
                        entry.file_name().to_string_lossy()
                    ));
                }
            }
        }
    }

    // Retain the exact prior canonical policy for operator review. Never overwrite
    // a backup, or change the actual routes as a side effect of migration.
    if adopted_tailnet.is_some() && target_exists
        && path_exists_nofollow(&target_dir.join("clients.pre-unified.json"))?
    {
        return Err("Existing pre-unified policy backup; resolve before retrying migration".into());
    }

    // Begin atomic migration transaction via durable intent marker.
    publish_new(
        &state_fd,
        OsStr::new(".migration-pending"),
        b"in_progress\n",
    )
    .map_err(|_| "Cannot write migration intent marker")?;
    fs::fsync(&state_fd).map_err(|_| "Cannot sync migration intent marker")?;
    if adopted_tailnet.is_some() && target_exists {
        let (_, (original, _, _)) = static_source.as_ref().ok_or("Missing original static policy")?;
        publish_new(&state_fd, OsStr::new("clients.pre-unified.json"), original)
            .map_err(|_| "Cannot preserve pre-unified policy backup")?;
        fs::fsync(&state_fd).map_err(|_| "Cannot sync pre-unified policy backup")?;
    }

    let audit_dir = target_dir.join("audit");
    let jobs_dir = target_dir.join("jobs");
    let skills_dir = target_dir.join("skills");
    let oauth_dest_dir = target_dir.join("oauth");
    for dir in [&audit_dir, &jobs_dir, &skills_dir] {
        std::fs::create_dir_all(dir).map_err(|_| "Cannot initialize target subdirectories")?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot secure target subdirectories")?;
    }

    let dest_audit_file = match &static_source {
        Some((_, (_, _, s))) if target_exists => s
            .audit_log
            .clone()
            .unwrap_or_else(|| audit_dir.join("events.jsonl")),
        _ => audit_dir.join("events.jsonl"),
    };
    let dest_jobs_dir = match &static_source {
        Some((_, (_, _, s))) if target_exists => s
            .job_state_path()
            .map(PathBuf::from)
            .unwrap_or_else(|| jobs_dir.clone()),
        _ => jobs_dir.clone(),
    };

    // Preserve verified audit ledger into target when creating target from legacy source.
    if !target_exists {
        if let Some((_, (_, _, s))) = &static_source {
            if let Some(src_audit) = s.audit_log.as_deref()
                && legacy_audit_initialized(src_audit)?
            {
                AuditSink::migrate_verified(src_audit, &dest_audit_file, s.audit_limits)
                    .map_err(|e| format!("Failed migrating verified static audit ledger: {e}"))?;
            }
            if let Some(src_jobs) = s.job_state_path() {
                copy_directory_contents_no_overwrite(src_jobs, &dest_jobs_dir, false)?;
            }
            if let Some(src_skills) = &s.skills {
                copy_directory_contents_no_overwrite(src_skills.path(), &skills_dir, false)?;
            }
            let src_goals = legacy_static.parent().unwrap().join(".clients.json.goals");
            if src_goals.exists() {
                copy_directory_contents_no_overwrite(
                    &src_goals,
                    &target_dir.join(".clients.json.goals"),
                    false,
                )?;
            }
        } else if let Some((_, _, os, _, _, _)) = &oauth_source {
            if let Some(src_audit) = os.audit_log.as_deref()
                && legacy_audit_initialized(src_audit)?
            {
                AuditSink::migrate_verified(src_audit, &dest_audit_file, os.audit_limits)
                    .map_err(|e| format!("Failed migrating verified OAuth audit ledger: {e}"))?;
            }
            if let Some(src_jobs) = os.job_state_path() {
                copy_directory_contents_no_overwrite(src_jobs, &dest_jobs_dir, false)?;
            }
            let src_goals = legacy_profile_dir.join(".clients.json.goals");
            if src_goals.exists() {
                copy_directory_contents_no_overwrite(
                    &src_goals,
                    &target_dir.join(".clients.json.goals"),
                    false,
                )?;
            }
        }
    }

    // Merge OAuth auxiliary jobs/goals if both static target & legacy OAuth existed.
    if let (Some(_), Some((_, _, os, _, _, _))) = (&static_source, &oauth_source) {
        if merge_oauth_jobs && let Some(oauth_jobs) = os.job_state_path() {
            copy_directory_contents_no_overwrite(oauth_jobs, &dest_jobs_dir, true)?;
        }
        let oauth_goals = legacy_profile_dir.join(".clients.json.goals");
        if oauth_goals.exists() {
            copy_directory_contents_no_overwrite(
                &oauth_goals,
                &target_dir.join(".clients.json.goals"),
                true,
            )?;
        }
    }

    // Assemble unified policy document.
    let mut new_doc = if let Some((_, (_, static_doc, static_settings))) = &static_source {
        let mut doc = static_doc.clone();
        let ver = static_settings.policy_version;
        let mut next_clients = Vec::with_capacity(static_settings.clients.len());
        for (entry, client) in static_doc["clients"]
            .as_array()
            .ok_or("Invalid clients array")?
            .iter()
            .zip(&static_settings.clients)
        {
            let (converted, _) = convert_client_entry_to_schema4(entry, client, ver)?;
            next_clients.push(converted);
        }
        doc["policy_version"] = json!(4);
        doc["clients"] = Value::Array(next_clients);
        if !target_exists {
            doc["audit_log"] = json!(dest_audit_file);
            if doc.get("job_state_dir").is_some() {
                doc["job_state_dir"] = json!(dest_jobs_dir);
            }
            if doc.get("skills_dir").is_some() {
                doc["skills_dir"] = json!(skills_dir);
            }
        }
        if doc.get("default_mode").is_none() {
            doc["default_mode"] = json!("standard");
        }
        doc
    } else if let Some((_, oauth_doc, _, _, _, _)) = &oauth_source {
        let mut doc = oauth_doc.clone();
        doc["policy_version"] = json!(4);
        doc["clients"] = json!([]);
        doc["default_mode"] = json!("standard");
        doc["audit_log"] = json!(dest_audit_file);
        doc["job_state_dir"] = json!(dest_jobs_dir);
        doc["admin_listen"] = json!("127.0.0.1:7332");
        doc["skills_dir"] = json!(skills_dir);
        doc
    } else {
        unreachable!()
    };

    if let Some((_, oauth_doc, oauth_settings, origin, _, _)) = &oauth_source {
        let workspace = oauth_settings.clients[0].root.clone();
        if new_doc.get("workspace").is_none() {
            new_doc["workspace"] = json!(workspace);
        }
        if new_doc.get("job_profiles").is_none() {
            if let Some(jp) = oauth_doc.get("job_profiles") {
                new_doc["job_profiles"] = jp.clone();
            } else {
                new_doc["job_profiles"] = json!({"health": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 5}});
            }
            new_doc["job_state_dir"] = json!(dest_jobs_dir);
        }
        if new_doc.get("admin_listen").is_none() {
            new_doc["admin_listen"] = json!("127.0.0.1:7332");
        }
        if let Some(servers) = oauth_doc.get("mcp_servers").and_then(Value::as_object) {
            if new_doc.get("mcp_servers").is_none() {
                new_doc["mcp_servers"] = json!({});
            }
            let unified = new_doc["mcp_servers"].as_object_mut().ok_or("Invalid static upstream catalog")?;
            for (id, definition) in servers {
                match unified.get(id) {
                    Some(existing) if existing != definition => {
                        return Err(format!("Static and OAuth upstream definitions conflict for {id}"));
                    }
                    Some(_) => {}
                    None => { unified.insert(id.clone(), definition.clone()); }
                }
            }
        }
        if new_doc.get("tailscale_serve").is_none()
            && new_doc.get("cloudflare_tunnel").is_none()
            && let Ok(uri) = origin.parse::<hyper::Uri>()
            && let Some(host) = uri.host()
            && host.ends_with(".ts.net")
        {
            let port = uri.port_u16().unwrap_or(8443);
            let admin_port = if port == 9443 { 10443 } else { 9443 };
            new_doc["tailscale_serve"] = json!({
                "hostname": host,
                "mcp_https_port": port,
                "admin_https_port": admin_port,
            });
        }
        if let Some(tailnet) = adopted_tailnet {
            new_doc["tailscale_serve"] = tailnet;
        }
        new_doc["oauth"] = build_oauth_section_from_profile(oauth_doc, oauth_settings, &oauth_dest_dir)?;
    }

    let mut provenance = new_doc
        .get("migrated_from")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if static_source.is_some() && !target_exists {
        provenance.insert("static_source".into(), json!(legacy_static));
    }
    if oauth_source.is_some() {
        provenance.insert("managed_source".into(), json!(legacy_profile_cfg));
    }
    new_doc["migrated_from"] = Value::Object(provenance);

    let mut new_bytes = serde_json::to_vec_pretty(&new_doc).map_err(|_| "Cannot encode unified policy")?;
    new_bytes.push(b'\n');
    let parsed_new = parse_clients(&target_cfg, &new_bytes)?;

    if let Some((_, _, oauth_settings, _, _, (old_v2, old_v1))) = &oauth_source {
        std::fs::create_dir_all(&oauth_dest_dir)
            .map_err(|_| "Cannot create unified oauth directory")?;
        std::fs::set_permissions(&oauth_dest_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot secure unified oauth directory")?;
        let workspace = parsed_new
            .workspace
            .as_deref()
            .ok_or("Missing workspace in migrated unified policy")?;
        let ws_fd = open_absolute_dir(workspace).map_err(|_| "Workspace unavailable")?;
        let ws_stat = fs::fstat(&ws_fd).map_err(|_| "Workspace unavailable")?;
        let ws_durable = DurableObjectId::probe(&ws_fd, &ws_stat)
            .map_err(|_| "Workspace filesystem identity unavailable")?;
        let local_client = oauth_settings.clients[0].id.as_str();
        let new_binding = crate::http::compute_unified_binding(
            &target_cfg
                .parent()
                .ok_or("Missing target dir")?
                .canonicalize()
                .map_err(|_| "Target dir unavailable")?
                .join("clients.json"),
            &parsed_new.oauth_binding_digest,
            local_client,
            workspace,
            &ws_durable,
        );
        oauth_http::rebind_migrated_state(
            &legacy_oauth_dir,
            &oauth_dest_dir,
            local_client,
            &[old_v2.as_str(), old_v1.as_str()],
            &new_binding,
        )?;
    }

    if target_exists {
        let policy = PolicyFile::lock(&target_cfg, true)?;
        let (_, (original, _, _)) = static_source.as_ref().ok_or("Missing original static policy")?;
        if policy.bytes()?.as_slice() != original.as_slice() {
            return Err("Static policy changed during migration; recovery required".into());
        }
        let limits = parsed_new.audit_limits;
        let audit_path = parsed_new
            .audit_log
            .as_deref()
            .ok_or("Missing unified audit ledger")?;
        let audit = AuditSink::open_with_limits(audit_path, limits)
            .map_err(|_| "Cannot open audit ledger for migration checkpoint")?;
        policy.commit_edit(&new_doc, "@unified-migration", |phase| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            audit.record_runtime_mode(
                "local_operator",
                "unified_registry_migration",
                parsed_new.default_mode.as_str(),
                phase,
                now,
            )
        })?;
    } else {
        publish_new(&state_fd, OsStr::new("clients.json"), &new_bytes)
            .map_err(|_| "Cannot publish migrated clients.json")?;
        let limits = parsed_new.audit_limits;
        let audit_path = parsed_new
            .audit_log
            .as_deref()
            .ok_or("Missing unified audit ledger")?;
        let audit = AuditSink::open_with_limits(audit_path, limits)
            .map_err(|_| "Cannot initialize unified audit ledger")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        audit
            .record_runtime_mode(
                "local_operator",
                "unified_registry_migration",
                parsed_new.default_mode.as_str(),
                AuditPhase::Success,
                now,
            )
            .map_err(|_| "Cannot record migration event in audit ledger")?;
    }

    // Verify complete unified state before clearing migration intent.
    let (_, _, verified) = read_verified_source_doc(&target_cfg)?;
    if oauth_source.is_some() {
        let _ = oauth_http::inspect_stopped_state(&oauth_dest_dir)?;
    }
    let _ = verified;
    fs::unlinkat(&state_fd, ".migration-pending", fs::AtFlags::empty())
        .map_err(|_| "Migrated state verified, but cleanup of .migration-pending failed")?;
    fs::fsync(&state_fd).map_err(|_| "Cannot sync state directory after migration")?;
    Ok(ReconcileStatus::Migrated)
}

/// Initialize minimal fresh unified registry under ~/.local/state/veyl when
/// zero state or legacy configs exist (e.g., `veyl mode yolo --yes` before `veyl up`).
pub(crate) fn ensure_minimal_empty_registry(home: &Path) -> Result<PathBuf, String> {
    let status = ensure_reconciled(home)?;
    let cfg = config_path(home);
    if status != ReconcileStatus::FreshEmpty && path_exists_nofollow(&cfg)? {
        return Ok(cfg);
    }
    let dir_fd = ensure_private_state_dir(home)?;
    let target_dir = state_root(home);
    for name in ["audit", "jobs", "skills"] {
        let sub = target_dir.join(name);
        std::fs::create_dir_all(&sub).map_err(|_| "Cannot create state subdirectories")?;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot secure state subdirectories")?;
    }
    let audit_log = target_dir.join("audit/events.jsonl");
    let doc = json!({
        "policy_version": 4,
        "default_mode": "standard",
        "audit_log": audit_log,
        "job_state_dir": target_dir.join("jobs"),
        "skills_dir": target_dir.join("skills"),
        "admin_listen": "127.0.0.1:0",
        "job_profiles": {"health": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 5}},
        "clients": [],
    });
    let mut bytes = serde_json::to_vec_pretty(&doc).map_err(|_| "Cannot encode policy")?;
    bytes.push(b'\n');
    publish_new(&dir_fd, OsStr::new("clients.json"), &bytes)
        .map_err(|_| "Cannot initialize unified clients.json")?;
    let settings = parse_clients(&cfg, &bytes)?;
    drop(
        AuditSink::open_with_limits(&audit_log, settings.audit_limits)
            .map_err(|_| "Cannot initialize audit ledger")?,
    );
    Ok(cfg)
}

pub(crate) fn fetch_oauth_registrations(
    home: &Path,
    settings: &Configuration,
) -> Result<(bool, Vec<Value>, bool), String> {
    let live = is_serve_live(home)?;
    let Some(oauth) = &settings.oauth else {
        return Ok((live, Vec::new(), false));
    };
    if live && path_exists_nofollow(&control_socket_path(home))? {
        let (status, body) = send_control_command(home, &json!({"action": "list"}))?;
        if status == 200 {
            let regs = body["registrations"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let supports_yolo = body["supports_yolo"].as_bool().unwrap_or(false);
            return Ok((true, regs, supports_yolo));
        }
    }
    if path_exists_nofollow(&oauth.state_dir.join("oauth-state.json"))? {
        let info = oauth_http::inspect_stopped_state(&oauth.state_dir)?;
        let regs = info["registrations"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        return Ok((live, regs, settings.jobs.is_some()));
    }
    Ok((live, Vec::new(), settings.jobs.is_some()))
}

fn legacy_audit_initialized(path: &Path) -> Result<bool, String> {
    let head_path = PathBuf::from(format!("{}.head", path.display()));
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    if path_exists_nofollow(&head_path)? || path_exists_nofollow(&lock_path)? {
        return Ok(true);
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || meta.len() > 0 {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("Cannot inspect legacy audit ledger: {e}")),
    }
}
