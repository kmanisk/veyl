//! Unified CLI surface: `veyl up`, `veyl down`, `veyl status`,
//! `veyl clients`, and `veyl serve` (while preserving `veyl serve plan`).

use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::http_common::oauth_http;
use mcp_gateway::security::audit::AuditSink;
use mcp_gateway::security::linux_fs::open_operator_dir;
use serde_json::json;

use crate::http::admission::parse_clients;
use crate::http::operator::{PolicyFile, parse_document, verify_approvals};
use crate::http::{UnifiedRuntimeOptions, UnifiedTunnelLaunch};
use crate::unified;

const UP_HELP: &str = "Usage: veyl up [--root DIR] [--tailscale | --cloudflare] [--yolo] [--yes | --confirm-native] [--service] [--adopt-oauth-issuer] [--no-ui] [--local] [--listen 127.0.0.1:PORT] [--funnel-port 8443|10000] [--funnel-socket PATH] [--cf-hostname HOST --cf-tunnel ID --cf-credentials PATH [--cf-config PATH] [--cf-bin PATH]]\n\
                       Initialize unified ~/.local/state/veyl state (or resume existing state), configure the tunnel, print the HTTPS /mcp URL and local approval link, and run the gateway.";
const DOWN_HELP: &str = "Usage: veyl down\nGracefully stop the running unified Veyl gateway (foreground serve or veyl.service) and tear down only its owned tunnel.";
const STATUS_HELP: &str = "Usage: veyl status [--config PATH] [--json]\nDisplay unified registry state, default_mode, active runtime/service, tunnel, static clients, and OAuth registrations.";
const CLIENTS_HELP: &str = "Usage: veyl clients [list | revoke <ID_OR_NAME>] [--yes] [--config PATH]\nList static and OAuth clients or immediately revoke one client cleanly.";
const SERVE_HELP: &str = "Usage: veyl serve [--config PATH] [--listen 127.0.0.1:PORT] [--tailscale | --cloudflare | --local] [--funnel-port 8443|10000] [--funnel-socket PATH] [--open-ui]\n\
                          veyl serve plan --config PATH [--listen 127.0.0.1:PORT] [--live] [--state-file PATH] [--wait-seconds N]\n\
                          Run the single unified Veyl gateway runtime in the foreground (invoked by `veyl up` and `veyl.service`).";

fn confirm_yolo(yes: bool) -> Result<(), String> {
    if yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err("YOLO requires typed local confirmation ('YOLO') or --yes; refusing non-interactive elevation".into());
    }
    eprint!("YOLO sets default_mode=yolo (grants native host-user access when approved). Type YOLO to confirm: ");
    io::stderr()
        .flush()
        .map_err(|_| "Cannot display confirmation")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| "Cannot read confirmation")?;
    if answer.trim() != "YOLO" {
        return Err("Cancelled; no mode or state changed".into());
    }
    Ok(())
}

fn confirm_revoke(label: &str, yes: bool) -> Result<(), String> {
    if yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(format!("Revoking {label} non-interactively requires --yes"));
    }
    eprint!("Revoke client {label}? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|_| "Cannot display confirmation")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| "Cannot read confirmation")?;
    if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        return Err("Cancelled; client not revoked".into());
    }
    Ok(())
}

fn select_workspace(default: PathBuf, state_dir: &Path) -> Result<PathBuf, String> {
    let normalize = |candidate: PathBuf| -> Result<PathBuf, String> {
        let canon = candidate
            .canonicalize()
            .map_err(|_| format!("Workspace unavailable: {}", candidate.display()))?;
        open_operator_dir(&canon).map_err(|_| "Workspace must be an existing owner-accessible directory")?;
        if canon.starts_with(state_dir) || state_dir.starts_with(&canon) || !canon.is_dir() {
            return Err("Choose an existing workspace separate from ~/.local/state/veyl".into());
        }
        Ok(canon)
    };
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return normalize(default);
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
            return normalize(default);
        }
        let chosen = line.trim();
        let candidate = if chosen.is_empty() {
            default.clone()
        } else {
            let p = PathBuf::from(chosen);
            if !p.is_absolute() {
                eprintln!("Use an absolute directory path.");
                continue;
            }
            p
        };
        match normalize(candidate) {
            Ok(canon) => return Ok(canon),
            Err(err) => eprintln!("{err}"),
        }
    }
}

pub(crate) fn serve(args: &[OsString]) -> Result<(), String> {
    if args.first().and_then(|a| a.to_str()).is_some_and(|sub| {
        matches!(
            sub,
            "plan"
                | "validate"
                | "inspect"
                | "apply"
                | "remove"
                | "rollback"
                | "funnel-plan"
                | "funnel-apply"
                | "funnel-rollback"
                | "funnel-retire-dedicated"
                | "funnel-retire-legacy"
        )
    }) {
        return crate::serve_plan::run(args);
    }
    if args.iter().any(|a| a == "--help") {
        println!("{SERVE_HELP}");
        return Ok(());
    }
    if rustix::process::geteuid().is_root() {
        return Err("Run veyl serve as your normal unprivileged user, not root".into());
    }

    let mut config_override = None;
    let mut listen_override: Option<SocketAddrV4> = None;
    let mut force_tailscale = false;
    let mut force_cloudflare = false;
    let mut force_local = false;
    let mut funnel_port = None;
    let mut funnel_socket = None;
    let mut open_ui = false;
    let mut options = args.iter();
    while let Some(arg) = options.next() {
        match arg.to_str() {
            Some("--config") if config_override.is_none() => {
                config_override = Some(PathBuf::from(options.next().ok_or(SERVE_HELP)?));
            }
            Some("--listen") if listen_override.is_none() => {
                let raw = options.next().and_then(|v| v.to_str()).ok_or(SERVE_HELP)?;
                listen_override = Some(raw.parse::<SocketAddrV4>().map_err(|_| "Invalid IPv4 127.0.0.1 listener")?);
            }
            Some("--tailscale" | "--funnel") => force_tailscale = true,
            Some("--cloudflare") => force_cloudflare = true,
            Some("--local" | "--no-tunnel") => force_local = true,
            Some("--funnel-port") if funnel_port.is_none() => {
                let port = options
                    .next()
                    .and_then(|v| v.to_str())
                    .and_then(|v| v.parse::<u16>().ok())
                    .filter(|p| matches!(p, 8443 | 10000))
                    .ok_or("Funnel port must be 8443 or 10000")?;
                funnel_port = Some(port);
            }
            Some("--funnel-socket") if funnel_socket.is_none() => {
                funnel_socket = Some(PathBuf::from(options.next().ok_or(SERVE_HELP)?));
            }
            Some("--open-ui") => open_ui = true,
            _ => return Err(SERVE_HELP.into()),
        }
    }
    if usize::from(force_tailscale) + usize::from(force_cloudflare) + usize::from(force_local) > 1 {
        return Err("Choose at most one of --tailscale, --cloudflare, or --local".into());
    }

    let home = unified::home_dir()?;
    if crate::service_cli::legacy_unit_is_active(&home)? {
        return Err(
            "Legacy mcp-gateway.service is active; stop and disable it before starting unified veyl serve (preserved until you transition)"
                .into(),
        );
    }
    let managed_base = home.join(crate::protected_paths::MANAGED_LOGIN_DIR);
    if managed_base.exists() && crate::oauth_cli::managed::is_live_dir(&managed_base)? {
        return Err("Legacy ~/.veyl-login session is active; stop it before starting veyl serve".into());
    }

    let cfg_path = if let Some(explicit) = config_override {
        explicit
    } else {
        let status = unified::ensure_reconciled(&home)?;
        if status == unified::ReconcileStatus::FreshEmpty {
            return Err("Veyl state is not initialized yet; run 'veyl up --root DIR' first".into());
        }
        unified::config_path(&home)
    };

    let _serve_lock = unified::acquire_serve_lock(&home)?;
    let (control, _socket_cleanup) = unified::bind_control_socket(&home)?;

    let policy = PolicyFile::lock(&cfg_path, false)?;
    let settings = policy.snapshot()?;
    verify_approvals(&settings)?;
    drop(policy);

    let tunnel = if force_local {
        UnifiedTunnelLaunch::None
    } else if force_cloudflare || (!force_tailscale && settings.cloudflare.is_some()) {
        UnifiedTunnelLaunch::Cloudflare
    } else if force_tailscale
        || settings.tailnet.is_some()
        || settings.oauth.as_ref().is_some_and(|o| o.enabled)
    {
        UnifiedTunnelLaunch::Tailscale {
            socket: funnel_socket,
            port: funnel_port,
        }
    } else {
        UnifiedTunnelLaunch::None
    };

    let initialize_oauth = settings
        .oauth
        .as_ref()
        .is_some_and(|o| o.enabled && !o.state_dir.join("oauth-state.json").exists());

    let listen = listen_override.unwrap_or_else(|| {
        // Preserve the conventional local endpoint for migrated static clients.
        // OAuth-only profiles need no fixed local MCP port.
        if !settings.clients.is_empty()
            || (settings.oauth.is_none() && settings.tailnet.is_none() && settings.cloudflare.is_none())
        {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7331)
        } else {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)
        }
    });

    let systemd_unit = std::env::var_os("INVOCATION_ID").is_some();
    crate::http::run_unified(UnifiedRuntimeOptions {
        listen: SocketAddr::V4(listen),
        path: cfg_path,
        initialize_oauth,
        tunnel,
        open_ui,
        control,
        status_path: unified::runtime_status_path(&home),
        systemd_unit,
    })
}

pub(crate) fn up(args: &[OsString]) -> Result<(), String> {
    if args.iter().any(|a| a == "--help") {
        println!("{UP_HELP}");
        return Ok(());
    }
    if rustix::process::geteuid().is_root() {
        return Err("Run veyl up as your normal unprivileged user, not root".into());
    }

    let mut root = None;
    let mut use_tailscale = false;
    let mut use_cloudflare = false;
    let mut local_only = false;
    let mut yolo = false;
    let mut yes = false;
    let mut service = false;
    let mut adopt_oauth_issuer = false;
    let mut no_ui = false;
    let mut listen: Option<SocketAddrV4> = None;
    let mut funnel_port = None;
    let mut funnel_socket = None;
    let mut cf_hostname = None;
    let mut cf_tunnel = None;
    let mut cf_credentials = None;
    let mut cf_config = None;
    let mut cf_bin = None;

    let mut options = args.iter();
    while let Some(arg) = options.next() {
        match arg.to_str() {
            Some("--root") if root.is_none() => {
                root = Some(PathBuf::from(options.next().ok_or(UP_HELP)?));
            }
            Some("--tailscale") => use_tailscale = true,
            Some("--cloudflare") => use_cloudflare = true,
            Some("--local") => local_only = true,
            Some("--yolo") => yolo = true,
            Some("--yes" | "--confirm-native") => yes = true,
            Some("--service") => service = true,
            Some("--adopt-oauth-issuer") if !adopt_oauth_issuer => adopt_oauth_issuer = true,
            Some("--no-ui") => no_ui = true,
            Some("--listen") if listen.is_none() => {
                let raw = options.next().and_then(|v| v.to_str()).ok_or(UP_HELP)?;
                listen = Some(raw.parse::<SocketAddrV4>().map_err(|_| "Invalid IPv4 127.0.0.1 listener")?);
            }
            Some("--funnel-port") if funnel_port.is_none() => {
                let port = options
                    .next()
                    .and_then(|v| v.to_str())
                    .and_then(|v| v.parse::<u16>().ok())
                    .filter(|p| matches!(p, 8443 | 10000))
                    .ok_or("Funnel port must be 8443 or 10000")?;
                funnel_port = Some(port);
            }
            Some("--funnel-socket") if funnel_socket.is_none() => {
                funnel_socket = Some(PathBuf::from(options.next().ok_or(UP_HELP)?));
            }
            Some("--cf-hostname") if cf_hostname.is_none() => {
                cf_hostname = Some(options.next().and_then(|v| v.to_str()).ok_or(UP_HELP)?.to_owned());
            }
            Some("--cf-tunnel") if cf_tunnel.is_none() => {
                cf_tunnel = Some(options.next().and_then(|v| v.to_str()).ok_or(UP_HELP)?.to_owned());
            }
            Some("--cf-credentials") if cf_credentials.is_none() => {
                cf_credentials = Some(PathBuf::from(options.next().ok_or(UP_HELP)?));
            }
            Some("--cf-config") if cf_config.is_none() => {
                cf_config = Some(PathBuf::from(options.next().ok_or(UP_HELP)?));
            }
            Some("--cf-bin") if cf_bin.is_none() => {
                cf_bin = Some(PathBuf::from(options.next().ok_or(UP_HELP)?));
            }
            _ => return Err(UP_HELP.into()),
        }
    }

    if usize::from(use_tailscale) + usize::from(use_cloudflare) + usize::from(local_only) > 1 {
        return Err("Choose at most one of --tailscale, --cloudflare, or --local".into());
    }

    if adopt_oauth_issuer && (use_cloudflare || funnel_port.is_some() || cf_hostname.is_some()
        || cf_tunnel.is_some() || cf_credentials.is_some() || cf_config.is_some() || cf_bin.is_some())
    {
        return Err("--adopt-oauth-issuer retains the saved Tailscale origin; do not override the provider or port".into());
    }
    if yolo {
        confirm_yolo(yes)?;
    }

    let home = unified::home_dir()?;
    if crate::service_cli::legacy_unit_is_active(&home)? {
        return Err(
            "Legacy mcp-gateway.service is active; stop and disable it before starting unified Veyl (existing routes/service remain untouched)"
                .into(),
        );
    }
    if unified::is_serve_live(&home)? {
        return Err("Veyl gateway is already running; inspect with 'veyl status' or stop with 'veyl down'".into());
    }

    let reconcile_status = unified::ensure_reconciled_with_issuer(&home, adopt_oauth_issuer)?;
    let cfg_path = unified::config_path(&home);
    let state_dir = unified::state_root(&home);

    let cf_from_flags = if use_cloudflare || cf_hostname.is_some() || cf_tunnel.is_some() || cf_credentials.is_some() {
        let host = cf_hostname.ok_or(
            "Cloudflare tunnel requires explicit --cf-hostname, --cf-tunnel, and --cf-credentials (or saved cloudflare_tunnel config); nothing started",
        )?;
        let tunnel = cf_tunnel.ok_or("Cloudflare tunnel requires explicit --cf-tunnel")?;
        let creds = cf_credentials.ok_or("Cloudflare tunnel requires explicit --cf-credentials")?;
        let raw = json!({
            "hostname": host,
            "tunnel": tunnel,
            "credentials_file": creds,
            "config_file": cf_config,
            "binary": cf_bin,
        });
        let parsed = crate::cloudflare::Settings::parse(&raw)?;
        parsed.validate_ready()?;
        Some(raw)
    } else {
        None
    };

    let mut need_bootstrap = reconcile_status == unified::ReconcileStatus::FreshEmpty;
    if !need_bootstrap && cfg_path.exists() {
        let existing = PolicyFile::preview(&cfg_path)?;
        if existing.workspace.is_none() || (existing.oauth.is_none() && !local_only && (use_tailscale || use_cloudflare || (!use_tailscale && !use_cloudflare && existing.tailnet.is_none() && existing.cloudflare.is_none()))) {
            need_bootstrap = true;
        }
    }

    if need_bootstrap {
        if !cfg_path.exists() {
            unified::ensure_minimal_empty_registry(&home)?;
        }
        let chosen_workspace = match root {
            Some(explicit) => select_workspace(explicit, &state_dir)?,
            None => {
                let existing = PolicyFile::preview(&cfg_path)?;
                if let Some(ws) = existing.workspace {
                    ws
                } else {
                    let cwd = std::env::current_dir().map_err(|_| "Cannot determine workspace")?;
                    select_workspace(cwd, &state_dir)?
                }
            }
        };

        let policy = PolicyFile::lock(&cfg_path, true)?;
        let bytes = policy.bytes()?;
        let mut doc = parse_document(&bytes)?;
        let prev_settings = parse_clients(&cfg_path, &bytes)?;

        doc["workspace"] = json!(chosen_workspace);
        if doc.get("admin_listen").is_none() {
            doc["admin_listen"] = json!("127.0.0.1:0");
        }
        let oauth_dir = state_dir.join("oauth");
        std::fs::create_dir_all(&oauth_dir).map_err(|_| "Cannot initialize oauth state dir")?;
        std::fs::set_permissions(&oauth_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot secure oauth state dir")?;

        if let Some(cf_val) = cf_from_flags.as_ref() {
            doc.as_object_mut().unwrap().remove("tailscale_serve");
            doc["cloudflare_tunnel"] = cf_val.clone();
            doc["oauth"] = json!({
                "enabled": true,
                "state_dir": oauth_dir,
                "local_client": "veyl-oauth",
            });
        } else if !local_only && (use_tailscale || doc.get("cloudflare_tunnel").is_none()) {
            let plan = crate::tailnet::oauth_provider::Plan::detect(funnel_socket.clone(), funnel_port)?;
            let uri: hyper::Uri = plan.origin().parse().map_err(|_| "Invalid Tailscale origin")?;
            let host = uri.host().unwrap_or_default().to_owned();
            let port = uri.port_u16().unwrap_or(8443);
            let admin_port = if port == 9443 { 10443 } else { 9443 };
            doc["tailscale_serve"] = json!({
                "hostname": host,
                "mcp_https_port": port,
                "admin_https_port": admin_port,
            });
            doc["oauth"] = json!({
                "enabled": true,
                "state_dir": oauth_dir,
                "local_client": "veyl-oauth",
            });
        }
        if yolo {
            doc["default_mode"] = json!("yolo");
        }
        let mut encoded = serde_json::to_vec_pretty(&doc).map_err(|_| "Cannot serialize policy")?;
        encoded.push(b'\n');
        let _ = parse_clients(&cfg_path, &encoded)?;
        let audit_path = prev_settings
            .audit_log
            .as_deref()
            .ok_or("Missing audit log")?;
        let audit = AuditSink::open_with_limits(audit_path, prev_settings.audit_limits)
            .map_err(|_| "Cannot open audit ledger")?;
        policy.commit_edit(&doc, "@up-init", |phase| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            audit.record_runtime_mode(
                "local_operator",
                "unified_up_init",
                doc["default_mode"].as_str().unwrap_or("standard"),
                phase,
                now,
            )
        })?;
    } else if root.is_some() {
        let existing = PolicyFile::preview(&cfg_path)?;
        let chosen = select_workspace(root.unwrap(), &state_dir)?;
        if existing.workspace.as_deref() != Some(chosen.as_path()) {
            return Err("Unified workspace already configured; resume without conflicting --root or update explicitly".into());
        }
    } else if yolo {
        crate::mode_cli::run(&["yolo".into(), "--yes".into()])?;
    }

    // Print expected endpoints clearly before starting runtime/service.
    let current = PolicyFile::preview(&cfg_path)?;
    if !local_only {
        if let Some(cf) = &current.cloudflare {
            println!("PUBLIC_MCP_URL={}/mcp", cf.origin());
        } else if let Ok(plan) = crate::tailnet::oauth_provider::Plan::detect(
            funnel_socket.clone(),
            funnel_port.or_else(|| current.tailnet.as_ref().map(|t| t.mcp_https_port)),
        ) {
            println!("PUBLIC_MCP_URL={}/mcp", plan.origin());
        }
    }
    if let Some(admin) = current.admin_listen {
        if admin.port() != 0 {
            println!("LOCAL_APPROVAL_URL=http://{}/dashboard", admin);
        } else {
            println!("LOCAL_APPROVAL_URL=http://127.0.0.1:<ephemeral>/dashboard");
        }
    }

    if service {
        return crate::service_cli::install_and_start_unified(
            &home,
            true,
            listen,
            funnel_socket.as_deref(),
        );
    }

    let mut serve_args = Vec::new();
    if let Some(addr) = listen {
        serve_args.extend(["--listen".into(), addr.to_string().into()]);
    }
    if local_only {
        serve_args.push("--local".into());
    } else if use_tailscale {
        serve_args.push("--tailscale".into());
    } else if use_cloudflare || current.cloudflare.is_some() {
        serve_args.push("--cloudflare".into());
    }
    if let Some(port) = funnel_port {
        serve_args.extend(["--funnel-port".into(), port.to_string().into()]);
    }
    if let Some(sock) = funnel_socket {
        serve_args.extend(["--funnel-socket".into(), sock.into_os_string()]);
    }
    if !no_ui {
        serve_args.push("--open-ui".into());
    }
    serve(&serve_args)
}

pub(crate) fn down(args: &[OsString]) -> Result<(), String> {
    if args.iter().any(|a| a == "--help") {
        println!("{DOWN_HELP}");
        return Ok(());
    }
    if !args.is_empty() {
        return Err(DOWN_HELP.into());
    }
    let home = unified::home_dir()?;
    if crate::service_cli::veyl_unit_is_active(&home)? {
        crate::service_cli::run(&["stop".into()])?;
        println!("Veyl service stopped cleanly.");
        return Ok(());
    }
    if unified::shutdown_live_foreground(&home)? {
        println!("Veyl gateway stopped cleanly.");
        return Ok(());
    }
    println!("Veyl gateway is not running.");
    Ok(())
}

pub(crate) fn status(args: &[OsString]) -> Result<(), String> {
    if args.iter().any(|a| a == "--help") {
        println!("{STATUS_HELP}");
        return Ok(());
    }
    let mut config_override = None;
    let mut as_json = false;
    let mut options = args.iter();
    while let Some(arg) = options.next() {
        match arg.to_str() {
            Some("--config") if config_override.is_none() => {
                config_override = Some(PathBuf::from(options.next().ok_or(STATUS_HELP)?));
            }
            Some("--json") => as_json = true,
            _ => return Err(STATUS_HELP.into()),
        }
    }

    let home = unified::home_dir()?;
    let legacy_unit_active = crate::service_cli::legacy_unit_is_active(&home).unwrap_or(false);
    let veyl_unit_active = crate::service_cli::veyl_unit_is_active(&home).unwrap_or(false);
    let legacy_managed_active = home
        .join(crate::protected_paths::MANAGED_LOGIN_DIR)
        .exists()
        && crate::oauth_cli::managed::is_live_dir(&home.join(crate::protected_paths::MANAGED_LOGIN_DIR))
            .unwrap_or(false);

    if let Some(cfg) = config_override {
        let policy = PolicyFile::lock(&cfg, false)?;
        let settings = policy.snapshot()?;
        verify_approvals(&settings)?;
        let out = json!({
            "config": cfg,
            "default_mode": settings.default_mode.as_str(),
            "clients": settings.clients.iter().map(|c| json!({
                "id": c.id,
                "mode": c.mode.public_label(),
                "disabled": c.is_disabled(),
            })).collect::<Vec<_>>(),
        });
        if as_json {
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            println!("Config: {}", cfg.display());
            println!("Default mode: {}", settings.default_mode.as_str());
            println!("Static clients: {}", settings.clients.len());
        }
        return Ok(());
    }

    let reconcile = unified::ensure_reconciled(&home)?;
    let cfg = unified::config_path(&home);
    if reconcile == unified::ReconcileStatus::FreshEmpty {
        let out = json!({
            "initialized": false,
            "state_root": unified::state_root(&home),
            "default_mode": "standard",
            "runtime": "stopped",
            "legacy_service_active": legacy_unit_active,
            "legacy_managed_active": legacy_managed_active,
        });
        if as_json {
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            println!("Unified state: uninitialized (~/.local/state/veyl)");
            println!("Default mode: standard");
            println!("Runtime: stopped");
        }
        return Ok(());
    }

    let policy = PolicyFile::lock(&cfg, false)?;
    let settings = policy.snapshot()?;
    let audit_ok = verify_approvals(&settings).is_ok();
    drop(policy);

    let live = unified::is_serve_live(&home).unwrap_or(false);
    let runtime_info = unified::read_runtime_status(&home).ok().flatten();
    let (_, oauth_regs, _) = unified::fetch_oauth_registrations(&home, &settings)?;

    let out = json!({
        "initialized": true,
        "state_root": unified::state_root(&home),
        "default_mode": settings.default_mode.as_str(),
        "workspace": settings.workspace,
        "runtime": if live { if veyl_unit_active { "running (systemd veyl.service)" } else { "running (foreground)" } } else { "stopped" },
        "runtime_details": runtime_info,
        "audit_verified": audit_ok,
        "veyl_service_active": veyl_unit_active,
        "legacy_service_active": legacy_unit_active,
        "legacy_managed_active": legacy_managed_active,
        "static_clients": settings.clients.iter().map(|c| json!({
            "id": c.id,
            "mode": c.mode.public_label(),
            "disabled": c.is_disabled(),
        })).collect::<Vec<_>>(),
        "oauth_registrations": oauth_regs,
    });
    if as_json {
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }
    println!("State root: {}", unified::state_root(&home).display());
    println!("Default mode: {}", settings.default_mode.as_str());
    if let Some(ws) = &settings.workspace {
        println!("Workspace: {}", ws.display());
    }
    println!("Runtime: {}", out["runtime"].as_str().unwrap_or("stopped"));
    if let Some(info) = &runtime_info {
        if let Some(mcp) = info["mcp_listen"].as_str() {
            println!("MCP listen: {mcp}");
        }
        if let Some(admin) = info["admin_listen"].as_str() {
            println!("Dashboard: http://{admin}/dashboard");
        }
        if let Some(url) = info["public_mcp_url"].as_str() {
            println!(
                "Tunnel ({}): {url}",
                info["tunnel_provider"].as_str().unwrap_or("active")
            );
        }
    }
    if legacy_unit_active {
        println!("Warning: legacy mcp-gateway.service is active");
    }
    println!("Static clients ({}):", settings.clients.len());
    for c in &settings.clients {
        println!(
            "  {}  mode={}  {}",
            c.id,
            c.mode.public_label(),
            if c.is_disabled() { "disabled" } else { "enabled" }
        );
    }
    println!("OAuth clients ({}):", oauth_regs.len());
    for r in &oauth_regs {
        println!(
            "  {}  mode={}  active_families={}  name={}",
            r["client_id"].as_str().unwrap_or("?"),
            r["mode"].as_str().unwrap_or("standard"),
            r["active_families"].as_u64().unwrap_or(0),
            r["client_name"].as_str().unwrap_or("Unnamed"),
        );
    }
    Ok(())
}

pub(crate) fn clients(args: &[OsString]) -> Result<(), String> {
    if args.iter().any(|a| a == "--help") {
        println!("{CLIENTS_HELP}");
        return Ok(());
    }
    let home = unified::home_dir()?;
    let mut sub = "list";
    let mut target: Option<String> = None;
    let mut yes = false;
    let mut config_override: Option<PathBuf> = None;
    let mut idx = 0;
    if let Some(first) = args.first().and_then(|v| v.to_str())
        && matches!(first, "list" | "revoke")
    {
        sub = first;
        idx = 1;
    }
    let mut iter = args[idx..].iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--yes") => yes = true,
            Some("--config") if config_override.is_none() => {
                config_override = Some(PathBuf::from(iter.next().ok_or(CLIENTS_HELP)?));
            }
            Some(v) if sub == "revoke" && !v.starts_with('-') && target.is_none() => {
                target = Some(v.to_owned());
            }
            _ => return Err(CLIENTS_HELP.into()),
        }
    }

    let cfg = if let Some(explicit) = config_override {
        explicit
    } else {
        let status = unified::ensure_reconciled(&home)?;
        if status == unified::ReconcileStatus::FreshEmpty {
            if sub == "list" {
                println!("default_mode=standard");
                println!("No clients configured.");
                return Ok(());
            }
            return Err("No clients configured".into());
        }
        unified::config_path(&home)
    };

    let policy = PolicyFile::lock(&cfg, false)?;
    let settings = policy.snapshot()?;
    verify_approvals(&settings)?;
    drop(policy);
    let (live, regs, _) = unified::fetch_oauth_registrations(&home, &settings)?;

    if sub == "list" {
        println!("default_mode={}", settings.default_mode.as_str());
        for c in &settings.clients {
            println!(
                "{}\tstatic\t{}\t{}",
                c.id,
                c.mode.public_label(),
                if c.is_disabled() { "disabled" } else { "enabled" }
            );
        }
        for r in &regs {
            println!(
                "{}\toauth\t{}\tactive_families={}\t{}",
                r["client_id"].as_str().unwrap_or("?"),
                r["mode"].as_str().unwrap_or("standard"),
                r["active_families"].as_u64().unwrap_or(0),
                r["client_name"].as_str().unwrap_or("Unnamed"),
            );
        }
        return Ok(());
    }

    let query = target.ok_or("Specify client ID or unambiguous name to revoke")?;
    enum Kind {
        Static(String),
        OAuth(String),
    }
    let mut hits = Vec::new();
    if settings.clients.iter().any(|c| c.id == query) {
        hits.push(Kind::Static(query.clone()));
    }
    for r in &regs {
        if r["client_id"].as_str() == Some(query.as_str()) {
            hits.push(Kind::OAuth(query.clone()));
        }
    }
    if hits.is_empty() {
        for r in &regs {
            if r["client_name"].as_str() == Some(query.as_str())
                && let Some(cid) = r["client_id"].as_str()
            {
                hits.push(Kind::OAuth(cid.to_owned()));
            }
        }
    }
    let hit = match hits.len() {
        0 => return Err(format!("Unknown client: {query}")),
        1 => hits.into_iter().next().unwrap(),
        _ => return Err(format!("Ambiguous client '{query}'; specify exact client ID")),
    };

    match hit {
        Kind::Static(id) => {
            confirm_revoke(&format!("static client {id}"), yes)?;
            crate::mode_cli::transition::revoke_static_client(&cfg, &id)?;
            println!("Revoked static client {id} (disabled and demoted to Standard).");
            Ok(())
        }
        Kind::OAuth(cid) => {
            confirm_revoke(&format!("OAuth client {cid}"), yes)?;
            if live {
                let (status, body) = unified::send_control_command(
                    &home,
                    &json!({"action": "revoke", "client_id": cid, "confirm": true}),
                )?;
                if status != 200 || body["revoked"] != true {
                    return Err("Failed revoking live OAuth client".into());
                }
            } else {
                let oauth = settings
                    .oauth
                    .as_ref()
                    .ok_or("OAuth state not configured")?;
                if !oauth_http::revoke_stopped_client(&oauth.state_dir, &oauth.local_client, &cid)? {
                    return Err(format!("Unknown OAuth client: {cid}"));
                }
            }
            println!("Revoked OAuth client {cid} and all its token families.");
            Ok(())
        }
    }
}
