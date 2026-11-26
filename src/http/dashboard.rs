//! Local operator UI and API on the dedicated IPv4 loopback listener.

use std::collections::HashMap;
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode as Status, header};
use mcp_gateway::security::audit::AuditSink;
use mcp_gateway::security::policy::ExecutionMode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use super::operator::{PolicyFile, verify_approvals};
use super::{Reply, State, json_response, simple, unix_seconds};
use mcp_gateway::core::session::random_id;
use crate::tools::registry::Tool;

const COOKIE: &str = "mcp_dash_session";
const PAIR_TTL: u64 = 300;
const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const HELP: &str = "usage: veyl dashboard open [--remote] [--config PATH] | veyl dashboard <pair|servers> [--config PATH]";
const INDEX: &str = include_str!("dashboard/index.html");
const STYLE: &str = include_str!("dashboard/style.css");
const SCRIPT: &str = include_str!("dashboard/app.js");
const ICON: &str = include_str!("../../assets/veyl.svg");

pub(super) struct Admin {
    pub(super) addr: SocketAddr,
    config: PathBuf,
    sessions: Mutex<HashMap<String, AdminSession>>,
    cpu_sample: Mutex<Option<(Instant, u64)>>,
    pub(super) trace: Arc<std::sync::Mutex<super::trace::Trace>>,
    pub(super) activity: Arc<super::activity::Activity>,
    pub(super) installer: Arc<crate::upstream::installer::MarketplaceManager>,
}

struct AdminSession {
    created: Instant,
    csrf: String,
    remote: bool,
}

impl AdminSession {
    fn active_at(&self, now: Instant) -> bool {
        now.duration_since(self.created) < SESSION_TTL
    }
}

impl Admin {
    pub(super) fn new(addr: SocketAddr, config: PathBuf) -> Self {
        Self {
            addr,
            config,
            sessions: Mutex::new(HashMap::new()),
            cpu_sample: Mutex::new(None),
            trace: Arc::default(),
            activity: Arc::default(),
            installer: Arc::default(),
        }
    }
}

pub(super) fn parse_listen(raw: &Value) -> Result<SocketAddr, String> {
    let addr: SocketAddr = raw
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or("Invalid admin_listen address")?;
    if addr.ip() != Ipv4Addr::LOCALHOST {
        return Err("The admin listener must bind to 127.0.0.1".into());
    }
    Ok(addr)
}

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "open") {
        let mut remote = false;
        let mut config = None;
        let mut options = args[1..].iter();
        while let Some(option) = options.next() {
            match option.to_str() {
                Some("--remote") if !remote => remote = true,
                Some("--config") if config.is_none() => config = options.next(),
                _ => return Err(HELP.into()),
            }
        }
        let path = Path::new(config.ok_or(HELP)?);
        if rustix::process::geteuid().is_root() {
            return Err("Dashboard pairing requires the unprivileged gateway owner".into());
        }
        let (token, address) = {
            let policy = PolicyFile::lock(path, true)?;
            let settings = policy.snapshot()?;
            verify_approvals(&settings)?;
            let listen = settings
                .admin_listen
                .ok_or("Configure admin_listen before pairing")?;
            if listen.port() == 0 {
                return Err("Automatic opening requires a fixed admin port".into());
            }
            let address = if remote {
                format!(
                    "https://{}",
                    settings
                        .tailnet
                        .as_ref()
                        .ok_or("Private Tailscale dashboard is not configured")?
                        .authority(true)
                )
            } else {
                format!("http://{listen}")
            };
            let token = issue_pairing(&policy)?;
            (token, address)
        };
        // A fragment is never sent in the HTTP request. The dashboard removes
        // it before redeeming the single-use code through its normal POST.
        let url = format!("{address}/dashboard/login#pair={token}");
        std::process::Command::new("xdg-open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| "Cannot open the default browser; use veyl dashboard pair")?;
        println!("Opening {address}/dashboard");
        return Ok(());
    }
    let [operation, key, path] = args else {
        return Err(HELP.into());
    };
    if operation == "servers" && key == "--config" {
        println!(
            "{}",
            crate::upstream::admin::manage(Path::new(path), &["list"])?
        );
        return Ok(());
    }
    if operation != "pair" || key != "--config" || rustix::process::geteuid().is_root() {
        return Err(HELP.into());
    }
    let policy = PolicyFile::lock(Path::new(path), true)?;
    let settings = policy.snapshot()?;
    if settings.admin_listen.is_none() {
        return Err("Configure admin_listen before pairing".into());
    }
    verify_approvals(&settings)?;
    let token = issue_pairing(&policy)?;
    println!("PAIRING_TOKEN={token}");
    eprintln!(
        "Open /dashboard at ADMIN_HTTP_LISTEN and enter this one-time code within five minutes."
    );
    Ok(())
}

pub(crate) fn issue_pairing(policy: &PolicyFile) -> Result<String, String> {
    let token = random_id::<24>().map_err(|_| "Secure randomness unavailable")?;
    let expiry = unix_seconds() + PAIR_TTL;
    policy
        .write_pairing(format!("{expiry} {}", digest(&token)).as_bytes())
        .map_err(|_| "Cannot persist the pairing verifier")?;
    Ok(token)
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn redeem(config: &Path, token: &str) -> Result<bool, String> {
    let policy = PolicyFile::lock(config, true)?;
    let Ok(record) = policy.read_pairing() else {
        return Ok(false);
    };
    let valid = record.split_once(' ').is_some_and(|(expiry, hash)| {
        expiry
            .parse::<u64>()
            .is_ok_and(|time| unix_seconds() < time)
            && bool::from(digest(token).as_bytes().ct_eq(hash.as_bytes()))
    });
    if valid {
        policy
            .consume_pairing()
            .map_err(|_| "Pairing storage unavailable")?;
    }
    Ok(valid)
}

pub(super) async fn serve(request: Request<Incoming>, state: Arc<State>) -> Reply {
    let mut reply = route(request, &state).await;
    for (name, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    ] {
        reply
            .headers_mut()
            .insert(name, header::HeaderValue::from_static(value));
    }
    reply
}

async fn route(request: Request<Incoming>, state: &Arc<State>) -> Reply {
    let Some(admin) = &state.admin else {
        return missing();
    };
    let local = admin.addr.to_string();
    let tail = state
        .tailnet
        .as_ref()
        .map(|settings| settings.authority(true));
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let remote = tail.as_deref() == Some(host);
    if request.uri().authority().is_some()
        || request.headers().get_all(header::HOST).iter().count() != 1
        || request.headers().contains_key("Tailscale-Funnel-Request")
        || !(host == local || remote)
    {
        return simple(Status::BAD_REQUEST, "Invalid Host");
    }
    if state.diagnostic_only {
        return unavailable();
    }
    let method = request.method().clone();
    let path = request
        .uri()
        .path()
        .strip_prefix("/dashboard/api/")
        .map_or_else(
            || request.uri().path().to_owned(),
            |rest| format!("/api/dashboard/{rest}"),
        );
    let query = request.uri().query().unwrap_or_default().to_owned();
    // The MCP listener is another Veyl-controlled origin with only bearer-authenticated JSON-RPC.
    // Browser requests from any other origin never reach pairing or state changes.
    if method == Method::POST {
        let scheme = if remote { "https" } else { "http" };
        let admin_origin = format!("{scheme}://{host}");
        let mcp_origin = format!("http://{}", state.addr);
        if request.headers().get_all(header::ORIGIN).iter().count() != 1
            || request.headers().get(header::ORIGIN).is_none_or(|origin| {
                origin.as_bytes() != admin_origin.as_bytes()
                    && (remote
                        || origin.as_bytes() != mcp_origin.as_bytes()
                        || request.headers().contains_key("sec-fetch-site"))
            })
        {
            return forbidden();
        }
    }
    if request
        .headers()
        .get("sec-fetch-site")
        .is_some_and(|site| site == "cross-site")
    {
        return forbidden();
    }
    if method == Method::GET {
        match path.as_str() {
            "/dashboard/login" => return asset(INDEX, "text/html; charset=utf-8"),
            "/dashboard/style.css" => return asset(STYLE, "text/css; charset=utf-8"),
            "/dashboard/app.js" => return asset(SCRIPT, "text/javascript; charset=utf-8"),
            "/dashboard/icon.svg" | "/favicon.ico" => return asset(ICON, "image/svg+xml"),
            "/dashboard" if query.starts_with("token=") => {
                return if remote {
                    redirect("/dashboard/login")
                } else {
                    pair(admin, &query[6..], true, false).await
                };
            }
            "/" => return redirect("/dashboard"),
            _ => {}
        }
    }
    if method == Method::POST && path == "/api/dashboard/pair" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        return pair(
            admin,
            body["pairing_token"].as_str().unwrap_or_default(),
            false,
            remote,
        )
        .await;
    }
    if remote && method == Method::GET && path == "/dashboard" {
        return asset(INDEX, "text/html; charset=utf-8");
    }
    let key = request
        .headers()
        .get(header::COOKIE)
        .and_then(|cookie| cookie.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                (name == COOKIE && secret_format(value)).then_some(value)
            })
        });
    let csrf = {
        let mut sessions = admin.sessions.lock().await;
        let now = Instant::now();
        sessions.retain(|_, session| session.active_at(now));
        let Some(session) = key
            .and_then(|key| sessions.get(key))
            .filter(|session| session.remote == remote)
        else {
            return if method == Method::GET && path == "/dashboard" {
                redirect("/dashboard/login")
            } else {
                simple(Status::UNAUTHORIZED, "Pair to open the dashboard")
            };
        };
        session.csrf.clone()
    };
    if method == Method::GET && path == "/dashboard" {
        return asset(INDEX, "text/html; charset=utf-8");
    }
    let csrf_matches = request.headers().get_all("X-CSRF-Token").iter().count() == 1
        && request
            .headers()
            .get("X-CSRF-Token")
            .is_some_and(|value| bool::from(value.as_bytes().ct_eq(csrf.as_bytes())));
    if remote && !csrf_matches {
        return simple(Status::UNAUTHORIZED, "Pair this browser tab");
    }
    if method == Method::POST && path == "/api/dashboard/logout" {
        // This endpoint can only end the caller's own session. Exact Origin is required.
        if let Some(key) = key {
            admin.sessions.lock().await.remove(key);
        }
        if let Ok(mut trace) = admin.trace.lock() {
            trace.set(&csrf, false);
        }
        return cookie(ok(json!({"signed_out": true})), "", 0);
    }
    if method == Method::POST && !csrf_matches {
        return forbidden();
    }
    if path == "/api/dashboard/trace" {
        // Raw command/response previews are explicitly enabled by one
        // paired loopback operator session. Never expose them over Tailnet.
        if remote || !csrf_matches {
            return forbidden();
        }
        if method == Method::GET {
            return match admin.trace.lock() {
                Ok(mut trace) => ok(trace.view(&csrf, parameter(&query, "metadata") != Some("1"))),
                Err(_) => unavailable(),
            };
        }
        if method == Method::POST {
            let Ok(data) = body(request).await else {
                return bad();
            };
            let Some(enabled) = data["enabled"].as_bool() else {
                return bad();
            };
            if data["confirm"] != true {
                return forbidden();
            }
            return match admin.trace.lock() {
                Ok(mut trace) => {
                    if !trace.set(&csrf, enabled) {
                        return simple(Status::CONFLICT, "Trace belongs to another local session");
                    }
                    trace.schedule_expiry(&admin.trace);
                    ok(trace.view(&csrf, false))
                }
                Err(_) => unavailable(),
            };
        }
        return bad();
    }
    if method == Method::GET && path == "/api/dashboard/integrations" {
        let config = admin.config.clone();
        let tailnet = state.tailnet.clone();
        let service = tokio::task::spawn_blocking(crate::service_cli::health);
        let routes =
            tokio::task::spawn_blocking(move || crate::tailnet::health(&config, tailnet.as_ref()));
        return match (service.await, routes.await) {
            (Ok(service), Ok(routes)) => ok(json!({"service":service,"tailscale":routes})),
            _ => unavailable(),
        };
    }
    if method == Method::GET && path == "/api/dashboard/status" {
        return status(state, admin, csrf).await;
    }
    if method == Method::GET && path == "/api/dashboard/servers" {
        return manage(admin, vec!["list".into()], crate::upstream::admin::manage).await;
    }
    if method == Method::GET && path == "/api/dashboard/marketplace" {
        return asset(
            include_str!("dashboard/marketplace.json"),
            "application/json; charset=utf-8",
        );
    }
    if method == Method::GET && path == "/api/dashboard/marketplace/state" {
        let installer = Arc::clone(&admin.installer);
        let config = admin.config.clone();
        return match tokio::task::spawn_blocking(move || installer.state(&config)).await {
            Ok(Ok(val)) => ok(val),
            Ok(Err(err)) => json_response(Status::BAD_REQUEST, json!({"error": err}), None),
            Err(_) => unavailable(),
        };
    }
    if method == Method::POST && path == "/api/dashboard/marketplace/install" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        if body["confirm"] != true {
            return forbidden();
        }
        let Ok(req) = serde_json::from_value::<crate::upstream::installer::InstallRequest>(body)
        else {
            return bad();
        };
        return match admin.installer.start_async(admin.config.clone(), req) {
            Ok(op_id) => ok(json!({"accepted": true, "op_id": op_id})),
            Err(err) => json_response(Status::BAD_REQUEST, json!({"error": err}), None),
        };
    }
    if method == Method::POST && path == "/api/dashboard/marketplace/configure" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        if body["confirm"] != true {
            return forbidden();
        }
        let Some(id) = body["id"].as_str().map(str::to_owned) else {
            return bad();
        };
        let families = body
            .get("tool_families")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let enabled = body.get("enabled").and_then(Value::as_bool);
        let config = admin.config.clone();
        return match tokio::task::spawn_blocking(move || {
            crate::upstream::installer::configure(&config, &id, families.as_deref(), enabled)
        })
        .await
        {
            Ok(Ok(val)) => ok(val),
            Ok(Err(err)) => json_response(Status::BAD_REQUEST, json!({"error": err}), None),
            Err(_) => unavailable(),
        };
    }
    if method == Method::POST && path == "/api/dashboard/marketplace/uninstall" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        if body["confirm"] != true {
            return forbidden();
        }
        let Some(id) = body["id"].as_str().map(str::to_owned) else {
            return bad();
        };
        let config = admin.config.clone();
        return match tokio::task::spawn_blocking(move || {
            crate::upstream::installer::uninstall(&config, &id)
        })
        .await
        {
            Ok(Ok(val)) => ok(val),
            Ok(Err(err)) => json_response(Status::BAD_REQUEST, json!({"error": err}), None),
            Err(_) => unavailable(),
        };
    }
    if method == Method::POST && path == "/api/dashboard/marketplace/cancel" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        if body["confirm"] != true {
            return forbidden();
        }
        let Some(op_id) = body["op_id"].as_str() else {
            return bad();
        };
        return match admin.installer.cancel(op_id) {
            Ok(cancelled) => ok(json!({"cancelled": cancelled, "op_id": op_id})),
            Err(err) => json_response(Status::BAD_REQUEST, json!({"error": err}), None),
        };
    }
    if method == Method::POST && path == "/api/dashboard/marketplace/recover" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        if body["confirm"] != true {
            return forbidden();
        }
        let installer = Arc::clone(&admin.installer);
        let config = admin.config.clone();
        return match tokio::task::spawn_blocking(move || installer.state(&config)).await {
            Ok(Ok(val)) => ok(val),
            Ok(Err(err)) => json_response(Status::BAD_REQUEST, json!({"error": err}), None),
            Err(_) => unavailable(),
        };
    }
    if method == Method::POST && path == "/api/dashboard/clients/grants" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        if body["confirm"] != true || (remote && body.get("timeshift_retention_count").is_some()) {
            return forbidden();
        }
        let config = admin.config.clone();
        return match tokio::task::spawn_blocking(move || {
            crate::upstream::installer::update_client_grants(&config, &body)
        })
        .await
        {
            Ok(Ok(val)) => ok(val),
            Ok(Err(err)) => json_response(Status::BAD_REQUEST, json!({"error": err}), None),
            Err(_) => unavailable(),
        };
    }
    if method == Method::GET && path == "/api/dashboard/requests" {
        return match crate::tools::extensions::list_requests(&admin.config) {
            Ok(list) => ok(json!({"requests": list, "count": list.len()})),
            Err(_) => unavailable(),
        };
    }
    if method == Method::POST && path == "/api/dashboard/requests" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        if body["confirm"] != true || body["action"].as_str() != Some("dismiss") {
            return forbidden();
        }
        let Some(id) = body["id"].as_str() else {
            return bad();
        };
        return match crate::tools::extensions::dismiss_request(&admin.config, id) {
            Ok(removed) => ok(json!({"dismissed": removed, "id": id})),
            Err(_) => bad(),
        };
    }
    if method == Method::GET && path == "/api/dashboard/diagnostics" {
        if remote || !csrf_matches {
            return forbidden();
        }
        let Some(section) = parameter(&query, "section").map(str::to_owned) else {
            return bad();
        };
        return match tokio::task::spawn_blocking(move || {
            crate::inspection::local_diagnostics(&section)
        })
        .await
        {
            Ok(Ok(value)) => ok(value),
            Ok(Err(_)) => bad(),
            Err(_) => unavailable(),
        };
    }
    if method == Method::POST && path == "/api/dashboard/servers" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        if body["confirm"] != true {
            return forbidden();
        }
        let action = body["action"].as_str().unwrap_or_default();
        if remote && matches!(action, "workspace" | "workspace-folder" | "unworkspace") {
            return forbidden();
        }
        let fields = match action {
            "workspace" | "workspace-folder" => &["client", "id", "root"][..],
            "unworkspace" => &["client", "id"][..],
            "probe" | "enable" | "disable" | "remove" => &["id"][..],
            "add-http" => &["id", "url"],
            "add-stdio" | "add-bundle" => &["id", "command"],
            "grant" | "revoke" => &["client", "id", "tool"],
            _ => return bad(),
        };
        let Some(values) = fields
            .iter()
            .map(|key| body[*key].as_str())
            .collect::<Option<Vec<_>>>()
        else {
            return bad();
        };
        let mut args: Vec<_> = std::iter::once(action)
            .chain(values)
            .map(str::to_owned)
            .collect();
        if matches!(action, "add-stdio" | "add-bundle") {
            let Some(argv) = body["arguments"].as_array() else {
                return bad();
            };
            for arg in argv {
                let Some(arg) = arg.as_str() else {
                    return bad();
                };
                args.push(arg.to_owned());
            }
        }
        if action == "add-http"
            && let Some(address) = body["connect_ip"]
                .as_str()
                .filter(|value| !value.is_empty())
        {
            args.push(address.to_owned());
        }
        return manage(admin, args, crate::upstream::admin::manage).await;
    }
    if method == Method::GET && path == "/api/dashboard/skills" {
        return manage(admin, vec!["list".into()], crate::skills_cli::manage).await;
    }
    if method == Method::GET && path == "/api/dashboard/skills/read" {
        let Some(name) = parameter(&query, "name") else {
            return bad();
        };
        return manage(
            admin,
            vec!["read".into(), name.into()],
            crate::skills_cli::manage,
        )
        .await;
    }
    if method == Method::POST && path == "/api/dashboard/skills" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        let action = body["action"].as_str().unwrap_or_default();
        if body["confirm"] != true {
            return forbidden();
        }
        let fields = match action {
            "import" => &["source"][..],
            "enable" | "disable" => &["name"],
            "grant" | "revoke" => &["client", "name"],
            _ => return bad(),
        };
        let Some(values) = fields
            .iter()
            .map(|key| body[*key].as_str())
            .collect::<Option<Vec<_>>>()
        else {
            return bad();
        };
        let params = std::iter::once(action)
            .chain(values)
            .map(str::to_owned)
            .collect();
        return manage(admin, params, crate::skills_cli::manage).await;
    }
    if method == Method::GET && path == "/api/dashboard/activity" {
        let include_funnel = parameter(&query, "funnel") == Some("1");
        return admin
            .activity
            .view(include_funnel)
            .map_or_else(unavailable, ok);
    }
    if method == Method::GET && path == "/api/dashboard/audit" {
        let result = with_policy(admin, |settings| {
            let path = settings.audit_log.as_deref().ok_or(Status::NOT_FOUND)?;
            AuditSink::recent(path)
                .map(|events| json!({"events": events}))
                .map_err(|_| Status::SERVICE_UNAVAILABLE)
        })
        .await;
        return result;
    }
    if method == Method::GET && path == "/api/dashboard/jobs" {
        let Some(client) = parameter(&query, "client") else {
            return bad();
        };
        let cursor = parameter(&query, "cursor").unwrap_or_default().to_owned();
        return job_request(state, client, None, move |jobs, client, _| {
            jobs.list_admin(client, &cursor)
        })
        .await;
    }
    if method == Method::GET
        && let Some(id) = path
            .strip_prefix("/api/dashboard/jobs/")
            .and_then(|path| path.strip_suffix("/logs"))
    {
        let Some(client) = parameter(&query, "client") else {
            return missing();
        };
        return job_request(state, client, Some(id), |jobs, client, id| {
            let empty = serde_json::Map::new();
            jobs.owned_tool(Tool::JobLogs, id, client, &empty)
        })
        .await;
    }
    if method == Method::POST && path == "/api/dashboard/jobs/cancel" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        let (Some(client), Some(id), Some(true)) = (
            body["client"].as_str(),
            body["job_id"].as_str(),
            body["confirm"].as_bool(),
        ) else {
            return bad();
        };
        return job_request(state, client, Some(id), |jobs, client, id| {
            let empty = serde_json::Map::new();
            jobs.owned_tool(Tool::CancelJob, id, client, &empty)
        })
        .await;
    }
    missing()
}

async fn pair(admin: &Admin, token: &str, navigate: bool, remote: bool) -> Reply {
    if !secret_format(token) {
        return simple(Status::UNAUTHORIZED, "Invalid or expired pairing code");
    }
    let (Ok(session), Ok(csrf)) = (random_id::<24>(), random_id::<24>()) else {
        return unavailable();
    };
    let config = admin.config.clone();
    let token = token.to_owned();
    pair_with_ids(admin, navigate, remote, session, csrf, move || redeem(&config, &token)).await
}

async fn pair_with_ids(
    admin: &Admin,
    navigate: bool,
    remote: bool,
    session: String,
    csrf: String,
    redeem_pair: impl FnOnce() -> Result<bool, String> + Send + 'static,
) -> Reply {
    let mut sessions = admin.sessions.lock().await;
    sessions.retain(|_, session| session.created.elapsed() < SESSION_TTL);
    if sessions.len() >= 16 || sessions.contains_key(&session) {
        return unavailable();
    }
    match tokio::task::spawn_blocking(redeem_pair).await {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return simple(Status::UNAUTHORIZED, "Invalid or expired pairing code"),
        _ => return unavailable(),
    }
    sessions.insert(
        session.clone(),
        AdminSession {
            created: Instant::now(),
            csrf: csrf.clone(),
            remote,
        },
    );
    let reply = if navigate {
        redirect("/dashboard")
    } else {
        ok(json!({"csrf": csrf}))
    };
    cookie(reply, &session, SESSION_TTL.as_secs())
}

async fn status(state: &State, admin: &Admin, csrf: String) -> Reply {
    let mut counts = HashMap::new();
    {
        let sessions = state.sessions.lock().await;
        for session in sessions
            .values()
            .filter(|s| s.is_live())
        {
            *counts.entry(session.owner().clone()).or_insert(0) += 1;
        }
    }
    let connected: usize = counts.values().sum();
    let cpu = std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|stat| {
            let (_, fields) = stat.rsplit_once(')')?;
            let mut fields = fields.split_ascii_whitespace();
            let user = fields.nth(11)?.parse::<u64>().ok()?;
            let system = fields.next()?.parse::<u64>().ok()?;
            user.checked_add(system)
        });
    let cpu_percent = {
        let mut last = admin.cpu_sample.lock().await;
        cpu.and_then(|ticks| {
            let now = Instant::now();
            last.replace((now, ticks)).and_then(|(then, before)| {
                let samples = now.duration_since(then).as_secs_f64()
                    * rustix::param::clock_ticks_per_second() as f64;
                (samples > 0.0).then(|| 100.0 * ticks.saturating_sub(before) as f64 / samples)
            })
        })
    };
    let rss_kib = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|line| line.strip_prefix("VmRSS:"))?
                .split_ascii_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        });
    let jobs_configured = state.jobs.is_some();
    let listener = state.addr;
    let active_tcp = super::MAX_CONNECTIONS - state.mcp_connections.available_permits();
    let (active_calls, active_tools) = match admin.activity.active_summary() {
        Some((count, tools)) => (Some(count), tools),
        None => (None, Vec::new()),
    };
    let config = admin.config.clone();
    with_policy(admin, move |settings| {
        let clients: Vec<_> = settings.clients.iter().map(|client| json!({
            "id": client.id,
            "disabled": client.is_disabled(),
            "mode": client.mode.public_label(),
            "native_tool_preset": client.native_tool_preset,
            "timeshift_retention_count": client.timeshift_retention_count,
            "grants": Tool::ALL.into_iter().filter(|tool| client.tools.contains(tool)).map(Tool::name).collect::<Vec<_>>(),
            "connections": counts.get(&client.id).copied().unwrap_or_default(),
            "skills": client.skills,
            "upstreams": client.upstreams.servers,
            "upstream_tools": client.upstreams.tools,
            "upstream_workspaces": client.upstreams.workspace_metadata(),
            "expired": client.expires_at <= unix_seconds()
        })).collect();
        let audit = settings.audit_log.as_deref().map(|path| if AuditSink::inspect(path, false).is_ok() { "verified" } else { "unavailable" });
        let broad = settings.clients.iter().any(|client| client.mode == ExecutionMode::BroadYolo);
        let layout = if broad {
            if crate::state_cli::Layout::admission(&config, &settings).is_ok() { "Valid" } else { "Invalid" }
        } else {
            "Broad YOLO inactive"
        };
        use crate::protected_paths::{Kind, OPTIONAL_DEFAULTS, READONLY_DEFAULTS};
        let protected = |kind| settings.protected_paths.selected(kind).iter()
            .map(|rule| &rule.path).collect::<Vec<_>>();
        let all_tools: Vec<_> = Tool::ALL
            .into_iter()
            .map(|t| {
                json!({
                    "name": t.name(),
                    "yolo_preset": t.in_yolo_preset(settings.jobs.is_some(), settings.skills.is_some()),
                    "git": t.is_git(),
                    "extension": t.is_extension(),
                    "process": t.process_control(),
                })
            })
            .collect();
        Ok(json!({
            "clients": clients, "all_tools": all_tools, "sessions": connected, "connections": active_tcp, "active_calls": active_calls, "active_tools": active_tools, "cpu_percent": cpu_percent, "rss_kib": rss_kib,
            "csrf": csrf, "listener": listener.to_string(), "audit": audit,
            "jobs_configured": jobs_configured, "job_state_dir": settings.job_state_path(), "audit_log": settings.audit_log,
            "version": env!("CARGO_PKG_VERSION"), "skills_configured": settings.skills.is_some(),
            "configuration": {
                "authorization": if settings.managed { "Managed" } else { "Legacy" },
                "broad_state_layout": layout,
                "configured_job_profiles": settings.jobs.is_some(),
                "configured_skills_store": settings.skills.is_some(),
            },
            "protected_paths": {
                "state_directory": broad.then(|| config.parent()).flatten(),
                "default_masked": OPTIONAL_DEFAULTS,
                "default_readonly": READONLY_DEFAULTS,
                "extra_masked": protected(Kind::Optional),
                "extra_readonly": protected(Kind::ReadOnly),
                "skills_directory": settings.skills.as_ref().map(|skills| skills.path()),
            },
        }))
    }).await
}

async fn with_policy(
    admin: &Admin,
    f: impl FnOnce(super::Configuration) -> Result<Value, Status> + Send + 'static,
) -> Reply {
    let config = admin.config.clone();
    tokio::task::spawn_blocking(move || {
        let result = {
            let policy =
                PolicyFile::lock(&config, false).map_err(|_| Status::SERVICE_UNAVAILABLE)?;
            let settings = policy.snapshot().map_err(|_| Status::SERVICE_UNAVAILABLE)?;
            verify_approvals(&settings).map_err(|_| Status::SERVICE_UNAVAILABLE)?;
            settings
        };
        f(result)
    })
    .await
    .unwrap_or(Err(Status::SERVICE_UNAVAILABLE))
    .map_or_else(
        |code| simple(code, code.canonical_reason().unwrap_or("Gateway error")),
        ok,
    )
}

async fn manage(
    admin: &Admin,
    args: Vec<String>,
    action: fn(&Path, &[&str]) -> Result<Value, String>,
) -> Reply {
    let config = admin.config.clone();
    match tokio::task::spawn_blocking(move || {
        action(
            &config,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        )
    })
    .await
    {
        Ok(Ok(value)) => ok(value),
        Ok(Err(error)) => json_response(Status::BAD_REQUEST, json!({"error":error}), None),
        Err(_) => unavailable(),
    }
}

async fn job_request(
    state: &Arc<State>,
    client: &str,
    job_id: Option<&str>,
    perform: impl FnOnce(&crate::jobs::Jobs, &str, &str) -> std::io::Result<Value> + Send + 'static,
) -> Reply {
    let snapshot = Arc::clone(state);
    let Some(admin) = &state.admin else {
        return missing();
    };
    let client = client.to_owned();
    let id = job_id.unwrap_or_default().to_owned();
    with_policy(admin, move |settings| {
        if !settings.clients.iter().any(|entry| entry.id == client) {
            return Err(Status::NOT_FOUND);
        }
        let jobs = snapshot.jobs.as_ref().ok_or(Status::NOT_FOUND)?;
        let value = perform(jobs, &client, &id).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::PermissionDenied => Status::NOT_FOUND,
            _ => Status::SERVICE_UNAVAILABLE,
        })?;
        if value.to_string().len() > 65_536 {
            return Err(Status::PAYLOAD_TOO_LARGE);
        }
        Ok(value)
    })
    .await
}

async fn body(request: Request<Incoming>) -> Result<Value, ()> {
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .is_none_or(|value| value != "application/json")
    {
        return Err(());
    }
    let bytes = super::bounded_body(request.into_body(), 8192)
        .await
        .map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn parameter<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|item| {
        let (name, value) = item.split_once('=')?;
        (name == key
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
        .then_some(value)
    })
}

fn secret_format(value: &str) -> bool {
    value.len() == 48 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn redirect(location: &'static str) -> Reply {
    let mut reply = simple(Status::SEE_OTHER, "See other");
    reply
        .headers_mut()
        .insert(header::LOCATION, header::HeaderValue::from_static(location));
    reply
}

fn asset(content: &'static str, content_type: &'static str) -> Reply {
    let mut reply = simple(Status::OK, content);
    reply.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    reply
}

fn cookie(mut reply: Reply, id: &str, age: u64) -> Reply {
    if let Ok(value) = header::HeaderValue::from_str(&format!(
        "{COOKIE}={id}; Max-Age={age}; Path=/dashboard; HttpOnly; Secure; SameSite=Strict"
    )) {
        reply.headers_mut().insert(header::SET_COOKIE, value);
    }
    reply
}

fn ok(value: Value) -> Reply {
    json_response(Status::OK, value, None)
}
fn missing() -> Reply {
    simple(Status::NOT_FOUND, "Not found")
}
fn forbidden() -> Reply {
    simple(Status::FORBIDDEN, "Forbidden")
}
fn unavailable() -> Reply {
    simple(Status::SERVICE_UNAVAILABLE, "Gateway data unavailable")
}
fn bad() -> Reply {
    simple(Status::BAD_REQUEST, "Invalid request")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_pair_collision_preserves_existing_session() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let admin = Admin::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
            let id = "a".repeat(48);
            let created = Instant::now();
            admin.sessions.lock().await.insert(id.clone(), AdminSession {
                created, csrf: "original".into(), remote: false,
            });
            let redeemed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed = redeemed.clone();
            let reply = pair_with_ids(&admin, false, true, id.clone(), "replacement".into(), move || {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(true)
            }).await;
            assert_eq!(reply.status(), Status::SERVICE_UNAVAILABLE);
            assert!(!reply.headers().contains_key(header::SET_COOKIE));
            assert!(!redeemed.load(std::sync::atomic::Ordering::SeqCst));
            let sessions = admin.sessions.lock().await;
            assert_eq!(sessions.len(), 1);
            let previous = &sessions[&id];
            assert_eq!(previous.created, created);
            assert_eq!(previous.csrf, "original");
            assert!(!previous.remote);
            drop(sessions);
            // Positive control: the same successful redemption creates a fresh session.
            let fresh = "b".repeat(48);
            let reply = pair_with_ids(&admin, false, true, fresh.clone(), "new".into(), || Ok(true)).await;
            assert_eq!(reply.status(), Status::OK);
            assert!(reply.headers().contains_key(header::SET_COOKIE));
            let sessions = admin.sessions.lock().await;
            assert_eq!(sessions.len(), 2);
            assert_eq!(sessions[&fresh].csrf, "new");
            assert!(sessions[&fresh].remote);
        });
    }

    #[test]
    fn dashboard_session_expires_at_its_ttl() {
        let created = Instant::now();
        let session = AdminSession {
            created,
            csrf: String::new(),
            remote: true,
        };
        assert!(session.active_at(created + SESSION_TTL - Duration::from_secs(1)));
        assert!(!session.active_at(created + SESSION_TTL));
    }
}
