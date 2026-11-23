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
use super::{Reply, SESSION_IDLE, State, json_response, new_session_id, simple, unix_seconds};
use crate::tools::registry::Tool;

const COOKIE: &str = "mcp_dash_session";
const PAIR_TTL: u64 = 300;
const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const HELP: &str = "usage: mcp-gateway dashboard <pair|servers> --config PATH";
const INDEX: &str = include_str!("dashboard/index.html");
const STYLE: &str = include_str!("dashboard/style.css");
const SCRIPT: &str = include_str!("dashboard/app.js");

pub(super) struct Admin {
    pub(super) addr: SocketAddr,
    config: PathBuf,
    sessions: Mutex<HashMap<String, AdminSession>>,
    cpu_sample: Mutex<Option<(Instant, u64)>>,
}

struct AdminSession {
    created: Instant,
    csrf: String,
    remote: bool,
}

impl Admin {
    pub(super) fn new(addr: SocketAddr, config: PathBuf) -> Self {
        Self {
            addr,
            config,
            sessions: Mutex::new(HashMap::new()),
            cpu_sample: Mutex::new(None),
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
    let token = new_session_id().map_err(|_| "Secure randomness unavailable")?;
    let expiry = unix_seconds() + PAIR_TTL;
    policy
        .write_pairing(format!("{expiry} {}", digest(&token)).as_bytes())
        .map_err(|_| "Cannot persist the pairing verifier")?;
    println!("PAIRING_TOKEN={token}");
    eprintln!(
        "Open /dashboard at ADMIN_HTTP_LISTEN and enter this one-time code within five minutes."
    );
    Ok(())
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
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
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
        sessions.retain(|_, session| session.created.elapsed() < SESSION_TTL);
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
        return cookie(ok(json!({"signed_out": true})), "", 0);
    }
    if method == Method::POST && !csrf_matches {
        return forbidden();
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
    if method == Method::POST && path == "/api/dashboard/servers" {
        let Ok(body) = body(request).await else {
            return bad();
        };
        if body["confirm"] != true {
            return forbidden();
        }
        let action = body["action"].as_str().unwrap_or_default();
        let fields = match action {
            "probe" | "enable" | "disable" | "remove" => &["id"][..],
            "add-http" => &["id", "url"],
            "add-stdio" => &["id", "command"],
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
        if action == "add-stdio" {
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
            jobs.list(client, &cursor)
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
            jobs.owned_tool(Tool::JobLogs, id, client)
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
            jobs.owned_tool(Tool::CancelJob, id, client)
        })
        .await;
    }
    missing()
}

async fn pair(admin: &Admin, token: &str, navigate: bool, remote: bool) -> Reply {
    if !secret_format(token) {
        return simple(Status::UNAUTHORIZED, "Invalid or expired pairing code");
    }
    let config = admin.config.clone();
    let token = token.to_owned();
    let (Ok(session), Ok(csrf)) = (new_session_id(), new_session_id()) else {
        return unavailable();
    };
    let mut sessions = admin.sessions.lock().await;
    sessions.retain(|_, session| session.created.elapsed() < SESSION_TTL);
    if sessions.len() >= 16 {
        return unavailable();
    }
    match tokio::task::spawn_blocking(move || redeem(&config, &token)).await {
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
            .filter(|s| s.last_used.elapsed() < SESSION_IDLE)
        {
            *counts.entry(session.owner.clone()).or_insert(0) += 1;
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
    with_policy(admin, move |settings| {
        let clients: Vec<_> = settings.clients.iter().map(|client| json!({
            "id": client.id,
            "mode": match client.mode {
                ExecutionMode::Standard => "standard",
                ExecutionMode::PersistentYolo => "scoped_yolo",
                ExecutionMode::BroadYolo => "broad_yolo",
                ExecutionMode::Full => "full",
                _ => "disabled",
            },
            "grants": client.actions.iter().map(|action| format!("{action:?}")).collect::<Vec<_>>(),
            "connections": counts.get(&client.id).copied().unwrap_or_default(),
            "skills": client.skills,
            "upstreams": client.upstreams.servers,
            "upstream_tools": client.upstreams.tools,
            "expired": client.expires_at <= unix_seconds()
        })).collect();
        let audit = settings.audit_log.as_deref().map(|path| if AuditSink::inspect(path, false).is_ok() { "verified" } else { "unavailable" });
        Ok(json!({
            "clients": clients, "sessions": connected, "connections": active_tcp, "cpu_percent": cpu_percent, "rss_kib": rss_kib,
            "csrf": csrf, "listener": listener.to_string(), "audit": audit,
            "jobs_configured": jobs_configured, "job_state_dir": settings.job_state_path(), "audit_log": settings.audit_log,
            "version": env!("CARGO_PKG_VERSION"), "skills_configured": settings.skills.is_some(),
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
