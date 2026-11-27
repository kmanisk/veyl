//! Explicitly launched, loopback-only authenticated MCP-over-HTTP transport.
//! No persistent unit, public listener, or privileged operation is created.

#[cfg(target_os = "linux")]
mod activity;
pub(crate) mod admission;
#[cfg(target_os = "linux")]
pub(crate) mod dashboard;
#[cfg(target_os = "linux")]
pub(crate) mod funnel;
#[cfg(target_os = "linux")]
pub(crate) mod operator;
#[cfg(target_os = "linux")]
mod oauth;
#[cfg(target_os = "linux")]
pub(crate) mod scope;
#[cfg(target_os = "linux")]
mod trace;

use std::collections::HashMap;
use std::convert::Infallible;
use std::ffi::OsString;
use std::future::{Future, poll_fn};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
#[cfg(target_os = "linux")]
use hyper::body::Body as _;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore, watch};
use tokio::task::JoinSet;

use mcp_gateway::security::policy::{self, Action, ExecutionMode, Grant, PolicyInput};
use mcp_gateway::http_common::{one, one_value};

use crate::file_access::FileAccess;
#[cfg(target_os = "linux")]
use crate::jobs::{JobPolicy, Jobs, OAuthSessionAuthorization, SessionAuthorization};
use crate::protocol::Protocol;
use crate::tools::mutation::MutationAudit;
#[cfg(not(target_os = "linux"))]
use crate::tools::registry::read_file;
use crate::tools::registry::{Tool, tool_text};

#[cfg(not(target_os = "linux"))]
use admission::load_clients;
use admission::{Client, Configuration, authenticate};
#[cfg(target_os = "linux")]
use mcp_gateway::core::oauth::ConnectionMode;
#[cfg(target_os = "linux")]
use mcp_gateway::security::audit::AuditPhase;

#[cfg(target_os = "linux")]
enum ResolvedClient<'a> {
    Borrowed(&'a Client),
    Owned(Box<Client>),
}

#[cfg(target_os = "linux")]
impl std::ops::Deref for ResolvedClient<'_> {
    type Target = Client;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(client) => client,
            Self::Owned(client) => client,
        }
    }
}

#[cfg(target_os = "linux")]
async fn handle_control_stream(
    stream: tokio::net::UnixStream,
    state: Arc<State>,
    shutdown: tokio::sync::mpsc::Sender<()>,
) {
    let mut input = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(Ok(())) = tokio::time::timeout_at(deadline, stream.readable()).await {
        let mut buf = [0u8; 1024];
        match stream.try_read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                input.extend_from_slice(&buf[..n]);
                if input.len() > 8192 {
                    return;
                }
                if input.contains(&b'\n') {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return,
        }
    }
    let line = String::from_utf8_lossy(&input);
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed == "{\"action\":\"shutdown\"}" {
        let _ = shutdown.try_send(());
        return;
    }
    let response_line = if let Some(oauth) = &state.oauth {
        let payload = trimmed.as_bytes().to_vec();
        let state_ref = state.clone();
        let oauth_server = oauth.server.clone();
        match oauth_server
            .admission_work(true, move || {
                state_ref
                    .oauth
                    .as_ref()
                    .map(|oauth| oauth.consent(&state_ref, &payload))
            })
            .await
        {
            Ok(Some(reply)) => {
                let status = reply.status().as_u16();
                let body = reply
                    .into_body()
                    .collect()
                    .await
                    .map(|collected| collected.to_bytes())
                    .unwrap_or_default();
                let parsed: Value = serde_json::from_slice(&body).unwrap_or_else(|_| {
                    Value::String(String::from_utf8_lossy(&body).into_owned())
                });
                format!(
                    "{}\n",
                    serde_json::json!({"status": status, "body": parsed})
                )
            }
            _ => "{\"status\":503,\"body\":{\"error\":\"temporarily_unavailable\"}}\n".into(),
        }
    } else {
        "{\"status\":503,\"body\":{\"error\":\"oauth_unavailable\"}}\n".into()
    };
    let bytes = response_line.as_bytes();
    let mut written = 0;
    while written < bytes.len() {
        match tokio::time::timeout_at(deadline, stream.writable()).await {
            Ok(Ok(())) => match stream.try_write(&bytes[written..]) {
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            },
            _ => break,
        }
    }
}

const MAX_BODY: usize = 1_048_576;
const MAX_SESSIONS: usize = 128;
const MAX_CONNECTIONS: usize = 32;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
use mcp_gateway::core::{protocol::MCP_VERSION, session::{OwnedSession, random_id}};

type Reply = Response<Full<Bytes>>;

type Session = OwnedSession<String, (bool, Option<[u8; 32]>), Protocol>;

struct Failure {
    count: u32,
    until: Instant,
}

struct State {
    addr: SocketAddr,
    #[cfg(target_os = "linux")]
    tailnet: Option<crate::tailnet::Settings>,
    #[cfg(not(target_os = "linux"))]
    clients: Vec<Client>,
    #[cfg(target_os = "linux")]
    policy: operator::PolicyCache,
    #[cfg(target_os = "linux")]
    oauth: Option<oauth::Native>,
    mutations: MutationAudit,
    #[cfg(target_os = "linux")]
    jobs: Option<Jobs>,
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<HashMap<IpAddr, Failure>>,
    #[cfg(target_os = "linux")]
    funnel_rate: Mutex<Failure>,
    #[cfg(target_os = "linux")]
    admin: Option<dashboard::Admin>,
    #[cfg(target_os = "linux")]
    diagnostic_only: bool,
    #[cfg(target_os = "linux")]
    mcp_connections: Arc<Semaphore>,
    #[cfg(target_os = "linux")]
    tool_workers: Arc<Semaphore>,
}

pub fn run(args: Vec<OsString>) -> Result<(), String> {
    run_inner(args,None,false,None,None)
}

pub(crate) fn run_onboarded(path: PathBuf, config: Value, open_ui: bool, funnel:Option<crate::tailnet::oauth_provider::Plan>, control: Option<std::os::unix::net::UnixListener>) -> Result<(),String> {
    let origin=funnel.as_ref().map_or("https://veyl.example",|p|p.origin()).to_owned();
    run_inner(vec!["--listen".into(),"127.0.0.1:0".into(),"--config".into(),path.into_os_string(),
        "--oauth-preview-origin".into(),origin.into()],Some(config),open_ui,funnel,control)
}

fn run_inner(args: Vec<OsString>, automated: Option<Value>, open_ui: bool, funnel:Option<crate::tailnet::oauth_provider::Plan>, control: Option<std::os::unix::net::UnixListener>) -> Result<(), String> {
    let onboarded=automated.is_some();
    let mut listen = None;
    let mut config = None;
    #[cfg(target_os = "linux")]
    let mut oauth_origin = None;
    let mut args = args.into_iter();
    while let Some(key) = args.next() {
        match key.to_str() {
            Some("--listen") if listen.is_none() => listen = args.next(),
            Some("--config") if config.is_none() => config = args.next(),
            #[cfg(target_os = "linux")]
            Some("--oauth-preview-origin") if oauth_origin.is_none() => {
                oauth_origin = Some(args.next().ok_or("Missing preview origin")?);
            }
            _ => {
                return Err(
                    "usage: veyl http --listen 127.0.0.1:PORT --config /absolute/clients.json"
                        .into(),
                );
            }
        }
    }
    let addr: SocketAddr = listen
        .ok_or("missing --listen")?
        .to_string_lossy()
        .parse()
        .map_err(|_| "invalid loopback listen address")?;
    if addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err("HTTP service may only listen on 127.0.0.1".into());
    }
    let path = PathBuf::from(config.ok_or("missing --config")?);
    #[cfg(not(target_os = "linux"))]
    let config = load_clients(&path)?;
    #[cfg(target_os = "linux")]
    let (policy, config) = operator::PolicyCache::open(&path)?;
    #[cfg(target_os = "linux")]
    let oauth = if let Some(origin) = oauth_origin {
        if addr.port() != 0 {
            return Err("OAuth native preview requires an ephemeral MCP port".into());
        }
        Some(oauth::Native::open(origin.to_str().ok_or("Invalid preview origin")?, &config, &path, automated,funnel.is_some())?)
    } else {
        None
    };
    let has_mutation_grants = config.clients.iter().any(|client| {
        client.actions.contains(&Action::WriteFile) || client.actions.contains(&Action::ApplyPatch)
    });
    let audit_log = config.audit_log.as_deref();
    #[cfg(target_os = "linux")]
    let startup_transaction = crate::update_cli::startup_transaction(&path, audit_log)?;
    let mutations = MutationAudit::open(
        &path,
        audit_log,
        #[cfg(target_os = "linux")]
        config.audit_limits,
    );
    #[cfg(target_os = "linux")]
    let (mutations, diagnostic_only) = match mutations {
        Ok(mutations) => (mutations, false),
        Err(_) if config.admin_listen.is_some() => {
            eprintln!("Gateway diagnostic mode: audit ledger unavailable");
            (MutationAudit::open(&path, None, config.audit_limits)?, true)
        }
        Err(error) => return Err(error),
    };
    #[cfg(not(target_os = "linux"))]
    let mutations = mutations?;
    #[cfg(target_os = "linux")]
    let degraded = mutations.read_only() || diagnostic_only;
    #[cfg(target_os = "linux")]
    if oauth.is_some() && (degraded || !mutations.available()) {
        return Err("OAuth native preview requires a writable audit ledger".into());
    }
    #[cfg(not(target_os = "linux"))]
    let degraded = false;
    if has_mutation_grants && !mutations.available() && !degraded {
        return Err("Mutation grants require a private, available audit log".into());
    }
    #[cfg(target_os = "linux")]
    if !diagnostic_only {
        operator::verify_approvals(&config)?;
        mutations.recover(&config.clients)?;
    }
    #[cfg(target_os = "linux")]
    let jobs = config
        .jobs
        .as_ref()
        .filter(|_| !degraded)
        .map(|(state, profiles)| {
            Jobs::open(
                state,
                profiles.clone(),
                config.audit_log.as_deref().ok_or("Missing job audit log")?,
                config.audit_limits,
            )
        })
        .transpose()?;

    #[cfg(target_os = "linux")]
    if config.managed && !diagnostic_only {
        operator::require_completed_legacy_jobs(&config)?;
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "cannot initialize HTTP runtime")?;
    let result = runtime.block_on(async move {
        let control = control.map(tokio::net::UnixListener::from_std).transpose().map_err(|_| "Cannot initialize private logout listener")?;
        #[cfg(unix)]
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| "cannot register SIGTERM handler")?;
        #[cfg(unix)]
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| "cannot register SIGINT handler")?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|_| "cannot bind requested loopback address")?;
        let actual = listener
            .local_addr()
            .map_err(|_| "cannot inspect bound listener")?;
        #[cfg(target_os = "linux")]
        let admin_listener = match config.admin_listen {
            Some(addr) => Some(
                TcpListener::bind(addr)
                    .await
                    .map_err(|_| "Cannot bind admin listener")?,
            ),
            None => None,
        };
        #[cfg(target_os = "linux")]
        let admin = admin_listener
            .as_ref()
            .map(|listener| {
                listener
                    .local_addr()
                    .map(|addr| dashboard::Admin::new(addr, path.clone()))
            })
            .transpose()
            .map_err(|_| "Cannot get admin listener address")?;
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let state = Arc::new(State {
            addr: actual,
            #[cfg(target_os = "linux")]
            tailnet: config.tailnet.clone(),
            #[cfg(not(target_os = "linux"))]
            clients: config.clients,
            #[cfg(target_os = "linux")]
            policy,
            #[cfg(target_os = "linux")]
            oauth,
            mutations,
            #[cfg(target_os = "linux")]
            jobs,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            #[cfg(target_os = "linux")]
            funnel_rate: Mutex::new(Failure {
                count: 0,
                until: Instant::now(),
            }),
            #[cfg(target_os = "linux")]
            admin,
            #[cfg(target_os = "linux")]
            diagnostic_only,
            #[cfg(target_os = "linux")]
            mcp_connections: Arc::clone(&permits),
            #[cfg(target_os = "linux")]
            tool_workers: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        });
        // The updater probes the bound TCP listener before committing its
        // transaction. Do not admit requests until the rollback window closes.
        #[cfg(target_os = "linux")]
        if let Some(journal) = startup_transaction {
            let until = tokio::time::Instant::now() + Duration::from_secs(15);
            loop {
                match std::fs::symlink_metadata(&journal) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Err(_) => return Err("Cannot inspect update transaction".into()),
                    Ok(_) if tokio::time::Instant::now() >= until => {
                        return Err("Interrupted update requires local recovery before admission".into());
                    }
                    Ok(_) => {}
                }
                let mut pause = std::pin::pin!(tokio::time::sleep(Duration::from_millis(50)));
                let stopping = poll_fn(|cx| {
                    if term.poll_recv(cx).is_ready() || interrupt.poll_recv(cx).is_ready() {
                        return Poll::Ready(true);
                    }
                    std::future::Future::poll(pause.as_mut(), cx).map(|()| false)
                }).await;
                if stopping {
                    return Ok(());
                }
            }
        }
        let mut lease=if let Some(plan)=funnel {
            let std::net::SocketAddr::V4(target)=actual else {return Err("Expected IPv4 loopback".into());};
            if !state.mutations.record_runtime_mode("local_operator","oauth_funnel_up","standard",AuditPhase::Intent){
                return Err("Funnel audit unavailable".into());
            }
            let lease=match plan.up(target).await {
                Ok(lease)=>lease,
                Err(err)=>{
                    let _=state.mutations.record_runtime_mode("local_operator","oauth_funnel_up","standard",AuditPhase::Uncertain);
                    return Err(err);
                }
            };
            if !state.mutations.record_runtime_mode("local_operator","oauth_funnel_up","standard",AuditPhase::Success){
                return Err("Funnel activation receipt unavailable".into());
            }
            let mcp_url = format!("{}/mcp", plan.origin());
            eprintln!("OAUTH_FUNNEL_URL={mcp_url}");
            eprintln!("Funnel route configured; external HTTPS reachability has not been verified.");
            if onboarded && copy_clipboard(&mcp_url) {
                eprintln!("Copied MCP URL to clipboard.");
            } else if onboarded {
                eprintln!("Copy the MCP URL above to configure your OAuth MCP client.");
            }
            Some(lease)
        } else {None};
        // Publish complete readiness records in one short pipe write; formatted
        // eprintln can expose a prefix before the address to a launcher.
        let mut readiness = String::new();
        #[cfg(target_os = "linux")]
        if let Some(admin) = &state.admin {
            readiness.push_str(&format!("ADMIN_HTTP_LISTEN={}\n", admin.addr));
        }
        readiness.push_str(&format!("MCP_HTTP_LISTEN={actual}\n"));
        std::io::stderr().lock().write_all(readiness.as_bytes())
            .map_err(|_| "Cannot publish listener readiness")?;
        if onboarded && let Some(admin) = &state.admin {
            eprintln!("Private OAuth dashboard: http://{}/dashboard",admin.addr);
            eprintln!("For local pairing: veyl dashboard pair --config {:?}",path);
            if open_ui && dashboard::open_paired_local(&path,admin.addr).is_err() {
                eprintln!("Automatic browser opening failed; use local dashboard pairing.");
            }
        }
        #[cfg(target_os = "linux")]
        let admin_permits = Arc::new(Semaphore::new(8));
        let (shutdown, _) = watch::channel(false);
        let (control_shutdown_tx, mut control_shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
        let mut connections = JoinSet::new();
        let mut lease_lost=false;
        let mut ingress_closed=Box::pin(async {
            if let Some(lease)=lease.as_mut(){lease.ended().await;} else {std::future::pending::<()>().await;}
        });
        enum AcceptEvent {
            Tcp(bool, std::io::Result<(tokio::net::TcpStream, SocketAddr)>),
            #[cfg(target_os = "linux")]
            Control(tokio::net::UnixStream),
        }
        loop {
            let event = poll_fn(|cx| {
                if ingress_closed.as_mut().poll(cx).is_ready(){lease_lost=true;return Poll::Ready(None);}
                #[cfg(unix)]
                if term.poll_recv(cx).is_ready() || interrupt.poll_recv(cx).is_ready() {
                    return Poll::Ready(None);
                }
                if control_shutdown_rx.poll_recv(cx).is_ready() {
                    return Poll::Ready(None);
                }
                if let Some(control) = &control {
                    match control.poll_accept(cx) {
                        Poll::Ready(Ok((stream, _))) => {
                            if stream.peer_cred().is_ok_and(|c| c.uid() == rustix::process::geteuid().as_raw()) {
                                #[cfg(target_os = "linux")]
                                return Poll::Ready(Some(AcceptEvent::Control(stream)));
                                #[cfg(not(target_os = "linux"))]
                                {
                                    drop(stream);
                                    return Poll::Ready(None);
                                }
                            }
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(None),
                        Poll::Pending => {},
                    }
                }
                #[cfg(target_os = "linux")]
                if let Some(admin) = &admin_listener
                    && let Poll::Ready(event) = admin.poll_accept(cx)
                {
                    return Poll::Ready(Some(AcceptEvent::Tcp(true, event)));
                }
                listener.poll_accept(cx).map(|event| Some(AcceptEvent::Tcp(false, event)))
            })
            .await;
            let Some(accept_event) = event else {
                break;
            };
            let (is_admin, event) = match accept_event {
                #[cfg(target_os = "linux")]
                AcceptEvent::Control(stream) => {
                    tokio::spawn(handle_control_stream(
                        stream,
                        state.clone(),
                        control_shutdown_tx.clone(),
                    ));
                    continue;
                }
                AcceptEvent::Tcp(is_admin, event) => (is_admin, event),
            };
            let (stream, peer) = event.map_err(|_| "loopback accept failed")?;
            while connections.try_join_next().is_some() {}
            #[cfg(target_os = "linux")]
            let selected = if is_admin { &admin_permits } else { &permits };
            #[cfg(not(target_os = "linux"))]
            let selected = &permits;
            let Ok(permit) = selected.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let state = state.clone();
            let mut stopping = shutdown.subscribe();
            connections.spawn(async move {
                #[cfg(target_os = "linux")]
                let oauth_preview_connection = state.oauth.is_some();
                #[cfg(not(target_os = "linux"))]
                let oauth_preview_connection = false;
                let service = service_fn(move |request| {
                    let state = state.clone();
                    async move {
                        #[cfg(target_os = "linux")]
                        let mut call = None;
                        let extend = std::sync::atomic::AtomicBool::new(false);
                        let deadline = tokio::time::Instant::now() + HTTP_TIMEOUT;
                        let result = {
                            let mut work = std::pin::pin!(async {
                                #[cfg(target_os = "linux")]
                                if is_admin {
                                    if let Some(oauth) = &state.oauth
                                        && oauth.legacy_operator
                                        && matches!(request.uri().path(), "/inspect" | "/approve" | "/deny" | "/revoke")
                                    {
                                        return oauth.operator(request, state.clone()).await;
                                    }
                                    return dashboard::serve(request, state).await;
                                }
                                #[cfg(target_os = "linux")]
                                if let Some(oauth) = &state.oauth {
                                    let server = oauth.server.clone();
                                    return server.handle(request, None, |request| async {
                                        serve_admitted(request, state.clone(), peer.ip(), false, None, &mut call, &extend).await
                                    }).await;
                                }
                                serve(
                                    request,
                                    state,
                                    peer.ip(),
                                    #[cfg(target_os = "linux")]
                                    &mut call,
                                    #[cfg(target_os = "linux")]
                                    &extend,
                                )
                                .await
                            });
                            match tokio::time::timeout_at(deadline, &mut work).await {
                                Err(_) if extend.load(std::sync::atomic::Ordering::Relaxed) => {
                                    tokio::time::timeout_at(
                                        deadline + Duration::from_secs(8),
                                        &mut work,
                                    )
                                    .await
                                }
                                result => result,
                            }
                        };
                        #[cfg(target_os = "linux")]
                        if let Some(call) = call {
                            call.finish(match &result {
                                Ok(reply) => reply
                                    .extensions()
                                    .get::<activity::Status>()
                                    .copied()
                                    .unwrap_or(activity::Status::Failure),
                                Err(_) => activity::Status::TimedOut,
                            });
                        }
                        Ok::<_, Infallible>(result.unwrap_or_else(|_| {
                            simple(StatusCode::REQUEST_TIMEOUT, "Request timed out")
                        }))
                    }
                });
                let mut builder = http1::Builder::new();
                if is_admin || oauth_preview_connection {
                    builder
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(5))
                        .keep_alive(false);
                }
                let mut connection =
                    std::pin::pin!(builder.serve_connection(TokioIo::new(stream), service));
                let mut changed = std::pin::pin!(stopping.changed());
                let completed = poll_fn(|cx| {
                    if connection.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(true);
                    }
                    changed.as_mut().poll(cx).map(|_| false)
                })
                .await;
                if !completed {
                    connection.as_mut().graceful_shutdown();
                    let _ = connection.await;
                }
                drop(permit);
            });
        }
        drop(ingress_closed);
        if let Some(lease)=lease {
            if !state.mutations.record_runtime_mode("local_operator","oauth_funnel_down","standard",AuditPhase::Intent){
                // Dropping the watcher still removes the foreground route.
                return Err("Funnel shutdown audit unavailable".into());
            }
            if let Err(err)=lease.down().await {
                let _=state.mutations.record_runtime_mode("local_operator","oauth_funnel_down","standard",AuditPhase::Uncertain);
                return Err(err);
            }
            if !state.mutations.record_runtime_mode("local_operator","oauth_funnel_down","standard",AuditPhase::Success){
                return Err("Funnel removal receipt unavailable".into());
            }
        }
        drop(listener);
        let _ = shutdown.send(true);
        tokio::time::timeout(Duration::from_secs(7), async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .map_err(|_| "Timed out draining HTTP connections")?;
        if lease_lost {Err("Funnel foreground lease lost; gateway stopped".into())} else {Ok(())}
    });
    // Detached job runners own their leases. Reaping waiters must not keep
    // the gateway alive after its listener and in-flight HTTP work drain.
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

async fn serve(
    request: Request<Incoming>,
    state: Arc<State>,
    peer: IpAddr,
    #[cfg(target_os = "linux")] call: &mut Option<activity::Call>,
    #[cfg(target_os = "linux")] extend: &std::sync::atomic::AtomicBool,
) -> Reply {
    let marker = request.headers().contains_key("Tailscale-Funnel-Request");
    let raw_path = request.uri().path();
    let path = raw_path.strip_prefix("/veyl").unwrap_or(raw_path);
    if path != "/mcp" && !(marker && path.starts_with("/mcp/")) {
        return simple(StatusCode::NOT_FOUND, "Not found");
    }
    #[cfg(target_os = "linux")]
    if state.diagnostic_only {
        return simple(StatusCode::SERVICE_UNAVAILABLE, "Gateway audit unavailable");
    }
    let expected = format!("127.0.0.1:{}", state.addr.port());
    let local_alias = format!("localhost:{}", state.addr.port());
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    #[cfg(target_os = "linux")]
    let remote = state
        .tailnet
        .as_ref()
        .map(|settings| settings.authority(false));
    #[cfg(not(target_os = "linux"))]
    let remote: Option<String> = None;
    #[cfg(target_os = "linux")]
    let shared_origin = state.tailnet.as_ref().and_then(|settings| {
        (marker && host.is_some_and(|host| settings.shared_authority(host)))
            .then(|| format!("https://{}", settings.hostname))
    });
    #[cfg(not(target_os = "linux"))]
    let shared_origin: Option<String> = None;
    #[cfg(target_os = "linux")]
    let public = state
        .tailnet
        .as_ref()
        .and_then(|settings| settings.funnel.as_ref())
        .filter(|_| {
            (host == remote.as_deref() || shared_origin.is_some())
                && host.is_some()
                && funnel::marked(request.headers())
        })
        .map(|settings| settings.allow_secret_path);
    if request.uri().authority().is_some()
        || request.headers().get_all(header::HOST).iter().count() != 1
        || !(shared_origin.is_some()
            || host
                .is_some_and(|h| h == expected || h == local_alias || remote.as_deref() == Some(h)))
    {
        return simple(StatusCode::FORBIDDEN, "Invalid Host");
    }
    #[cfg(target_os = "linux")]
    if marker && (public.is_none() || request.uri().query().is_some()) {
        return simple(StatusCode::FORBIDDEN, "Invalid public MCP route");
    }
    #[cfg(not(target_os = "linux"))]
    if marker {
        return simple(StatusCode::FORBIDDEN, "Invalid Host");
    }
    let origin = if let Some(origin) = shared_origin {
        origin
    } else if host == remote.as_deref() {
        format!("https://{}", host.unwrap_or_default())
    } else {
        format!("http://{}", host.unwrap_or_default())
    };
    #[cfg(target_os = "linux")]
    if let Some(allow_secret_path) = public {
        let origin = funnel::Origin::parse(request.headers(), &origin);
        return serve_public(
            request,
            state,
            peer,
            origin,
            allow_secret_path,
            call,
            extend,
        )
        .await;
    }
    if request.headers().get_all(header::ORIGIN).iter().count() > 1
        || request
            .headers()
            .get(header::ORIGIN)
            .is_some_and(|value| value.as_bytes() != origin.as_bytes())
    {
        return simple(StatusCode::FORBIDDEN, "Invalid Origin");
    }
    serve_admitted(
        request,
        state,
        peer,
        false,
        None,
        #[cfg(target_os = "linux")]
        call,
        #[cfg(target_os = "linux")]
        extend,
    )
    .await
}

#[cfg(target_os = "linux")]
async fn serve_public(
    request: Request<Incoming>,
    state: Arc<State>,
    peer: IpAddr,
    origin: funnel::Origin,
    allow_secret_path: bool,
    call: &mut Option<activity::Call>,
    extend: &std::sync::atomic::AtomicBool,
) -> Reply {
    let options = request.method() == Method::OPTIONS;
    let valid_path = funnel::route_matches(request.uri().path(), allow_secret_path);
    {
        // Charge all requests on the validated public route to one budget,
        // including rejected origins and preflights. Private admission is separate.
        let mut rate = state.funnel_rate.lock().await;
        let instant = Instant::now();
        if instant >= rate.until {
            rate.until = instant + Duration::from_secs(10);
            rate.count = 0;
        }
        if rate.count >= 60 {
            let mut response = simple(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many public MCP requests",
            );
            if valid_path {
                funnel::cors_headers(response.headers_mut(), origin, options);
            }
            return response;
        }
        rate.count += 1;
    }
    let method = match *request.method() {
        Method::OPTIONS => "OPTIONS",
        Method::POST => "POST",
        Method::GET => "GET",
        _ => "other",
    };
    let mut response = if !valid_path {
        simple(StatusCode::NOT_FOUND, "Not found")
    } else if matches!(origin, funnel::Origin::Rejected) {
        simple(StatusCode::FORBIDDEN, "Invalid Origin")
    } else if options {
        if origin.value().is_none()
            || !request.body().is_end_stream()
            || !funnel::options_allowed(request.headers())
        {
            simple(StatusCode::FORBIDDEN, "Invalid MCP preflight")
        } else {
            let mut response = Response::new(Full::default());
            *response.status_mut() = StatusCode::NO_CONTENT;
            funnel::preflight_headers(response.headers_mut());
            response
        }
    } else {
        let proof = funnel::proof(request.uri().path(), request.headers(), allow_secret_path);
        serve_admitted(request, state, peer, true, proof, call, extend).await
    };
    if valid_path {
        funnel::cors_headers(response.headers_mut(), origin, options);
    }
    if !options && response.status().is_success() {
        response.headers_mut().insert(
            "Mcp-Protocol-Version",
            HeaderValue::from_static(MCP_VERSION),
        );
    }
    // Only fixed classifications and an HTTP status. In particular, the
    // request target, raw Origin and client-supplied identity are sensitive.
    let _ = writeln!(
        std::io::stderr().lock(),
        "MCP_HTTP_EVENT=funnel.response method={method} origin={} status={}",
        origin.label(),
        response.status().as_u16()
    );
    response
}

async fn serve_admitted(
    request: Request<Incoming>,
    state: Arc<State>,
    peer: IpAddr,
    marker: bool,
    proof: Option<[u8; 32]>,
    #[cfg(target_os = "linux")] call: &mut Option<activity::Call>,
    #[cfg(target_os = "linux")] extend: &std::sync::atomic::AtomicBool,
) -> Reply {
    #[cfg(not(target_os = "linux"))]
    let _ = proof;
    if request.headers().contains_key("MCP-Protocol-Version")
        && one(request.headers(), "MCP-Protocol-Version") != Some(MCP_VERSION)
    {
        if marker {
            let _ = audit("funnel.unsupported_protocol");
        }
        return simple(StatusCode::BAD_REQUEST, "Unsupported protocol version");
    }

    // Admission precedes reading even one byte of an untrusted request body.
    let now = unix_seconds();
    let bearer = one_value(request.headers(), "authorization").cloned();
    if !marker {
        let locks = state.failures.lock().await;
        if locks
            .get(&peer)
            .is_some_and(|f| f.count >= 5 && Instant::now() < f.until)
        {
            return simple(StatusCode::TOO_MANY_REQUESTS, "Too many requests");
        }
    }
    #[cfg(target_os = "linux")]
    let (settings, oauth_identity) = {
        let snapshot_state = state.clone();
        let auth = bearer.clone();
        let load=move || {
            let (_guard,settings)=snapshot_state.policy.read().map_err(|_|"Authorization state unavailable or restart required")?;
            let identity=snapshot_state.oauth.as_ref().and_then(|oauth| {
                oauth.admit(&settings,auth.as_ref().and_then(|h|h.to_str().ok()),unix_seconds())
            });
            if let Some((index, id))=&identity {
                let mode_label = if id.mode == ConnectionMode::Yolo {
                    "broad_yolo"
                } else {
                    "standard"
                };
                if ![AuditPhase::Intent,AuditPhase::Success].into_iter().all(|phase|
                    snapshot_state.mutations.record_runtime_mode(&settings.clients[*index].id,"oauth_admission",mode_label,phase))
                { return Err("Audit unavailable"); }
            }
            Ok((settings,identity))
        };
        let loaded=if let Some(oauth)=&state.oauth {
            oauth.server.admission_work(false,load).await.map_err(|_|())
        } else {
            tokio::task::spawn_blocking(load).await.map_err(|_|())
        };
        match loaded {
            Ok(Ok(result)) => result,
            Ok(Err(message))=>return simple(StatusCode::SERVICE_UNAVAILABLE,message),
            _ => {
                return simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authorization state unavailable or restart required",
                );
            }
        }
    };
    #[cfg(target_os = "linux")]
    let clients = &settings.clients;
    #[cfg(not(target_os = "linux"))]
    let clients = &state.clients;

    #[cfg(target_os = "linux")]
    let client_index = if state.oauth.is_some() {
        oauth_identity.as_ref().map(|(index, _)| *index)
    } else if marker {
        funnel::authenticate(&settings, proof.as_ref(), now)
    } else {
        authenticate(clients, bearer.as_ref(), now)
    };
    #[cfg(not(target_os = "linux"))]
    let client_index = authenticate(clients, bearer.as_ref(), now);
    let Some(client_index) = client_index else {
        #[cfg(target_os = "linux")]
        if state.oauth.is_some() {
            return simple(StatusCode::UNAUTHORIZED, "Unauthorized");
        }
        if marker {
            #[cfg(target_os = "linux")]
            if let Some(admin) = &state.admin {
                admin
                    .activity
                    .funnel_admission(None, activity::Status::Failure);
            }
            let _ = audit("funnel.denied");
            return simple(StatusCode::NOT_FOUND, "Not found");
        }
        let mut locks = state.failures.lock().await;
        let failure = locks.entry(peer).or_insert(Failure {
            count: 0,
            until: Instant::now(),
        });
        if Instant::now() >= failure.until {
            failure.count = 0;
        }
        failure.count = failure.count.saturating_add(1);
        failure.until = Instant::now() + Duration::from_secs(60);
        let _ = audit("auth.denied");
        return simple(
            if failure.count > 5 {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::UNAUTHORIZED
            },
            "Unauthorized",
        );
    };
    #[cfg(target_os = "linux")]
    let oauth_identity = oauth_identity.map(|(_, identity)| identity);
    #[cfg(target_os = "linux")]
    let resolved_client = match (&state.oauth, oauth_identity.as_ref()) {
        (Some(oauth), Some(identity)) => {
            match oauth.resolve_client_override(&settings, client_index, Some(identity)) {
                Ok(Some(client)) => ResolvedClient::Owned(Box::new(client)),
                Ok(None) => ResolvedClient::Borrowed(&clients[client_index]),
                Err(msg) => return simple(StatusCode::SERVICE_UNAVAILABLE, msg),
            }
        }
        _ => ResolvedClient::Borrowed(&clients[client_index]),
    };
    #[cfg(target_os = "linux")]
    let client: &Client = &resolved_client;
    #[cfg(not(target_os = "linux"))]
    let client = &clients[client_index];
    #[cfg(target_os = "linux")]
    let session_scope = (marker, oauth_identity.as_ref().map(|identity| identity.family));
    #[cfg(not(target_os = "linux"))]
    let session_scope = (marker, None);
    #[cfg(target_os = "linux")]
    if marker
        && ![AuditPhase::Intent, AuditPhase::Success]
            .into_iter()
            .all(|phase| {
                state.mutations.record_runtime_mode(
                    &client.id,
                    "funnel_admission",
                    "broad_yolo",
                    phase,
                )
            })
    {
        return simple(StatusCode::SERVICE_UNAVAILABLE, "Audit unavailable");
    }
    #[cfg(target_os = "linux")]
    if marker && let Some(admin) = &state.admin {
        admin
            .activity
            .funnel_admission(Some(&client.id), activity::Status::Success);
    }
    let accepted = audit("auth.accepted");
    if !accepted {
        return simple(StatusCode::SERVICE_UNAVAILABLE, "Audit unavailable");
    }
    // Even unsupported HTTP methods require Host/Origin validation and
    // bearer admission. GET without SSE is explicitly 405 under MCP 2025-11-25.
    if request.method() != Method::POST {
        return simple(StatusCode::METHOD_NOT_ALLOWED, "Only POST is supported");
    }
    if one(request.headers(), "content-type") != Some("application/json")
    {
        return simple(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON required");
    }

    let session_header = one(request.headers(), "Mcp-Session-Id").map(str::to_owned);
    if request.headers().contains_key("Mcp-Session-Id") && session_header.is_none() {
        return simple(StatusCode::BAD_REQUEST, "Invalid MCP session header");
    }
    let body = match tokio::time::timeout(HTTP_TIMEOUT, bounded_body(request.into_body(), MAX_BODY))
        .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(StatusCode::PAYLOAD_TOO_LARGE)) => {
            return simple(StatusCode::PAYLOAD_TOO_LARGE, "Request too large");
        }
        _ => return simple(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(value @ Value::Object(_)) => value,
        _ => return simple(StatusCode::BAD_REQUEST, "Malformed JSON-RPC request"),
    };
    let method = payload.get("method").and_then(Value::as_str);
    if marker {
        match method {
            Some("initialize") => {
                let _ = audit("funnel.rpc_initialize");
            }
            Some("tools/list") => {
                let _ = audit("funnel.rpc_tools_list");
            }
            _ => {}
        }
    }

    if method == Some("initialize") && session_header.is_none() {
        let Ok(files) = FileAccess::new(&client.root) else {
            return simple(StatusCode::SERVICE_UNAVAILABLE, "Client root unavailable");
        };
        let mut protocol = Protocol::new(files);
        let Some(reply) = protocol.dispatch(payload) else {
            return simple(StatusCode::BAD_REQUEST, "Invalid initialization");
        };
        if reply.get("result").is_none() {
            return json_response(StatusCode::OK, reply, None);
        }
        let mut sessions = state.sessions.lock().await;
        sessions.retain(|_, value| value.is_live());
        if sessions.len() >= MAX_SESSIONS {
            return simple(StatusCode::SERVICE_UNAVAILABLE, "Session capacity reached");
        }
        let Ok(id) = random_id::<24>() else {
            return simple(StatusCode::SERVICE_UNAVAILABLE, "Session unavailable");
        };
        if sessions.contains_key(&id) {
            return simple(StatusCode::SERVICE_UNAVAILABLE, "Session unavailable");
        }
        sessions.insert(id.clone(), Session::new(client.id.clone(), session_scope, protocol));
        return json_response(StatusCode::OK, reply, Some(&id));
    }

    let Some(session_id) = session_header else {
        return simple(StatusCode::BAD_REQUEST, "MCP session required");
    };
    let mut sessions = state.sessions.lock().await;
    let Some(session) = sessions.get_mut(&session_id) else {
        return simple(StatusCode::NOT_FOUND, "Unknown MCP session");
    };
    if !session.belongs_to(&client.id, &session_scope) {
        return simple(StatusCode::FORBIDDEN, "Session access denied");
    }
    if !session.is_live() {
        sessions.remove(&session_id);
        return simple(StatusCode::NOT_FOUND, "Expired MCP session");
    }
    session.touch();

    #[cfg(target_os = "linux")]
    if client
        .actions
        .contains(&mcp_gateway::security::policy::Action::CallUpstream)
        && client.upstreams.scoped_call(&payload)
    {
        extend.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(target_os = "linux")]
    if matches!(method, Some("tools/list" | "tools/call")) {
        // Tool requests leave protocol phase unchanged. Release session state
        // before waiting on storage, a short command, or crash instrumentation.
        let mut protocol = session.protocol.clone();
        drop(sessions);
        // Blocking work may outlive a disconnected or timed-out RPC. Keep
        // its capacity slot until the actual worker exits.
        let Ok(worker) = state.tool_workers.clone().try_acquire_owned() else {
            return simple(StatusCode::SERVICE_UNAVAILABLE, "Tool workers busy");
        };
        *call = state
            .admin
            .as_ref()
            .and_then(|admin| admin.activity.start(&client.id, &payload));
        let trace_key = call.as_ref().map(activity::Call::trace_key);
        return match tokio::task::spawn_blocking(move || {
            let _worker = worker;
            let Ok((_admission, current)) = state.policy.read() else {
                return simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authorization state unavailable or restart required",
                );
            };
            let now = unix_seconds();
            let (index, worker_identity) = if let Some(oauth) = &state.oauth {
                match oauth
                    .admit(&current, bearer.as_ref().and_then(|h| h.to_str().ok()), now)
                    .filter(|(_, identity)| Some(identity) == oauth_identity.as_ref())
                {
                    Some((index, id)) => (index, Some(id)),
                    None => return simple(StatusCode::UNAUTHORIZED, "Unauthorized"),
                }
            } else if marker {
                match funnel::authenticate(&current, proof.as_ref(), now) {
                    Some(index) => (index, None),
                    None => return simple(StatusCode::UNAUTHORIZED, "Unauthorized"),
                }
            } else {
                match authenticate(&current.clients, bearer.as_ref(), now) {
                    Some(index) => (index, None),
                    None => return simple(StatusCode::UNAUTHORIZED, "Unauthorized"),
                }
            };
            if current.clients[index].id != settings.clients[client_index].id {
                return simple(StatusCode::FORBIDDEN, "Session access denied");
            }
            let worker_client = match (&state.oauth, worker_identity.as_ref()) {
                (Some(oauth), Some(id)) => {
                    match oauth.resolve_client_override(&current, index, Some(id)) {
                        Ok(Some(c)) => ResolvedClient::Owned(Box::new(c)),
                        Ok(None) => ResolvedClient::Borrowed(&current.clients[index]),
                        Err(msg) => return simple(StatusCode::SERVICE_UNAVAILABLE, msg),
                    }
                }
                _ => ResolvedClient::Borrowed(&current.clients[index]),
            };
            if worker_identity.is_some()
                && ![AuditPhase::Intent, AuditPhase::Success].into_iter().all(|phase| {
                    state.mutations.record_runtime_mode(
                        &current.clients[index].id,
                        "oauth_worker_admission",
                        worker_client.mode.audit_mode().unwrap_or("standard"),
                        phase,
                    )
                })
            {
                return simple(StatusCode::SERVICE_UNAVAILABLE, "Audit unavailable");
            }
            dispatch_tools(
                &mut protocol,
                payload,
                &state,
                &worker_client,
                &current,
                (trace_key, worker_identity.as_ref()),
            )
        })
        .await
        {
            Ok(reply) => reply,
            Err(_) => simple(
                StatusCode::SERVICE_UNAVAILABLE,
                "Tool operation unavailable",
            ),
        };
    }
    dispatch_tools(
        &mut session.protocol,
        payload,
        &state,
        client,
        &settings,
        #[cfg(target_os = "linux")]
        (None,None),
    )
}

fn dispatch_tools(
    protocol: &mut Protocol,
    payload: Value,
    state: &State,
    client: &Client,
    settings: &Configuration,
    #[cfg(target_os = "linux")] (trace_key, oauth_identity): (
        Option<(String, Instant)>,
        Option<&mcp_gateway::http_common::oauth_http::Identity>,
    ),
) -> Reply {
    #[cfg(target_os = "linux")]
    let oauth_owner = oauth_identity.map(oauth::job_owner);
    #[cfg(target_os = "linux")]
    let oauth_owner = oauth_owner.as_deref();
    #[cfg(target_os = "linux")]
    let trace = trace_key.filter(|(id, _)| {
        state.admin.as_ref().is_some_and(|admin| {
            admin
                .trace
                .lock()
                .is_ok_and(|mut trace| trace.begin(id, &client.id, &payload))
        })
    });
    #[cfg(not(target_os = "linux"))]
    let _ = settings;
    let response = protocol.dispatch_with_tools(
        payload,
        || {
            let audited = audit("policy.checked");
            if !authorized(client, Action::ListTools, state, audited, unix_seconds()) {
                return Vec::new();
            }
            #[cfg(target_os = "linux")]
            if let Some(mode) = client.mode.audit_mode()
                && (!state.mutations.record_runtime_mode(
                    &client.id,
                    "tools/list",
                    mode,
                    AuditPhase::Intent,
                ) || !state.mutations.record_runtime_mode(
                    &client.id,
                    "tools/list",
                    mode,
                    AuditPhase::Success,
                ))
            {
                return Vec::new();
            }
            let now = unix_seconds();
            let mut tools: Vec<_> = Tool::ALL
                .into_iter()
                .filter(|tool| permit_tool(*tool, client, state, settings, audited, now).is_ok())
                .map(|tool| {
                    let mut schema = tool.schema();
                    #[cfg(target_os = "linux")]
                    if oauth_owner.is_some() && tool==Tool::JobWait {
                        schema["inputSchema"]["properties"]["timeout_seconds"]=serde_json::json!({"type":"integer","minimum":0,"maximum":2});
                        schema["inputSchema"]["required"]=serde_json::json!(["job_id","timeout_seconds"]);
                    }
                    #[cfg(target_os = "linux")]
                    if oauth_owner.is_some()
                        && client.mode != ExecutionMode::BroadYolo
                        && matches!(tool, Tool::ExecCommand | Tool::TaskRun)
                    {
                        schema["description"]=serde_json::json!("Execute explicitly granted arbitrary code in the offline, writable workspace sandbox. Returns a durable job ID; poll job_status/job_logs for completion.");
                        schema["inputSchema"]["properties"]["cwd"]=serde_json::json!({"type":"string","enum":["."]});
                        if tool==Tool::TaskRun {
                            schema["inputSchema"]["properties"]["wait_seconds"]=serde_json::json!({"type":"integer","minimum":0,"maximum":2,"default":2});
                            schema["inputSchema"]["properties"]["ephemeral_worktree"]=serde_json::json!({"type":"boolean","enum":[false]});
                        }
                    }
                    #[cfg(target_os = "linux")]
                    if matches!(tool, Tool::TaskRun | Tool::ProcessStart) {
                        schema["inputSchema"]["properties"]["timeout_seconds"]["maximum"] =
                            serde_json::json!(client.job_runtime_limit_seconds);
                    }
                    schema
                })
                .collect();
            #[cfg(target_os = "linux")]
            if permit_tool(Tool::UpstreamsCall, client, state, settings, audited, now).is_ok()
                && !client.upstreams.servers.is_empty()
            {
                let mode = client.mode.audit_mode().unwrap_or("standard");
                let record = |phase| {
                    state.mutations.record_runtime_mode(
                        oauth_owner.unwrap_or(&client.id),
                        "upstream_discovery",
                        mode,
                        phase,
                    )
                };
                if record(AuditPhase::Intent) {
                    let found = settings
                        .upstreams
                        .discover(state.policy.path(), &client.upstreams);
                    if record(AuditPhase::Success) {
                        tools.extend(found);
                    }
                }
            }
            tools
        },
        |_, name, args| {
            let tool = Tool::parse(name);
            let now = unix_seconds();
            let audited = audit("policy.checked");
            let permits = |tool| permit_tool(tool, client, state, settings, audited, now);
            #[cfg(target_os = "linux")]
            if tool == Some(Tool::UpstreamsList) {
                if permits(Tool::UpstreamsList).is_err()
                    || args.is_some_and(|value| {
                        !value.as_object().is_some_and(serde_json::Map::is_empty)
                    })
                {
                    return Some(tool_text(
                        true,
                        "Upstream access denied or invalid arguments",
                    ));
                }
                let listing = settings.upstreams.listing(Some(&client.upstreams));
                return Some(tool_text(
                    false,
                    &serde_json::json!({"servers":listing}).to_string(),
                ));
            }
            #[cfg(target_os = "linux")]
            if tool == Some(Tool::UpstreamsCall) || (tool.is_none() && !settings.upstreams.empty())
            {
                if permits(Tool::UpstreamsCall).is_err() {
                    return Some(tool_text(true, "Upstream access denied"));
                }
                let (name, args) = if tool == Some(Tool::UpstreamsCall) {
                    let Some(args) = args
                        .and_then(Value::as_object)
                        .filter(|a| a.keys().all(|k| matches!(k.as_str(), "name" | "arguments")))
                    else {
                        return Some(tool_text(true, "Invalid upstream tool arguments"));
                    };
                    let Some(name) = args.get("name").and_then(Value::as_str) else {
                        return Some(tool_text(true, "Expected a namespaced upstream tool name"));
                    };
                    (name, args.get("arguments"))
                } else {
                    (name, args)
                };
                let mode = client.mode.audit_mode().unwrap_or("standard");
                return Some(
                    settings
                        .upstreams
                        .call(
                            state.policy.path(),
                            &client.upstreams,
                            name,
                            args,
                            |tool, intent, successful| {
                                let phase = if intent {
                                    AuditPhase::Intent
                                } else if successful {
                                    AuditPhase::Success
                                } else {
                                    AuditPhase::Failure
                                };
                                state
                                    .mutations
                                    .record_runtime_mode(oauth_owner.unwrap_or(&client.id), tool, mode, phase)
                            },
                        )
                        .unwrap_or_else(|reason| tool_text(true, reason)),
                );
            }
            if let Err(reason) = tool.ok_or("Unknown tool").and_then(permits) {
                #[cfg(target_os = "linux")]
                if let Some(mode) = client.mode.audit_mode() {
                    // Known names come from the tool registry. Never journal
                    // the caller's arbitrary text for an unknown tool.
                    let name = if tool.is_some() { name } else { "unknown_tool" };
                    if state.mutations.record_runtime_mode(
                        &client.id,
                        name,
                        mode,
                        AuditPhase::Intent,
                    ) {
                        let _ = state.mutations.record_runtime_mode(
                            &client.id,
                            name,
                            mode,
                            AuditPhase::Failure,
                        );
                    }
                }
                return tool.map(|_| tool_text(true, reason));
            }
            let tool = tool?;
            #[cfg(target_os = "linux")]
            if matches!(tool, Tool::SkillsList | Tool::SkillsRead) {
                let store = settings.skills.as_ref()?;
                let mode = client.mode.audit_mode().unwrap_or("standard");
                if !state
                    .mutations
                    .record_runtime_mode(&client.id, name, mode, AuditPhase::Intent)
                {
                    return Some(tool_text(true, "Audit intent unavailable"));
                }
                let reply = store.call(tool, args, &client.skills);
                let phase = if reply["isError"] == true {
                    AuditPhase::Failure
                } else {
                    AuditPhase::Success
                };
                return Some(
                    if state
                        .mutations
                        .record_runtime_mode(&client.id, name, mode, phase)
                    {
                        reply
                    } else {
                        tool_text(true, "Audit outcome unavailable")
                    },
                );
            }
            #[cfg(target_os = "linux")]
            if tool.inspection() || tool == Tool::Remember {
                let mode = client.mode.audit_mode().unwrap_or("standard");
                let audit_client = oauth_owner.unwrap_or(&client.id);
                let record = |phase| {
                    state
                        .mutations
                        .record_runtime_mode(audit_client, name, mode, phase)
                };
                if !record(AuditPhase::Intent) {
                    return Some(tool_text(true, "Audit intent unavailable"));
                }
                let result =
                    crate::inspection::run(tool, args, state.policy.path(), settings, client);
                let phase = if result["isError"] == true {
                    AuditPhase::Failure
                } else {
                    AuditPhase::Success
                };
                return Some(if record(phase) {
                    result
                } else {
                    tool_text(true, "Audit outcome unavailable")
                });
            }
            #[cfg(target_os = "linux")]
            if tool.is_git() {
                let mode = client.mode.audit_mode().unwrap_or("standard");
                let audit_client = oauth_owner.unwrap_or(&client.id);
                let record = |phase| {
                    state
                        .mutations
                        .record_runtime_mode(audit_client, name, mode, phase)
                };
                if !record(AuditPhase::Intent) {
                    return Some(tool_text(true, "Audit intent unavailable"));
                }
                let result =
                    crate::tools::git::run(tool, args, state.policy.path(), settings, client);
                let phase = if result["isError"] == true {
                    AuditPhase::Failure
                } else {
                    AuditPhase::Success
                };
                return Some(if record(phase) {
                    result
                } else {
                    tool_text(true, "Audit outcome unavailable")
                });
            }
            #[cfg(target_os = "linux")]
            if tool.is_extension() {
                let mode = client.mode.audit_mode().unwrap_or("standard");
                let audit_client = oauth_owner.unwrap_or(&client.id);
                let record = |phase| {
                    state
                        .mutations
                        .record_runtime_mode(audit_client, name, mode, phase)
                };
                if !record(AuditPhase::Intent) {
                    return Some(tool_text(true, "Audit intent unavailable"));
                }
                let result = match crate::tools::extensions::run(
                    tool,
                    args,
                    state.policy.path(),
                    settings,
                    client,
                ) {
                    Ok(value) => tool_text(false, &value.to_string()),
                    Err(err) => tool_text(true, &err),
                };
                let phase = if result["isError"] == true {
                    AuditPhase::Failure
                } else {
                    AuditPhase::Success
                };
                return Some(if record(phase) {
                    result
                } else {
                    tool_text(true, "Audit outcome unavailable")
                });
            }
            #[cfg(target_os = "linux")]
            if (oauth_owner.is_none() || client.mode == ExecutionMode::BroadYolo)
                && (client.mode.audit_mode().is_some() || tool.process_control())
            {
                return Some(privileged_tool(
                    state,
                    settings,
                    client,
                    oauth_owner,
                    oauth_identity,
                    tool,
                    name,
                    args,
                    now,
                ));
            }
            #[cfg(target_os = "linux")]
            if tool == Tool::ReadFile {
                return Some(
                    client_file_tool(state, settings, client, tool, args, now)
                        .unwrap_or_else(|| tool_text(true, "Operation outside an approved scope")),
                );
            }
            #[cfg(not(target_os = "linux"))]
            if tool == Tool::ReadFile {
                let files = FileAccess::new(&client.root);
                return Some(match files {
                    Ok(files) => read_file(&files, args),
                    Err(_) => tool_text(true, "Client root unavailable"),
                });
            }
            if tool.action().is_job() {
                #[cfg(target_os = "linux")]
                if let (Some(jobs), Some(root)) = (state.jobs.as_ref(), client.job_root.as_ref()) {
                    if state.oauth.is_some() && oauth_owner.is_none() {
                        return Some(tool_text(true,"OAuth job owner unavailable"));
                    }
                    if oauth_owner.is_some() && tool == Tool::JobWait
                        && args.and_then(|a|a.get("timeout_seconds")).and_then(Value::as_u64).is_none_or(|v|v>2) {
                        return Some(tool_text(true,"OAuth job_wait requires timeout_seconds in 0..=2"));
                    }
                    let session = if tool.process_control() {
                        if let Some(identity) = oauth_identity {
                            let Some(oauth) = state.oauth.as_ref().filter(|o| o.workspace_interactive) else {
                                return Some(tool_text(true, "Interactive OAuth sessions are not enabled"));
                            };
                            let Some(state_dir) = oauth.durable_state_dir.as_deref() else {
                                return Some(tool_text(true, "Durable OAuth state unavailable"));
                            };
                            Some(SessionAuthorization {
                                config: state.policy.path(),
                                digest: &settings.digest,
                                expires_at: identity.expires_at.min(client.expires_at),
                                oauth: Some(OAuthSessionAuthorization {
                                    state_dir,
                                    oauth_client: &identity.oauth_client,
                                    local_client: &identity.local_client,
                                    family: &identity.family,
                                }),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let owner = oauth_owner.unwrap_or(&client.id);
                    if oauth_owner.is_some()
                        && tool.process_control()
                        && !state.mutations.record_runtime_mode(owner, name, "standard", AuditPhase::Intent)
                    {
                        return Some(tool_text(true, "Audit intent unavailable"));
                    }
                    let oauth_grant = oauth_identity.and_then(|identity| {
                        state
                            .oauth
                            .as_ref()
                            .and_then(|o| o.durable_state_dir.as_deref())
                            .map(|state_dir| OAuthSessionAuthorization {
                                state_dir,
                                oauth_client: &identity.oauth_client,
                                local_client: &identity.local_client,
                                family: &identity.family,
                            })
                    });
                    let result = jobs.call(
                        tool,
                        args,
                        owner,
                        root,
                        JobPolicy {
                            oauth_family:oauth_owner.is_some(),
                            oauth_bounded_workspace:oauth_owner.is_some() && state.oauth.as_ref().is_some_and(|o| o.bounded_workspace),
                            yolo: false,
                            session,
                            oauth: oauth_grant,
                            full: false,
                            job_runtime_limit_seconds: client.job_runtime_limit_seconds,
                            job_cpu_percent_limit: client.job_cpu_percent_limit,
                            job_memory_bytes_limit: client.job_memory_bytes_limit,
                            job_output_limit_bytes: client.job_output_limit_bytes,
                            job_retention_count: client.job_retention_count,
                            broad: None,
                            workspace_mounts: settings.managed.then_some(&client.job_extra_roots),
                        },
                    );
                    if oauth_owner.is_some() && tool.process_control() {
                        let phase = if result["isError"].as_bool() == Some(true) {
                            AuditPhase::Failure
                        } else {
                            AuditPhase::Success
                        };
                        if !state.mutations.record_runtime_mode(owner, name, "standard", phase) {
                            return Some(tool_text(
                                true,
                                "Audit outcome unavailable; operation status uncertain",
                            ));
                        }
                    }
                    return Some(result);
                }
                return Some(tool_text(true, "Jobs unavailable"));
            }
            #[cfg(target_os = "linux")]
            if tool.is_rewind() || client.explicit_extra_roots && !client.extra_roots.is_empty() {
                return Some(
                    client_file_tool(state, settings, client, tool, args, now)
                        .unwrap_or_else(|| tool_text(true, "Operation outside an approved scope")),
                );
            }
            #[cfg(target_os = "linux")]
            if let Some(root) = client.mutation_root.as_ref() {
                let strict;
                let root=if state.oauth.is_some() {
                    strict=match root.strict_alias_scope() {
                        Ok(root)=>root,
                        Err(_)=>return Some(tool_text(true,"OAuth workspace identity unavailable")),
                    };
                    &strict
                } else {root};
                return Some(state.mutations.call(
                    tool,
                    args,
                    root,
                    &client.id,
                    now,
                    (client.mode, timeshift_limit(client, settings)),
                ));
            }
            Some(tool_text(true, "Mutation unavailable"))
        },
    );

    #[cfg(target_os = "linux")]
    if let Some((id, started)) = trace
        && let Some(admin) = &state.admin
        && let Ok(mut trace) = admin.trace.lock()
    {
        trace.finish(&id, started, response.as_ref());
    }
    match response {
        None => simple(StatusCode::ACCEPTED, ""),
        Some(response) => {
            #[cfg(target_os = "linux")]
            let outcome =
                if response.get("error").is_some() || response["result"]["isError"] == true {
                    activity::Status::Failure
                } else {
                    activity::Status::Success
                };
            let reply = json_response(StatusCode::OK, response, None);
            #[cfg(target_os = "linux")]
            {
                let mut reply = reply;
                reply.extensions_mut().insert(outcome);
                reply
            }
            #[cfg(not(target_os = "linux"))]
            reply
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn privileged_tool(
    state: &State,
    settings: &Configuration,
    client: &Client,
    oauth_owner: Option<&str>,
    oauth_identity: Option<&mcp_gateway::http_common::oauth_http::Identity>,
    tool: Tool,
    name: &str,
    args: Option<&Value>,
    now: u64,
) -> Value {
    let mode = client.mode.audit_mode().unwrap_or("standard");
    let full = client.mode == ExecutionMode::Full;
    let owner = oauth_owner.unwrap_or(&client.id);
    if !state
        .mutations
        .record_runtime_mode(owner, name, mode, AuditPhase::Intent)
    {
        return tool_text(true, "Audit intent unavailable");
    }
    let result = if tool.action().is_job() {
        if oauth_owner.is_some()
            && tool == Tool::JobWait
            && args
                .and_then(|a| a.get("timeout_seconds"))
                .and_then(Value::as_u64)
                .is_none_or(|v| v > 2)
        {
            tool_text(true, "OAuth job_wait requires timeout_seconds in 0..=2")
        } else {
            match (state.jobs.as_ref(), client.job_root.as_ref()) {
                (Some(jobs), Some(root)) => {
                    let broad = if client.mode == ExecutionMode::BroadYolo
                        && (tool.process_control()
                            || matches!(tool.action(), Action::StartJob | Action::RunShortJob))
                    {
                        crate::jobs::broad::Broad::prepare(state.policy.path(), settings).map(Some)
                    } else {
                        Ok(None)
                    };
                    let oauth_grant = oauth_identity.and_then(|identity| {
                        state
                            .oauth
                            .as_ref()
                            .and_then(|o| o.durable_state_dir.as_deref())
                            .map(|state_dir| OAuthSessionAuthorization {
                                state_dir,
                                oauth_client: &identity.oauth_client,
                                local_client: &identity.local_client,
                                family: &identity.family,
                            })
                    });
                    match broad {
                        Ok(broad) => jobs.call(
                            tool,
                            args,
                            owner,
                            root,
                            JobPolicy {
                                oauth_family: oauth_owner.is_some(),
                                oauth_bounded_workspace: false,
                                yolo: client.mode.audit_mode().is_some() && !full,
                                session: tool.process_control().then_some(SessionAuthorization {
                                    config: state.policy.path(),
                                    digest: &settings.digest,
                                    expires_at: oauth_identity.map_or(client.expires_at, |id| {
                                        id.expires_at.min(client.expires_at)
                                    }),
                                    oauth: oauth_grant,
                                }),
                                oauth: oauth_grant,
                                full,
                                job_runtime_limit_seconds: client.job_runtime_limit_seconds,
                                job_cpu_percent_limit: client.job_cpu_percent_limit,
                                job_memory_bytes_limit: client.job_memory_bytes_limit,
                                job_output_limit_bytes: client.job_output_limit_bytes,
                                job_retention_count: client.job_retention_count,
                                broad: broad.as_ref(),
                                workspace_mounts: (!full
                                    && broad.is_none()
                                    && (settings.managed || client.mode.audit_mode().is_some()))
                                .then_some(&client.job_extra_roots),
                            },
                        ),
                        Err(reason) => tool_text(true, &format!("Broad job denied: {reason}")),
                    }
                }
                _ => tool_text(true, "Jobs unavailable"),
            }
        }
    } else {
        client_file_tool(state, settings, client, tool, args, now).unwrap_or_else(|| {
            tool_text(true, "Operation unavailable or outside an approved scope")
        })
    };

    let phase = if result["isError"].as_bool() == Some(true) {
        AuditPhase::Failure
    } else {
        AuditPhase::Success
    };
    if !state
        .mutations
        .record_runtime_mode(owner, name, mode, phase)
    {
        return tool_text(
            true,
            "Audit outcome unavailable; operation status uncertain",
        );
    }
    result
}

#[cfg(target_os = "linux")]
fn client_file_tool(
    state: &State,
    settings: &Configuration,
    client: &Client,
    tool: Tool,
    args: Option<&Value>,
    now: u64,
) -> Option<Value> {
    use std::path::{Component, Path};

    let args = args?.as_object()?;
    let raw_path = args.get("path")?.as_str()?;
    let path = Path::new(raw_path);
    if raw_path.split('/').any(|part| part == ".." || part == ".") {
        return None;
    }
    let yolo = client.mode == ExecutionMode::PersistentYolo;
    let full_root;
    let absolute;
    let (root, relative) = if matches!(client.mode, ExecutionMode::Full | ExecutionMode::BroadYolo)
    {
        if raw_path.is_empty() || raw_path.ends_with('/') {
            return None;
        }
        absolute = client.root.join(path);
        full_root = if client.mode == ExecutionMode::BroadYolo {
            crate::jobs::broad::Broad::prepare(state.policy.path(), settings)
                .ok()?
                .file_parent(&absolute, tool != Tool::ReadFile)
                .ok()?
        } else {
            crate::tools::MutationRoot::open_host_parent(absolute.parent()?).ok()?
        };
        (&full_root, Path::new(absolute.file_name()?))
    } else if path.is_absolute() {
        if !yolo && !(client.explicit_extra_roots && !client.extra_roots.is_empty()) {
            return None;
        }
        client
            .mutation_root
            .iter()
            .chain(&client.extra_roots)
            .find_map(|root| {
                path.strip_prefix(root.path())
                    .ok()
                    .map(|relative| (root, relative))
            })?
    } else {
        (client.mutation_root.as_ref()?, path)
    };
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return None;
    }
    if client.mode != ExecutionMode::Full
        && operator::policy_path(state.policy.path(), &root.path().join(relative))
    {
        return None;
    }
    let relative = relative.to_str()?;
    if tool == Tool::ReadFile {
        if args.len() != 1 {
            return None;
        }
        return Some(match root.read(relative) {
            Ok(content) => tool_text(false, &content),
            Err(message) => tool_text(true, message),
        });
    }
    let mut args = args.clone();
    args.insert("path".into(), relative.into());
    Some(state.mutations.call(
        tool,
        Some(&Value::Object(args)),
        root,
        &client.id,
        now,
        (client.mode, timeshift_limit(client, settings)),
    ))
}

fn permit_tool(
    tool: Tool,
    client: &Client,
    state: &State,
    settings: &Configuration,
    audited: bool,
    now: u64,
) -> Result<(), &'static str> {
    const DENIED: &str = "Not authorized or capability unavailable";
    if !client.tools.contains(&tool) || !authorized(client, tool.action(), state, audited, now) {
        return Err(DENIED);
    }
    if matches!(
        tool,
        Tool::ProcessInput | Tool::ProcessResize | Tool::ShellStatus | Tool::ShellReset
    ) && (!client.tools.contains(&Tool::ProcessStart)
        || !authorized(client, Action::ProcessStart, state, audited, now))
    {
        return Err(DENIED);
    }
    if tool == Tool::ShellReset && !authorized(client, Action::CancelJob, state, audited, now) {
        return Err(DENIED);
    }
    #[cfg(target_os = "linux")]
    if state
        .oauth
        .as_ref()
        .is_some_and(|oauth| tool.process_control() && !oauth.workspace_interactive)
    {
        return Err(DENIED);
    }
    if tool_available(tool, client, state, settings) {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if matches!(tool.action(), Action::WriteFile | Action::ApplyPatch)
        && !state.mutations.available()
    {
        return Err("Audit intent unavailable");
    }
    Err(DENIED)
}

#[cfg(target_os = "linux")]
fn timeshift_limit(client: &Client, settings: &Configuration) -> Option<usize> {
    (settings.managed
        && client.mode != ExecutionMode::Full
        && client.tools.contains(&Tool::Rewind)
        && client.tools.contains(&Tool::ReadFile))
    .then_some(client.timeshift_retention_count)
}

fn tool_available(tool: Tool, client: &Client, state: &State, settings: &Configuration) -> bool {
    if tool.is_rewind() {
        #[cfg(target_os = "linux")]
        return timeshift_limit(client, settings).is_some()
            && state.mutations.available()
            && (tool == Tool::Rewind || client.tools.contains(&Tool::WriteFile));
        #[cfg(not(target_os = "linux"))]
        return false;
    }
    if tool.process_control() {
        #[cfg(target_os = "linux")]
        return settings.managed
            && !matches!(client.mode, ExecutionMode::Full)
            && client.job_root.is_some()
            && state.jobs.as_ref().is_some_and(Jobs::sessions_available)
            && state.mutations.available()
            && state.oauth.as_ref().is_none_or(|oauth| {
                oauth.workspace_interactive
                    && state.jobs.as_ref().is_some_and(Jobs::oauth_launch_available)
            });
        #[cfg(not(target_os = "linux"))]
        return false;
    }
    if matches!(tool, Tool::SkillsList | Tool::SkillsRead) {
        #[cfg(target_os = "linux")]
        return settings.skills.is_some() && state.mutations.available();
        #[cfg(not(target_os = "linux"))]
        {
            let _ = settings;
            return false;
        }
    }
    if matches!(tool, Tool::UpstreamsList | Tool::UpstreamsCall) {
        #[cfg(target_os = "linux")]
        return !settings.upstreams.empty() && state.mutations.available();
        #[cfg(not(target_os = "linux"))]
        return false;
    }
    if tool.is_extension() {
        #[cfg(target_os = "linux")]
        return state.mutations.available();
        #[cfg(not(target_os = "linux"))]
        return false;
    }
    if tool.inspection() {
        #[cfg(target_os = "linux")]
        return state.mutations.available();
        #[cfg(not(target_os = "linux"))]
        return false;
    }
    if tool.is_git() {
        #[cfg(target_os = "linux")]
        return state.mutations.available()
            && (client.mutation_root.is_some()
                || matches!(client.mode, ExecutionMode::BroadYolo | ExecutionMode::Full));
        #[cfg(not(target_os = "linux"))]
        return false;
    }
    if tool == Tool::ReadFile {
        return true;
    }
    if tool.action().is_job() {
        #[cfg(target_os = "linux")]
        {
            if state.oauth.is_some() && matches!(tool,Tool::RunCommand|Tool::JobStart|Tool::ExecCommand|Tool::TaskRun) {
                return client.job_root.is_some() && state.jobs.as_ref().is_some_and(Jobs::oauth_launch_available);
            }
            return client.job_root.is_some() && state.jobs.as_ref().is_some_and(Jobs::available);
        }
        #[cfg(not(target_os = "linux"))]
        return false;
    }
    mutation_available(client, &state.mutations)
}

fn authorized(
    client: &Client,
    action: Action,
    state: &State,
    audit_available: bool,
    now: u64,
) -> bool {
    if client.is_disabled() {
        return false;
    }
    let audit_available =
        audit_available && (client.mode.audit_mode().is_none() || state.mutations.available());
    let grant = Grant {
        principal: &client.id,
        root: &client.root,
        actions: &client.actions,
        expires_at_unix_seconds: client.expires_at,
    };
    policy::authorize(&PolicyInput {
        principal: Some(&client.id),
        action,
        requested_root: &client.root,
        grant: Some(&grant),
        mode: client.mode,
        audit_available,
        now_unix_seconds: now,
    })
    .is_ok()
}

fn mutation_available(client: &Client, mutations: &MutationAudit) -> bool {
    #[cfg(target_os = "linux")]
    {
        client.mutation_root.is_some() && mutations.available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (client, mutations);
        false
    }
}

async fn bounded_body(mut body: Incoming, limit: usize) -> Result<Vec<u8>, StatusCode> {
    let mut data = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Ok(chunk) = frame.into_data() {
            if chunk.len() > limit.saturating_sub(data.len()) {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            data.extend_from_slice(&chunk);
        }
    }
    Ok(data)
}

fn simple(status: StatusCode, message: &'static str) -> Reply {
    let mut response = Response::new(Full::new(Bytes::from_static(message.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(target_os = "linux")]
fn copy_clipboard(text: &str) -> bool {
    use std::process::{Command, Stdio};
    let copy_with = |program: &str, args: &[&str]| -> bool {
        let Ok(mut child) = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        if let Some(mut stdin) = child.stdin.take()
            && stdin.write_all(text.as_bytes()).is_err()
        {
            return false;
        }
        child.wait().is_ok_and(|status| status.success())
    };
    if std::env::var_os("WAYLAND_DISPLAY").is_some()
        && copy_with("wl-copy", &["--trim-newline"])
    {
        return true;
    }
    if std::env::var_os("DISPLAY").is_some() {
        return copy_with("xclip", &["-selection", "clipboard", "-in"])
            || copy_with("xsel", &["--clipboard", "--input"]);
    }
    false
}

fn json_response(status: StatusCode, body: Value, session: Option<&str>) -> Reply {
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(id) = session
        && let Ok(value) = HeaderValue::from_str(id)
    {
        response.headers_mut().insert("Mcp-Session-Id", value);
    }
    response
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}


fn audit(event: &'static str) -> bool {
    writeln!(std::io::stderr().lock(), "MCP_HTTP_EVENT={event}").is_ok()
}
