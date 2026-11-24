//! Explicitly launched, loopback-only authenticated MCP-over-HTTP transport.
//! No persistent unit, public listener, or privileged operation is created.

pub(crate) mod admission;
#[cfg(target_os = "linux")]
pub(crate) mod dashboard;
#[cfg(target_os = "linux")]
pub(crate) mod funnel;
#[cfg(target_os = "linux")]
pub(crate) mod operator;
#[cfg(target_os = "linux")]
pub(crate) mod scope;

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

use crate::file_access::FileAccess;
#[cfg(target_os = "linux")]
use crate::jobs::{JobPolicy, Jobs};
use crate::protocol::Protocol;
use crate::tools::mutation::MutationAudit;
#[cfg(not(target_os = "linux"))]
use crate::tools::registry::read_file;
use crate::tools::registry::{Tool, tool_text};

#[cfg(not(target_os = "linux"))]
use admission::load_clients;
use admission::{Client, Configuration, authenticate};
#[cfg(target_os = "linux")]
use mcp_gateway::security::audit::AuditPhase;

const MAX_BODY: usize = 1_048_576;
const MAX_SESSIONS: usize = 128;
const MAX_CONNECTIONS: usize = 32;
const SESSION_IDLE: Duration = Duration::from_secs(1800);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const MCP_VERSION: &str = "2025-11-25";

type Reply = Response<Full<Bytes>>;

struct Session {
    owner: String,
    public: bool,
    protocol: Protocol,
    last_used: Instant,
}

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
}

pub fn run(args: Vec<OsString>) -> Result<(), String> {
    let mut listen = None;
    let mut config = None;
    let mut args = args.into_iter();
    while let Some(key) = args.next() {
        match key.to_str() {
            Some("--listen") if listen.is_none() => listen = args.next(),
            Some("--config") if config.is_none() => config = args.next(),
            _ => return Err(
                "usage: mcp-gateway http --listen 127.0.0.1:PORT --config /absolute/clients.json"
                    .into(),
            ),
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
    let has_mutation_grants = config.clients.iter().any(|client| {
        client.actions.contains(&Action::WriteFile) || client.actions.contains(&Action::ApplyPatch)
    });
    let audit_log = config.audit_log.as_deref();
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
                    .map(|addr| dashboard::Admin::new(addr, path))
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
        });
        // No token, hash, root, request content, or auth configuration is logged.
        #[cfg(target_os = "linux")]
        if let Some(admin) = &state.admin {
            eprintln!("ADMIN_HTTP_LISTEN={}", admin.addr);
        }
        eprintln!("MCP_HTTP_LISTEN={actual}");
        #[cfg(target_os = "linux")]
        let admin_permits = Arc::new(Semaphore::new(8));
        let (shutdown, _) = watch::channel(false);
        let mut connections = JoinSet::new();
        loop {
            let event = poll_fn(|cx| {
                #[cfg(unix)]
                if term.poll_recv(cx).is_ready() || interrupt.poll_recv(cx).is_ready() {
                    return Poll::Ready(None);
                }
                #[cfg(target_os = "linux")]
                if let Some(admin) = &admin_listener
                    && let Poll::Ready(event) = admin.poll_accept(cx)
                {
                    return Poll::Ready(Some((true, event)));
                }
                listener.poll_accept(cx).map(|event| Some((false, event)))
            })
            .await;
            let Some((is_admin, event)) = event else {
                break;
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
                let service = service_fn(move |request| {
                    let state = state.clone();
                    async move {
                        let result = tokio::time::timeout(HTTP_TIMEOUT, async {
                            #[cfg(target_os = "linux")]
                            if is_admin {
                                return dashboard::serve(request, state).await;
                            }
                            serve(request, state, peer.ip()).await
                        })
                        .await;
                        Ok::<_, Infallible>(result.unwrap_or_else(|_| {
                            simple(StatusCode::REQUEST_TIMEOUT, "Request timed out")
                        }))
                    }
                });
                let mut builder = http1::Builder::new();
                if is_admin {
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
        drop(listener);
        let _ = shutdown.send(true);
        tokio::time::timeout(Duration::from_secs(7), async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .map_err(|_| "Timed out draining HTTP connections")?;
        Ok(())
    });
    // Detached job runners own their leases. Reaping waiters must not keep
    // the gateway alive after its listener and in-flight HTTP work drain.
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

async fn serve(request: Request<Incoming>, state: Arc<State>, peer: IpAddr) -> Reply {
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
        return serve_public(request, state, peer, origin, allow_secret_path).await;
    }
    if request.headers().get_all(header::ORIGIN).iter().count() > 1
        || request
            .headers()
            .get(header::ORIGIN)
            .is_some_and(|value| value.as_bytes() != origin.as_bytes())
    {
        return simple(StatusCode::FORBIDDEN, "Invalid Origin");
    }
    serve_admitted(request, state, peer, false, None).await
}

#[cfg(target_os = "linux")]
async fn serve_public(
    request: Request<Incoming>,
    state: Arc<State>,
    peer: IpAddr,
    origin: funnel::Origin,
    allow_secret_path: bool,
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
        serve_admitted(request, state, peer, true, proof).await
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
) -> Reply {
    #[cfg(not(target_os = "linux"))]
    let _ = proof;
    if request
        .headers()
        .get("MCP-Protocol-Version")
        .is_some_and(|value| value.as_bytes() != MCP_VERSION.as_bytes())
    {
        if marker {
            let _ = audit("funnel.unsupported_protocol");
        }
        return simple(StatusCode::BAD_REQUEST, "Unsupported protocol version");
    }

    // Admission precedes reading even one byte of an untrusted request body.
    let now = unix_seconds();
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
    let settings = {
        let snapshot_state = state.clone();
        match tokio::task::spawn_blocking(move || {
            snapshot_state.policy.read().map(|(_, settings)| settings)
        })
        .await
        {
            Ok(Ok(settings)) => settings,
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

    let bearer = request.headers().get(header::AUTHORIZATION).cloned();
    #[cfg(target_os = "linux")]
    let client_index = if marker {
        funnel::authenticate(&settings, proof.as_ref(), now)
    } else {
        authenticate(clients, bearer.as_ref(), now)
    };
    #[cfg(not(target_os = "linux"))]
    let client_index = authenticate(clients, bearer.as_ref(), now);
    let Some(client_index) = client_index else {
        if marker {
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
    let client = &clients[client_index];
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
    let accepted = audit("auth.accepted");
    if !accepted {
        return simple(StatusCode::SERVICE_UNAVAILABLE, "Audit unavailable");
    }
    // Even unsupported HTTP methods require Host/Origin validation and
    // bearer admission. GET without SSE is explicitly 405 under MCP 2025-11-25.
    if request.method() != Method::POST {
        return simple(StatusCode::METHOD_NOT_ALLOWED, "Only POST is supported");
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .is_none_or(|value| value.as_bytes() != b"application/json")
    {
        return simple(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON required");
    }

    let session_header = request
        .headers()
        .get("Mcp-Session-Id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
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
        sessions.retain(|_, value| value.last_used.elapsed() < SESSION_IDLE);
        if sessions.len() >= MAX_SESSIONS {
            return simple(StatusCode::SERVICE_UNAVAILABLE, "Session capacity reached");
        }
        let Ok(id) = new_session_id() else {
            return simple(StatusCode::SERVICE_UNAVAILABLE, "Session unavailable");
        };
        sessions.insert(
            id.clone(),
            Session {
                owner: client.id.clone(),
                public: marker,
                protocol,
                last_used: Instant::now(),
            },
        );
        return json_response(StatusCode::OK, reply, Some(&id));
    }

    let Some(session_id) = session_header else {
        return simple(StatusCode::BAD_REQUEST, "MCP session required");
    };
    let mut sessions = state.sessions.lock().await;
    let Some(session) = sessions.get_mut(&session_id) else {
        return simple(StatusCode::NOT_FOUND, "Unknown MCP session");
    };
    if session.owner != client.id || session.public != marker {
        return simple(StatusCode::FORBIDDEN, "Session access denied");
    }
    if session.last_used.elapsed() >= SESSION_IDLE {
        sessions.remove(&session_id);
        return simple(StatusCode::NOT_FOUND, "Expired MCP session");
    }
    session.last_used = Instant::now();

    #[cfg(target_os = "linux")]
    if matches!(method, Some("tools/list" | "tools/call")) {
        // Tool requests leave protocol phase unchanged. Release session state
        // before waiting on storage, a short command, or crash instrumentation.
        let mut protocol = session.protocol.clone();
        drop(sessions);
        return match tokio::task::spawn_blocking(move || {
            let Ok((_admission, current)) = state.policy.read() else {
                return simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authorization state unavailable or restart required",
                );
            };
            let now = unix_seconds();
            let index = if marker {
                funnel::authenticate(&current, proof.as_ref(), now)
            } else {
                authenticate(&current.clients, bearer.as_ref(), now)
            };
            let Some(index) = index else {
                return simple(StatusCode::UNAUTHORIZED, "Unauthorized");
            };
            if current.clients[index].id != settings.clients[client_index].id {
                return simple(StatusCode::FORBIDDEN, "Session access denied");
            }
            dispatch_tools(
                &mut protocol,
                payload,
                &state,
                &current.clients[index],
                &current,
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
    dispatch_tools(&mut session.protocol, payload, &state, client, &settings)
}

fn dispatch_tools(
    protocol: &mut Protocol,
    payload: Value,
    state: &State,
    client: &Client,
    settings: &Configuration,
) -> Reply {
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
            let mut tools: Vec<_> = Tool::ALL
                .into_iter()
                .filter(|tool| {
                    authorized(client, tool.action(), state, audited, unix_seconds())
                        && tool_available(*tool, client, state, settings)
                })
                .map(Tool::schema)
                .collect();
            #[cfg(target_os = "linux")]
            if state.mutations.available()
                && authorized(client, Action::CallUpstream, state, audited, unix_seconds())
                && !client.upstreams.servers.is_empty()
            {
                let mode = client.mode.audit_mode().unwrap_or("standard");
                let record = |phase| {
                    state.mutations.record_runtime_mode(
                        &client.id,
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
            #[cfg(target_os = "linux")]
            if tool == Some(Tool::UpstreamsList) {
                if !state.mutations.available()
                    || !authorized(
                        client,
                        Action::ListUpstreams,
                        state,
                        audit("policy.checked"),
                        now,
                    )
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
                if !state.mutations.available()
                    || !authorized(
                        client,
                        Action::CallUpstream,
                        state,
                        audit("policy.checked"),
                        now,
                    )
                {
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
                                    .record_runtime_mode(&client.id, tool, mode, phase)
                            },
                        )
                        .unwrap_or_else(|reason| tool_text(true, reason)),
                );
            }
            let permitted = tool.is_some_and(|tool| {
                authorized(client, tool.action(), state, audit("policy.checked"), now)
            });
            if !permitted {
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
                return tool.map(|_| tool_text(true, "Not authorized or capability unavailable"));
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
            if tool.inspection() {
                let mode = client.mode.audit_mode().unwrap_or("standard");
                let record = |phase| {
                    state
                        .mutations
                        .record_runtime_mode(&client.id, name, mode, phase)
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
            if client.mode.audit_mode().is_some() {
                return Some(privileged_tool(
                    state, settings, client, tool, name, args, now,
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
                    return Some(jobs.call(
                        tool,
                        args,
                        &client.id,
                        root,
                        JobPolicy {
                            yolo: false,
                            full: false,
                            broad: None,
                            workspace_mounts: settings.managed.then_some(&client.job_extra_roots),
                        },
                    ));
                }
                return Some(tool_text(true, "Jobs unavailable"));
            }
            #[cfg(target_os = "linux")]
            if client.explicit_extra_roots && !client.extra_roots.is_empty() {
                return Some(
                    client_file_tool(state, settings, client, tool, args, now)
                        .unwrap_or_else(|| tool_text(true, "Operation outside an approved scope")),
                );
            }
            #[cfg(target_os = "linux")]
            if let Some(root) = client.mutation_root.as_ref() {
                return Some(
                    state
                        .mutations
                        .call(tool, args, root, &client.id, now, false),
                );
            }
            Some(tool_text(true, "Mutation unavailable"))
        },
    );

    match response {
        None => simple(StatusCode::ACCEPTED, ""),
        Some(response) => json_response(StatusCode::OK, response, None),
    }
}

#[cfg(target_os = "linux")]
fn privileged_tool(
    state: &State,
    settings: &Configuration,
    client: &Client,
    tool: Tool,
    name: &str,
    args: Option<&Value>,
    now: u64,
) -> Value {
    let Some(mode) = client.mode.audit_mode() else {
        return tool_text(true, "Privileged execution mode unavailable");
    };
    let full = client.mode == ExecutionMode::Full;
    if !state
        .mutations
        .record_runtime_mode(&client.id, name, mode, AuditPhase::Intent)
    {
        return tool_text(true, "Audit intent unavailable");
    }
    let result = if tool.action().is_job() {
        match (state.jobs.as_ref(), client.job_root.as_ref()) {
            (Some(jobs), Some(root)) => {
                let broad = if client.mode == ExecutionMode::BroadYolo
                    && matches!(tool.action(), Action::StartJob | Action::RunShortJob)
                {
                    crate::jobs::broad::Broad::prepare(state.policy.path(), settings).map(Some)
                } else {
                    Ok(None)
                };
                match broad {
                    Ok(broad) => jobs.call(
                        tool,
                        args,
                        &client.id,
                        root,
                        JobPolicy {
                            yolo: !full,
                            full,
                            broad: broad.as_ref(),
                            workspace_mounts: (!full && broad.is_none())
                                .then_some(&client.job_extra_roots),
                        },
                    ),
                    Err(reason) => tool_text(true, &format!("Broad job denied: {reason}")),
                }
            }
            _ => tool_text(true, "Jobs unavailable"),
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
        .record_runtime_mode(&client.id, name, mode, phase)
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
        yolo || client.mode == ExecutionMode::BroadYolo,
    ))
}

fn tool_available(tool: Tool, client: &Client, state: &State, settings: &Configuration) -> bool {
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
    if tool.inspection() {
        #[cfg(target_os = "linux")]
        return state.mutations.available();
        #[cfg(not(target_os = "linux"))]
        return false;
    }
    if tool == Tool::ReadFile {
        return true;
    }
    if tool.action().is_job() {
        #[cfg(target_os = "linux")]
        {
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

fn new_session_id() -> Result<String, getrandom::Error> {
    let mut random = [0_u8; 24];
    getrandom::fill(&mut random)?;
    let mut result = String::with_capacity(48);
    for byte in random {
        use std::fmt::Write as _;
        let _ = write!(&mut result, "{byte:02x}");
    }
    Ok(result)
}

fn audit(event: &'static str) -> bool {
    writeln!(std::io::stderr().lock(), "MCP_HTTP_EVENT={event}").is_ok()
}
