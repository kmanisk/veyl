//! Explicitly launched, loopback-only authenticated MCP-over-HTTP transport.
//! No persistent unit, public listener, or privileged operation is created.

pub(crate) mod admission;

use std::collections::HashMap;
use std::convert::Infallible;
use std::ffi::OsString;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};

use mcp_gateway::security::policy::{self, Action, ExecutionMode, Grant, PolicyInput};

use crate::file_access::FileAccess;
#[cfg(target_os = "linux")]
use crate::jobs::Jobs;
use crate::protocol::Protocol;
use crate::tools::mutation::MutationAudit;
use crate::tools::registry::{Tool, read_file, tool_text};

use admission::{Client, authenticate, load_clients};

const MAX_BODY: usize = 1_048_576;
const MAX_SESSIONS: usize = 128;
const MAX_CONNECTIONS: usize = 32;
const SESSION_IDLE: Duration = Duration::from_secs(1800);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const MCP_VERSION: &str = "2025-11-25";

type Reply = Response<Full<Bytes>>;

struct Session {
    owner: usize,
    protocol: Protocol,
    last_used: Instant,
}

struct Failure {
    count: u32,
    until: Instant,
}

struct State {
    addr: SocketAddr,
    clients: Vec<Client>,
    mutations: MutationAudit,
    #[cfg(target_os = "linux")]
    jobs: Option<Jobs>,
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<HashMap<IpAddr, Failure>>,
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
    let config = load_clients(&path)?;
    let has_mutation_grants = config.clients.iter().any(|client| {
        client.actions.contains(&Action::WriteFile) || client.actions.contains(&Action::ApplyPatch)
    });
    let audit_log = config.audit_log.as_deref();
    let mutations = MutationAudit::open(
        &path,
        audit_log,
        #[cfg(target_os = "linux")]
        config.audit_limits,
    )?;
    if has_mutation_grants && !mutations.available() {
        return Err("Mutation grants require a private, available audit log".into());
    }
    #[cfg(target_os = "linux")]
    mutations.recover(&config.clients)?;
    #[cfg(target_os = "linux")]
    let jobs = config
        .jobs
        .map(|(state, profiles)| {
            Jobs::open(
                &state,
                profiles,
                config.audit_log.as_deref().ok_or("Missing job audit log")?,
                config.audit_limits,
            )
        })
        .transpose()?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "cannot initialize HTTP runtime")?;
    runtime.block_on(async move {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|_| "cannot bind requested loopback address")?;
        let actual = listener
            .local_addr()
            .map_err(|_| "cannot inspect bound listener")?;
        let state = Arc::new(State {
            addr: actual,
            clients: config.clients,
            mutations,
            #[cfg(target_os = "linux")]
            jobs,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
        });
        // No token, hash, root, request content, or auth configuration is logged.
        eprintln!("MCP_HTTP_LISTEN={actual}");
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let (stream, peer) = listener
                .accept()
                .await
                .map_err(|_| "loopback accept failed")?;
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let state = state.clone();
                    async move {
                        let result =
                            tokio::time::timeout(HTTP_TIMEOUT, serve(request, state, peer.ip()))
                                .await;
                        Ok::<_, Infallible>(result.unwrap_or_else(|_| {
                            simple(StatusCode::REQUEST_TIMEOUT, "Request timed out")
                        }))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                drop(permit);
            });
        }
        #[allow(unreachable_code)]
        Ok(())
    })
}

async fn serve(request: Request<Incoming>, state: Arc<State>, peer: IpAddr) -> Reply {
    if request.uri().path() != "/mcp" {
        return simple(StatusCode::NOT_FOUND, "Not found");
    }
    let expected = format!("127.0.0.1:{}", state.addr.port());
    let local_alias = format!("localhost:{}", state.addr.port());
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    if !matches!(host, Some(h) if h == expected || h == local_alias) {
        return simple(StatusCode::FORBIDDEN, "Invalid Host");
    }
    if let Some(origin) = request.headers().get(header::ORIGIN) {
        let actual = origin.to_str().ok();
        if !matches!(actual, Some(s) if s == format!("http://{expected}") || s == format!("http://{local_alias}"))
        {
            return simple(StatusCode::FORBIDDEN, "Invalid Origin");
        }
    }
    if request
        .headers()
        .get("MCP-Protocol-Version")
        .is_some_and(|value| value.as_bytes() != MCP_VERSION.as_bytes())
    {
        return simple(StatusCode::BAD_REQUEST, "Unsupported protocol version");
    }

    // Admission precedes reading even one byte of an untrusted request body.
    let now = unix_seconds();
    {
        let locks = state.failures.lock().await;
        if locks
            .get(&peer)
            .is_some_and(|f| f.count >= 5 && Instant::now() < f.until)
        {
            return simple(StatusCode::TOO_MANY_REQUESTS, "Too many requests");
        }
    }
    let client_index = authenticate(
        &state.clients,
        request.headers().get(header::AUTHORIZATION),
        now,
    );
    let Some(client_index) = client_index else {
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
    let client = &state.clients[client_index];
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
    let body = match tokio::time::timeout(HTTP_TIMEOUT, bounded_body(request.into_body())).await {
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
                owner: client_index,
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
    if session.owner != client_index {
        return simple(StatusCode::FORBIDDEN, "Session access denied");
    }
    if session.last_used.elapsed() >= SESSION_IDLE {
        sessions.remove(&session_id);
        return simple(StatusCode::NOT_FOUND, "Expired MCP session");
    }
    session.last_used = Instant::now();

    #[cfg(target_os = "linux")]
    if (state.jobs.is_some() || cfg!(feature = "test-hooks"))
        && matches!(method, Some("tools/list" | "tools/call"))
    {
        // Tool requests leave protocol phase unchanged. Release session state
        // before waiting on storage, a short command, or crash instrumentation.
        let mut protocol = session.protocol.clone();
        drop(sessions);
        return match tokio::task::spawn_blocking(move || {
            dispatch_tools(&mut protocol, payload, &state, &state.clients[client_index])
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
    dispatch_tools(&mut session.protocol, payload, &state, client)
}

fn dispatch_tools(
    protocol: &mut Protocol,
    payload: Value,
    state: &State,
    client: &Client,
) -> Reply {
    let response = protocol.dispatch_with_tools(
        payload,
        || {
            let audited = audit("policy.checked");
            if !authorized(client, Action::ListTools, audited, unix_seconds()) {
                return Vec::new();
            }
            Tool::ALL
                .into_iter()
                .filter(|tool| {
                    authorized(client, tool.action(), audited, unix_seconds())
                        && tool_available(*tool, client, state)
                })
                .map(Tool::schema)
                .collect()
        },
        |files, name, args| {
            let tool = Tool::parse(name)?;
            let now = unix_seconds();
            if !authorized(client, tool.action(), audit("policy.checked"), now) {
                return Some(tool_text(true, "Not authorized"));
            }
            if tool == Tool::ReadFile {
                return Some(read_file(files, args));
            }
            if tool.action().is_job() {
                #[cfg(target_os = "linux")]
                if let (Some(jobs), Some(root)) = (state.jobs.as_ref(), client.job_root.as_ref()) {
                    return Some(jobs.call(tool, args, &client.id, root));
                }
                return Some(tool_text(true, "Jobs unavailable"));
            }
            #[cfg(target_os = "linux")]
            if let Some(root) = client.mutation_root.as_ref() {
                return Some(state.mutations.call(tool, args, root, &client.id, now));
            }
            Some(tool_text(true, "Mutation unavailable"))
        },
    );

    match response {
        None => simple(StatusCode::ACCEPTED, ""),
        Some(response) => json_response(StatusCode::OK, response, None),
    }
}

fn tool_available(tool: Tool, client: &Client, state: &State) -> bool {
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

fn authorized(client: &Client, action: Action, audit_available: bool, now: u64) -> bool {
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
        mode: ExecutionMode::Standard,
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

async fn bounded_body(mut body: Incoming) -> Result<Vec<u8>, StatusCode> {
    let mut data = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Ok(chunk) = frame.into_data() {
            if chunk.len() > MAX_BODY.saturating_sub(data.len()) {
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
