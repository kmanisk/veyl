//! Independent, loopback-only connector preview. No device control or public routes.
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, header, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use mcp_gateway::core::credential::{decode_sha256, select_client};
use mcp_gateway::core::session::{OwnedSession, random_id};
use mcp_gateway::http_common::{bearer_text, one};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

mod agent;
#[cfg(target_os = "linux")]
use mcp_gateway::http_common::oauth_http as oauth_preview;
#[cfg(target_os = "linux")]
use mcp_gateway::platform::private_store as store;

const API: u64 = 1;
use mcp_gateway::core::protocol::{MCP_VERSION as MCP, Session};
const MAX: usize = 16_384;
type Reply = Response<Full<Bytes>>;
struct User {
    id: String,
    hash: [u8; 32],
}
struct Device {
    owner: String,
    hash: [u8; 32],
    last: Option<Heartbeat>,
    last_sequence: u64,
}
struct Heartbeat {
    os: String,
    version: String,
    at: Instant,
}
struct State {
    users: Vec<User>,
    devices: BTreeMap<String, Device>,
    sessions: BTreeMap<String, OwnedSession<String, (), Session>>,
    #[cfg(target_os = "linux")]
    store: Option<store::Store>,
    failed: bool,
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str()
        .filter(|s| identifier(s))
        .ok_or_else(|| format!("Invalid {k}"))
}
fn config(v: Value) -> Result<State, String> {
    if v.as_object().is_none_or(|m| m.len() != 2) {
        return Err("Invalid registry fields".into());
    }
    let users = v["users"].as_array().ok_or("Expected users")?;
    let devices = v["devices"].as_array().ok_or("Expected devices")?;
    if users.is_empty() || users.len() > 16 || devices.len() > 64 {
        return Err("Registry capacity exceeded".into());
    }
    let mut s = State {
        users: vec![],
        devices: BTreeMap::new(),
        sessions: BTreeMap::new(),
        #[cfg(target_os = "linux")]
        store: None,
        failed: false,
    };
    let mut hashes = BTreeSet::new();
    for u in users {
        if u.as_object().is_none_or(|m| m.len() != 2) {
            return Err("Invalid user fields".into());
        }
        let id = field(u, "id")?.to_owned();
        let hash = decode_sha256(u["token_sha256"].as_str().ok_or("Missing verifier")?)?;
        if s.users.iter().any(|x| x.id == id) || !hashes.insert(hash) {
            return Err("Duplicate identity or credential".into());
        }
        s.users.push(User { id, hash });
    }
    for d in devices {
        if d.as_object().is_none_or(|m| m.len() != 3 && m.len() != 4) {
            return Err("Invalid device fields".into());
        }
        let seq = match d.get("last_sequence") {
            None if d.as_object().is_some_and(|m| m.len() == 3) => 0,
            Some(v) if d.as_object().is_some_and(|m| m.len() == 4) => {
                v.as_u64().ok_or("Invalid sequence")?
            }
            _ => return Err("Invalid device fields".into()),
        };
        let id = field(d, "id")?.to_owned();
        let owner = field(d, "owner")?.to_owned();
        let hash = decode_sha256(d["token_sha256"].as_str().ok_or("Missing verifier")?)?;
        if !s.users.iter().any(|x| x.id == owner)
            || s.devices.contains_key(&id)
            || !hashes.insert(hash)
        {
            return Err("Invalid owner or duplicate identity/credential".into());
        }
        s.devices.insert(
            id,
            Device {
                owner,
                hash,
                last: None,
                last_sequence: seq,
            },
        );
    }
    Ok(s)
}
fn response(status: StatusCode, value: Option<Value>) -> Reply {
    let mut r = Response::new(Full::new(
        value
            .map(|v| Bytes::from(v.to_string()))
            .unwrap_or_default(),
    ));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    if status == StatusCode::OK {
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
    }
    r
}
fn reject(status: StatusCode) -> Reply {
    response(status, None)
}
fn tool_result(value: Value) -> Value {
    json!({"content":[{"type":"text","text":value.to_string()}],"isError":false})
}
fn schemas() -> Value {
    json!([
        {"name":"list_devices","description":"List only devices paired to the authenticated account, with live heartbeat status.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false}},
        {"name":"device_health","description":"Get heartbeat status and runtime version of one paired device.","inputSchema":{"type":"object","properties":{"device_id":{"type":"string"}},"required":["device_id"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false}}
    ])
}
fn device_view(id: &str, d: &Device) -> Value {
    let online = d
        .last
        .as_ref()
        .is_some_and(|h| h.at.elapsed() < Duration::from_secs(30));
    json!({"device_id":id,"online":online,"api_version":API,"os":d.last.as_ref().map(|h|&h.os),"runtime_version":d.last.as_ref().map(|h|&h.version)})
}
#[cfg(target_os = "linux")]
fn snapshot(s: &State) -> Value {
    fn encode(d: &[u8; 32]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }
    json!({"users":s.users.iter().map(|u|json!({"id":u.id,"token_sha256":encode(&u.hash)})).collect::<Vec<_>>(),
        "devices":s.devices.iter().map(|(id,d)|json!({"id":id,"owner":d.owner,"token_sha256":encode(&d.hash),"last_sequence":d.last_sequence})).collect::<Vec<_>>()})
}
fn device_index(s: &State, hash: &[u8; 32]) -> Option<String> {
    let index = select_client(hash, s.devices.values().map(|d| (d.hash, true)))?;
    s.devices.keys().nth(index).cloned()
}
fn sequence(s: &State, hash: &[u8; 32], msg: &Value) -> Reply {
    if msg.as_object().is_none_or(|m| m.len() != 1) || msg["api_version"].as_u64() != Some(API) {
        return reject(StatusCode::BAD_REQUEST);
    }
    let Some(id) = device_index(s, hash) else {
        return reject(StatusCode::UNAUTHORIZED);
    };
    response(
        StatusCode::OK,
        Some(json!({"api_version":API,"last_sequence":s.devices[&id].last_sequence})),
    )
}
fn heartbeat(s: &mut State, hash: &[u8; 32], msg: &Value) -> Reply {
    let Some(id) = device_index(s, hash) else {
        return reject(StatusCode::UNAUTHORIZED);
    };
    if msg.as_object().is_none_or(|m| m.len() != 4) || msg["api_version"].as_u64() != Some(API) {
        return reject(StatusCode::BAD_REQUEST);
    }
    let (Some(seq), Some(os), Some(version)) = (
        msg["sequence"].as_u64(),
        msg["os"].as_str(),
        msg["runtime_version"].as_str(),
    ) else {
        return reject(StatusCode::BAD_REQUEST);
    };
    if seq == 0
        || !matches!(os, "linux" | "android" | "windows")
        || version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
    {
        return reject(StatusCode::BAD_REQUEST);
    }
    let d = s.devices.get_mut(&id).expect("existing device");
    if seq <= d.last_sequence {
        return reject(StatusCode::CONFLICT);
    }
    d.last_sequence = seq;
    #[cfg(target_os = "linux")]
    if let Some(store) = &s.store
        && store.write(&snapshot(s), false).is_err()
    {
        s.failed = true;
        return reject(StatusCode::SERVICE_UNAVAILABLE);
    }
    s.devices.get_mut(&id).expect("existing device").last = Some(Heartbeat {
        os: os.into(),
        version: version.into(),
        at: Instant::now(),
    });
    response(
        StatusCode::OK,
        Some(json!({"accepted":true,"api_version":API})),
    )
}
fn mcp(s: &mut State, owner: String, session: Option<&str>, msg: Value) -> Reply {
    s.sessions.retain(|_, session| session.is_live());
    let id = msg.get("id");
    if msg["jsonrpc"] != "2.0"
        || id.is_some_and(|v| !v.is_string() && !v.is_i64() && !v.is_u64())
        || msg.get("params").is_some_and(|v| !v.is_object())
    {
        return reject(StatusCode::BAD_REQUEST);
    }
    if session.is_none() {
        if msg["method"] != "initialize" || id.is_none() || msg["params"]["protocolVersion"] != MCP
        {
            return reject(StatusCode::BAD_REQUEST);
        }
        if s.sessions.len() >= 64 {
            return reject(StatusCode::SERVICE_UNAVAILABLE);
        }
        let mut protocol = Session::new("veyl-connector", "1");
        let Some(reply) = protocol.dispatch(msg, Vec::new, |_, _| None) else {
            return reject(StatusCode::BAD_REQUEST);
        };
        if reply.get("result").is_none() {
            return response(StatusCode::OK, Some(reply));
        }
        let Ok(key) = random_id::<32>() else {
            return reject(StatusCode::SERVICE_UNAVAILABLE);
        };
        if s.sessions.contains_key(&key) {
            return reject(StatusCode::SERVICE_UNAVAILABLE);
        }
        s.sessions
            .insert(key.clone(), OwnedSession::new(owner, (), protocol));
        let mut r = response(StatusCode::OK, Some(reply));
        r.headers_mut().insert(
            "mcp-session-id",
            header::HeaderValue::from_str(&key).expect("hex"),
        );
        return r;
    }
    let Some(session) = session
        .and_then(|key| s.sessions.get_mut(key))
        .filter(|s| s.belongs_to(&owner, &()))
    else {
        return reject(StatusCode::NOT_FOUND);
    };
    session.touch();
    let devices = &s.devices;
    let reply=session.protocol.dispatch(msg,||schemas().as_array().expect("catalog").clone(),|name,args|{
        match name {
            "list_devices" if args.is_none_or(|a|a.as_object().is_some_and(|m|m.is_empty()))=>
                Some(tool_result(json!({"devices":devices.iter().filter(|(_,d)|d.owner==owner).map(|(k,d)|device_view(k,d)).collect::<Vec<_>>()}))),
            "device_health" if args.and_then(Value::as_object).is_some_and(|a|a.len()==1)=>
                args.and_then(|a|a["device_id"].as_str()).and_then(|key|devices.get(key).filter(|d|d.owner==owner).map(|d|tool_result(device_view(key,d)))),
            _=>None
        }
    });
    match reply {
        Some(v) => response(StatusCode::OK, Some(v)),
        None => reject(StatusCode::ACCEPTED),
    }
}
async fn handle(req: Request<Incoming>, state: Arc<Mutex<State>>, authority: String) -> Reply {
    let h = req.headers();
    if one(h, "host") != Some(authority.as_str())
        || h.contains_key(header::ORIGIN)
        || req.uri().authority().is_some()
    {
        return reject(StatusCode::FORBIDDEN);
    }
    let Some(hash) = one(h, "authorization").and_then(bearer_text) else {
        return reject(StatusCode::UNAUTHORIZED);
    };
    let route = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if !matches!(
        route.as_str(),
        "/mcp" | "/device/heartbeat" | "/device/sequence"
    ) {
        return reject(StatusCode::NOT_FOUND);
    }
    let session = one(h, "mcp-session-id").map(str::to_owned);
    if h.contains_key("mcp-session-id")
        && session
            .as_ref()
            .is_none_or(|s| !mcp_gateway::core::credential::token_shape(s))
    {
        return reject(StatusCode::BAD_REQUEST);
    }
    if req.method() == Method::DELETE && route == "/mcp" {
        let Ok(mut s) = state.lock() else {
            return reject(StatusCode::SERVICE_UNAVAILABLE);
        };
        if s.failed {
            return reject(StatusCode::SERVICE_UNAVAILABLE);
        }
        let Some(i) = select_client(&hash, s.users.iter().map(|u| (u.hash, true))) else {
            return reject(StatusCode::UNAUTHORIZED);
        };
        if let Some(key) = session
            && s.sessions
                .get(&key)
                .is_some_and(|session| session.belongs_to(&s.users[i].id, &()))
        {
            s.sessions.remove(&key);
            return reject(StatusCode::NO_CONTENT);
        }
        return reject(StatusCode::NOT_FOUND);
    }
    if req.method() != Method::POST {
        return reject(StatusCode::METHOD_NOT_ALLOWED);
    }
    if one(h, "content-type")
        .and_then(|s| s.split(';').next())
        .map(str::trim)
        != Some("application/json")
    {
        return reject(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let Ok(body) = Limited::new(req.into_body(), MAX).collect().await else {
        return reject(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(msg) = serde_json::from_slice::<Value>(&body.to_bytes()) else {
        return reject(StatusCode::BAD_REQUEST);
    };
    let Ok(mut s) = state.lock() else {
        return reject(StatusCode::SERVICE_UNAVAILABLE);
    };
    if s.failed {
        return reject(StatusCode::SERVICE_UNAVAILABLE);
    }
    if route == "/device/sequence" {
        return sequence(&s, &hash, &msg);
    }
    if route == "/device/heartbeat" {
        return heartbeat(&mut s, &hash, &msg);
    }
    let Some(i) = select_client(&hash, s.users.iter().map(|u| (u.hash, true))) else {
        return reject(StatusCode::UNAUTHORIZED);
    };
    let owner = s.users[i].id.clone();
    mcp(&mut s, owner, session.as_deref(), msg)
}
async fn serve(port: u16, s: State) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|_| "Cannot bind loopback")?;
    let addr = listener
        .local_addr()
        .map_err(|_| "Cannot inspect listener")?;
    println!("CONNECTOR_PREVIEW {addr}");
    let s = Arc::new(Mutex::new(s));
    let permits = Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let (stream, _) = listener.accept().await.map_err(|_| "Accept failed")?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let state = s.clone();
        let authority = addr.to_string();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                let authority = authority.clone();
                async move { Ok::<_, std::convert::Infallible>(handle(req, state, authority).await) }
            });
            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(stream), service),
            )
            .await;
            drop(permit);
        });
    }
}
fn input() -> Result<Value, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Input failed")?;
    if bytes.len() > MAX {
        return Err("Input exceeds limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Malformed JSON input".into())
}
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Runtime failed".into())
}
fn parse_port(p: &str) -> Result<u16, String> {
    p.parse().map_err(|_| "Invalid port".into())
}
#[cfg(target_os = "linux")]
fn local_state(args: &[String]) -> Result<(), String> {
    use std::path::Path;
    match args {
        [mode, dir] if mode == "state-init" => {
            let store = store::Store::open(Path::new(dir))?;
            let s = config(input()?)?;
            store.write(&snapshot(&s), true)?;
            println!("REGISTRY_INITIALIZED");
            Ok(())
        }
        [mode, dir] if mode == "state-pair" => {
            let store = store::Store::open(Path::new(dir))?;
            let s = config(store.read()?)?;
            let device = input()?;
            if device.as_object().is_none_or(|m| m.len() != 3)
                || device.get("last_sequence").is_some()
            {
                return Err("Expected id, owner and token_sha256".into());
            }
            let mut v = snapshot(&s);
            v["devices"].as_array_mut().expect("registry").push(device);
            let updated = config(v)?;
            store.write(&snapshot(&updated), false)?;
            println!("DEVICE_PAIRED");
            Ok(())
        }
        [mode, dir, id] if mode == "state-revoke" => {
            let store = store::Store::open(Path::new(dir))?;
            let mut s = config(store.read()?)?;
            if s.devices.remove(id).is_none() {
                return Err("Unknown device".into());
            }
            store.write(&snapshot(&s), false)?;
            println!("DEVICE_REVOKED");
            Ok(())
        }
        [mode, port, dir] if mode == "serve" => {
            let store = store::Store::open(Path::new(dir))?;
            let mut s = config(store.read()?)?;
            s.store = Some(store);
            runtime()?.block_on(serve(parse_port(port)?, s))
        }
        _ => {
            Err("Use state-init DIR, state-pair DIR, state-revoke DIR ID, or serve PORT DIR".into())
        }
    }
}
pub fn run(args: Vec<String>) -> Result<(), String> {
    if args == ["--version"] {
        println!("veyl-connector {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args == ["--help"] || args == ["-h"] {
        println!(
            "Usage: veyl connector preview PORT | heartbeat PORT | state-init DIR | state-pair DIR | state-revoke DIR ID | serve PORT DIR | oauth-preview PORT ADMIN_PORT ORIGIN [DIR] | oauth-state-init DIR ORIGIN"
        );
        return Ok(());
    }
    match args.as_slice() {
        #[cfg(target_os = "linux")]
        [mode, port, admin_port, origin] if mode == "oauth-preview" => {
            runtime()?.block_on(oauth_preview::serve(
                parse_port(port)?,
                parse_port(admin_port)?,
                origin,
                input()?,
                None,
            ))
        }
        #[cfg(target_os = "linux")]
        [mode, dir, origin] if mode == "oauth-state-init" => {
            oauth_preview::init_state(std::path::Path::new(dir), origin)
        }
        #[cfg(target_os = "linux")]
        [mode, port, admin_port, origin, dir] if mode == "oauth-preview" => {
            runtime()?.block_on(oauth_preview::serve(
                parse_port(port)?,
                parse_port(admin_port)?,
                origin,
                input()?,
                Some(std::path::Path::new(dir)),
            ))
        }
        [mode, port] if mode == "preview" => {
            runtime()?.block_on(serve(parse_port(port)?, config(input()?)?))
        }
        [mode, port] if mode == "heartbeat" => {
            runtime()?.block_on(agent::heartbeat(parse_port(port)?))
        }
        #[cfg(target_os = "linux")]
        _ => local_state(&args),
        #[cfg(not(target_os = "linux"))]
        _ => Err("Use preview PORT or heartbeat PORT; durable registry requires Linux".into()),
    }
}
