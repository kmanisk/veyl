//! Experimental Android-only, foreground, authenticated loopback read service.
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, header, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use mcp_gateway::core::credential::{
    decode_sha256, select_client, token_shape as hex,
};
use mcp_gateway::core::lifecycle::AuditPhase;
use mcp_gateway::core::{
    protocol::{Session as Protocol, MCP_VERSION},
    session::{OwnedSession, random_id},
    tools::tool_text,
    workspace::{WorkspaceGrants, WorkspaceTool},
};
use mcp_gateway::platform::{self, private_workspace::PrivateWorkspace};
use mcp_gateway::http_common::{one, bearer_text};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    convert::Infallible,
    ffi::OsString,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

const LIMIT: usize = 65_536;
const MAX_CLIENTS: usize = 16;
const MAX_SESSIONS: usize = 32;

fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn state_name(s: &str) -> bool {
    name_ok(s) && s.starts_with("veyl-android-")
}
fn random_hex() -> Result<String, String> {
    random_id::<32>().map_err(|_| "random generation failed".to_string())
}
fn digest(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}
fn state(s: &str) -> Result<PrivateWorkspace, String> {
    if !state_name(s) {
        return Err("Use a state name beginning with veyl-android-".into());
    }
    Ok(PrivateWorkspace::termux_home()?.private_child(Path::new(s))?)
}
struct Client {
    id: String,
    hash: [u8; 32],
    enabled: bool,
    tools: WorkspaceGrants,
    root: PrivateWorkspace,
    audit: Option<PrivateWorkspace>,
}
fn load_clients(state: &PrivateWorkspace) -> Result<Vec<Client>, String> {
    let configs = state.private_child(Path::new("clients"))?;
    let workspaces = state.private_child(Path::new("workspaces"))?;
    let listing = configs.list(".")?;
    if listing["omitted"] != 0 || listing["truncated"] != false {
        return Err("Unsafe or excessive client state".into());
    }
    let entries = listing["entries"]
        .as_array()
        .ok_or("Invalid client directory")?;
    if entries.len() > MAX_CLIENTS {
        return Err("Too many clients".into());
    }
    let mut clients: Vec<Client> = Vec::new();
    for entry in entries {
        let filename = entry["name"].as_str().ok_or("Invalid client filename")?;
        let id = filename
            .strip_suffix(".json")
            .filter(|s| name_ok(s))
            .ok_or("Invalid client filename")?;
        let doc: Value = serde_json::from_str(&configs.read_private(filename)?)
            .map_err(|_| "Invalid client policy")?;
        let fields = doc.as_object().ok_or("Invalid client policy")?;
        if fields.len() != 4 || doc["id"].as_str() != Some(id) {
            return Err("Invalid client policy".into());
        }
        let hash = decode_sha256(
            doc["token_sha256"]
                .as_str()
                .ok_or("Invalid credential hash")?,
        )?;
        if clients.iter().any(|c| c.hash == hash) {
            return Err("Duplicate credential hash".into());
        }
        let enabled = doc["enabled"].as_bool().ok_or("Invalid enabled state")?;
        let tools = WorkspaceGrants::parse(&doc["tools"])?;
        let root = workspaces.private_child(Path::new(id))?;
        let audit = if tools.has_mutation() {
            Some(
                state
                    .private_child(Path::new("audit"))?
                    .private_child(Path::new(id))?,
            )
        } else {
            None
        };
        clients.push(Client {
            id: id.into(),
            hash,
            enabled,
            tools,
            root,
            audit,
        });
    }
    Ok(clients)
}
pub fn run(args: &[OsString]) -> Result<(), String> {
    let args: Vec<&str> = args
        .iter()
        .map(|a| a.to_str().ok_or("Expected UTF-8 arguments"))
        .collect::<Result<_, _>>()?;
    match args.as_slice() {
        ["android-init",s] if state_name(s) => {
            let root=PrivateWorkspace::termux_home()?.create_private_child(s)?;
            root.create_private_child("clients")?;
            root.create_private_child("workspaces")?;
            root.create_private_child("audit")?;
            println!("Created private Android state: {s}");
            Ok(())
        }
        ["android-add-client",s,id,tools] if name_ok(id) => {
            let root=state(s)?;
            root.lock_exclusive()?;
            let existing=load_clients(&root)?;
            if existing.len()>=MAX_CLIENTS || existing.iter().any(|c|c.id==*id) {
                return Err("Client already exists or capacity reached".into());
            }
            let tools=WorkspaceGrants::parse(&json!(tools.split(',').collect::<Vec<_>>()))?;
            let token=random_hex()?;
            if tools.has_mutation() {
                root.private_child(Path::new("audit"))?.create_private_child(id)?;
            }
            root.private_child(Path::new("workspaces"))?.create_private_child(id)?;
            let data=serde_json::to_vec(&json!({"id":id,"token_sha256":digest(&token),"enabled":true,"tools":tools.names()})).map_err(|_|"Encoding failed")?;
            root.private_child(Path::new("clients"))?.create_private_file(&format!("{id}.json"),&data)?;
            // Only the explicit local operator command reveals the newly generated token.
            println!("{}",json!({"client":id,"token":token,"workspace":format!("{s}/workspaces/{id}")}));
            Ok(())
        }
        ["android-serve",s,port] => {
            let port:u16=port.parse().map_err(|_|"Invalid loopback port")?;
            if port==0 { return Err("Explicit nonzero port required".into()); }
            let root=state(s)?;
            root.lock_exclusive()?;
            let clients=load_clients(&root)?;
            if !clients.iter().any(|c|c.enabled) { return Err("No enabled clients".into()); }
            tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|"Runtime unavailable")?
                .block_on(serve(port,clients,root))
        }
        _=>Err("Usage: veyl android-init veyl-android-NAME | android-add-client STATE CLIENT TOOL[,TOOL] | android-serve STATE PORT".into())
    }
}

type Session = OwnedSession<usize, (), Protocol>;
struct State {
    clients: Vec<Client>,
    sessions: Mutex<HashMap<String, Session>>,
    authority: String,
}
type Reply = Response<Full<Bytes>>;
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
    if status == StatusCode::UNAUTHORIZED {
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
    }
    r
}
fn empty(s: StatusCode) -> Reply {
    response(s, None)
}
fn schemas(c: &Client) -> Vec<Value> {
    c.tools.schemas()
}
// Bounded private intent/outcome journal, not a tamper-proof audit chain.
// Unpaired intents or uncertain outcomes require local operator review.
fn mutate(c: &Client, name: &str, args: Option<&Value>) -> Result<Value, String> {
    let m = args
        .and_then(Value::as_object)
        .ok_or("Expected mutation arguments")?;
    let path = m
        .get("path")
        .and_then(Value::as_str)
        .ok_or("Expected path")?;
    let expected = match m.get("expected_sha256") {
        Some(Value::Null) if name == "write_file" => None,
        Some(Value::String(s)) if hex(s) => Some(s.as_str()),
        _ => return Err("Expected explicit SHA-256 or null for exclusive creation".into()),
    };
    let content = if name == "write_file" && m.len() == 3 {
        m.get("content")
            .and_then(Value::as_str)
            .ok_or("Expected content")?
            .to_owned()
    } else if name == "apply_patch" && m.len() == 4 {
        let old = m
            .get("old")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("Expected nonempty old text")?;
        let new = m
            .get("new")
            .and_then(Value::as_str)
            .ok_or("Expected replacement")?;
        let before = c.root.read(path)?;
        if expected != Some(digest(&before).as_str()) || before.match_indices(old).count() != 1 {
            return Err("Patch checksum conflict or nonunique match".into());
        }
        before.replacen(old, new, 1)
    } else {
        return Err("Unexpected mutation arguments".into());
    };
    if content.len() > 65536 {
        return Err("Mutation exceeds size limit".into());
    }
    let audit = c.audit.as_ref().ok_or("Mutation journal unavailable")?;
    let listing = audit.list(".")?;
    let entries = listing["entries"]
        .as_array()
        .ok_or("Invalid audit directory")?;
    if listing["omitted"] != 0 || listing["truncated"] != false || entries.len() >= 256 {
        return Err("Mutation journal unavailable or full".into());
    }
    let mut pending = BTreeSet::new();
    let mut outcomes = BTreeSet::new();
    for item in entries {
        let filename = item["name"].as_str().ok_or("Invalid journal name")?;
        let (id, phase) = filename.split_once('.').ok_or("Invalid journal name")?;
        if !hex(id) {
            return Err("Invalid journal ID".into());
        }
        let record: Value = serde_json::from_str(&audit.read_private(filename)?)
            .map_err(|_| "Invalid journal entry")?;
        if record["id"] != id || record["client"] != c.id || record["phase"] != phase {
            return Err("Invalid journal record".into());
        }
        match phase {
            "intent" => {
                pending.insert(id);
            }
            "outcome" if record["status"].as_str().and_then(AuditPhase::parse_android_outcome).is_some_and(AuditPhase::is_definite) => {
                outcomes.insert(id);
            }
            _ => return Err("Uncertain journal outcome; local review required".into()),
        }
    }
    if pending != outcomes {
        return Err("Unpaired mutation intent; local review required".into());
    }
    let id = random_hex()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "Clock unavailable")?
        .as_secs();
    let intent = json!({"id":id,"client":c.id,"phase":"intent","tool":name,"time":now,"path_sha256":digest(path),"before_sha256":expected,"after_sha256":digest(&content)});
    audit.create_private_file(&format!("{id}.intent"), intent.to_string().as_bytes())?;
    let result = c.root.publish_text(path, &content, expected);
    let phase = match result {
        Ok(()) => AuditPhase::Success,
        Err("Mutation outcome uncertain") => AuditPhase::Uncertain,
        Err(_) => AuditPhase::Failure,
    };
    let status = phase.android_outcome().ok_or("Invalid mutation outcome")?;
    let outcome = json!({"id":id,"client":c.id,"phase":"outcome","status":status});
    audit
        .create_private_file(&format!("{id}.outcome"), outcome.to_string().as_bytes())
        .map_err(|_| "Mutation outcome uncertain; journal unavailable")?;
    result?;
    Ok(json!({"operation_id":id,"sha256":digest(&content),"status":"success"}))
}

fn invoke(c: &Client, name: &str, args: Option<&Value>) -> Option<Value> {
    let tool = WorkspaceTool::parse(name)?;
    if !c.tools.allows(tool) {
        return None;
    }
    if tool.is_mutation() {
        return Some(match mutate(c, name, args) {
            Ok(v) => tool_text(false, &v.to_string()),
            Err(e) => tool_text(true, &e),
        });
    }
    if tool == WorkspaceTool::PlatformInfo {
        if !args.is_none_or(|v| v.as_object().is_some_and(|m| m.is_empty())) {
            return Some(tool_text(true, "Unexpected arguments"));
        }
        let mut report = platform::report();
        report["active_transport"] = json!("authenticated_android_loopback_http");
        report["granted_tools"] = json!(c.tools.names());
        return Some(tool_text(false, &report.to_string()));
    }
    Some(
        match tool.path(args).and_then(|p| match tool {
            WorkspaceTool::ReadFile => c.root.read(p),
            WorkspaceTool::FileInfo => c.root.info(p).map(|v| v.to_string()),
            WorkspaceTool::ListDirectory => c.root.list(p).map(|v| v.to_string()),
            _ => Err("Unknown tool"),
        }) {
            Ok(s) => tool_text(false, &s),
            Err(e) => tool_text(true, e),
        },
    )
}
async fn handle(req: Request<Incoming>, state: Arc<State>) -> Reply {
    let h = req.headers();
    if req.uri().path_and_query().map(|p| p.as_str()) != Some("/mcp") {
        return empty(StatusCode::NOT_FOUND);
    }
    if one(h, "host") != Some(state.authority.as_str())
        || h.contains_key(header::ORIGIN)
        || req.uri().authority().is_some()
    {
        return empty(StatusCode::FORBIDDEN);
    }
    let Some(hash) = one(h, "authorization").and_then(bearer_text) else {
        return empty(StatusCode::UNAUTHORIZED);
    };
    let Some(owner) = select_client(&hash, state.clients.iter().map(|c| (c.hash, c.enabled)))
    else {
        return empty(StatusCode::UNAUTHORIZED);
    };
    let session = one(h, "mcp-session-id").map(str::to_owned);
    if h.contains_key("mcp-session-id") && session.as_deref().is_none_or(|s| !hex(s)) {
        return empty(StatusCode::BAD_REQUEST);
    }
    if h.contains_key("mcp-protocol-version")
        && one(h, "mcp-protocol-version") != Some(MCP_VERSION)
    {
        return empty(StatusCode::BAD_REQUEST);
    }
    if req.method() == Method::DELETE {
        let Ok(mut sessions) = state.sessions.lock() else {
            return empty(StatusCode::SERVICE_UNAVAILABLE);
        };
        if let Some(id) = session
            && sessions.get(&id).is_some_and(|s| s.belongs_to(&owner, &()))
        {
            sessions.remove(&id);
            return empty(StatusCode::NO_CONTENT);
        }
        return empty(StatusCode::NOT_FOUND);
    }
    if req.method() != Method::POST {
        return empty(StatusCode::METHOD_NOT_ALLOWED);
    }
    if one(h, "content-type")
        .and_then(|v| v.split(';').next())
        .map(str::trim)
        != Some("application/json")
    {
        return empty(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let Ok(body) = Limited::new(req.into_body(), LIMIT).collect().await else {
        return empty(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(msg) = serde_json::from_slice::<Value>(&body.to_bytes()) else {
        return response(StatusCode::OK, Some(Protocol::parse_error()));
    };
    if !msg.is_object() {
        return empty(StatusCode::BAD_REQUEST);
    }
    let c = &state.clients[owner];
    let Ok(mut sessions) = state.sessions.lock() else {
        return empty(StatusCode::SERVICE_UNAVAILABLE);
    };
    sessions.retain(|_, s| s.is_live());
    if let Some(id) = session {
        let Some(s) = sessions.get_mut(&id).filter(|s| s.belongs_to(&owner, &())) else {
            return empty(StatusCode::NOT_FOUND);
        };
        s.touch();
        return match s
            .protocol
            .dispatch(msg, || schemas(c), |name, args| invoke(c, name, args))
        {
            Some(v) => response(StatusCode::OK, Some(v)),
            None => empty(StatusCode::ACCEPTED),
        };
    }
    if msg["method"] != "initialize"
        || !msg
            .get("id")
            .is_some_and(|id| id.is_string() || id.is_i64() || id.is_u64())
    {
        return empty(StatusCode::BAD_REQUEST);
    }
    if sessions.len() >= MAX_SESSIONS {
        return empty(StatusCode::SERVICE_UNAVAILABLE);
    }
    let mut protocol = Protocol::new("mcp-gateway", env!("CARGO_PKG_VERSION"));
    let Some(reply) = protocol.dispatch(msg, || schemas(c), |name, args| invoke(c, name, args))
    else {
        return empty(StatusCode::BAD_REQUEST);
    };
    let mut result = response(StatusCode::OK, Some(reply.clone()));
    if reply.get("result").is_some() {
        let Ok(id) = random_hex() else {
            return empty(StatusCode::SERVICE_UNAVAILABLE);
        };
        if sessions.contains_key(&id) {
            return empty(StatusCode::SERVICE_UNAVAILABLE);
        }
        let Ok(header) = header::HeaderValue::from_str(&id) else {
            return empty(StatusCode::SERVICE_UNAVAILABLE);
        };
        sessions.insert(id, Session::new(owner, (), protocol));
        result.headers_mut().insert("mcp-session-id", header);
    }
    result
}
async fn serve(
    port: u16,
    clients: Vec<Client>,
    _state_lock: PrivateWorkspace,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|_| "Loopback bind failed")?;
    let state = Arc::new(State {
        clients,
        sessions: Mutex::new(HashMap::new()),
        authority: format!("127.0.0.1:{port}"),
    });
    let permits = Arc::new(tokio::sync::Semaphore::new(16));
    eprintln!("Android MCP preview listening on http://127.0.0.1:{port}/mcp");
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|_| "Loopback accept failed")?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(req, state).await) }
            });
            let mut builder = http1::Builder::new();
            builder.keep_alive(false).max_buf_size(32 * 1024);
            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                builder.serve_connection(TokioIo::new(stream), service),
            )
            .await;
            drop(permit);
        });
    }
}
