//! Compare-and-swap updates to the local Tailscale Serve configuration.

use std::{
    ffi::OsString,
    net::SocketAddrV4,
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, StatusCode, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use mcp_gateway::security::audit::{AuditPhase, AuditSink};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::UnixStream;

use crate::http::operator::{PolicyFile, revision, verify_approvals};

const SOCKET: &str = "/run/tailscale/tailscaled.sock";
const API: &str = "/localapi/v0/serve-config";
const MARKER: &str = "/.well-known/veyl-serve";
const SHARED_MOUNT: &str = "/veyl/";
const SHARED_MARKER: &str = "/veyl/.well-known/veyl-serve";
const ADAPTER_BACKEND: &str = "http://127.0.0.1:7330";
const SHARED_DISABLED: &str = "Veyl public MCP disabled";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub hostname: String,
    pub mcp_https_port: u16,
    pub admin_https_port: u16,
    pub funnel: Option<crate::http::funnel::Settings>,
    #[serde(default)]
    pub shared_funnel: bool,
}

impl Settings {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let parsed: Self = serde_json::from_value(value.clone())
            .map_err(|_| "Invalid tailscale_serve configuration")?;
        let name = &parsed.hostname;
        if !name.ends_with(".ts.net")
            || name.len() > 253
            || name.split('.').count() < 4
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            || parsed.mcp_https_port < 1024
            || parsed.admin_https_port < 1024
            || parsed.mcp_https_port == parsed.admin_https_port
        {
            return Err(
                "Use a MagicDNS .ts.net hostname and two distinct unprivileged HTTPS ports".into(),
            );
        }
        if parsed.funnel.is_some() && !matches!(parsed.mcp_https_port, 8443 | 10000) {
            return Err("Veyl Funnel requires a dedicated MCP port of 8443 or 10000".into());
        }
        if parsed.shared_funnel && parsed.funnel.is_none() {
            return Err("Shared Funnel requires a configured public MCP credential".into());
        }
        Ok(parsed)
    }

    pub fn authority(&self, admin: bool) -> String {
        format!(
            "{}:{}",
            self.hostname,
            if admin {
                self.admin_https_port
            } else {
                self.mcp_https_port
            }
        )
    }

    pub fn shared_authority(&self, host: &str) -> bool {
        self.shared_funnel && (host == self.hostname || host == format!("{}:443", self.hostname))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Routes {
    id: String,
    host: String,
    ports: [u16; 2],
    targets: [SocketAddrV4; 2],
}

impl Routes {
    fn of(settings: &Settings, mcp: SocketAddrV4, admin: SocketAddrV4, id: String) -> Self {
        Self {
            id,
            host: settings.hostname.clone(),
            ports: [settings.mcp_https_port, settings.admin_https_port],
            targets: [mcp, admin],
        }
    }

    fn handler(&self, index: usize) -> Value {
        json!({"Handlers": {
            "/": {"Proxy": format!("http://{}", self.targets[index])},
            MARKER: {"Text": format!("Veyl route {}", self.id)}
        }})
    }

    fn authority(&self, index: usize) -> String {
        format!("{}:{}", self.host, self.ports[index])
    }
}

#[derive(Clone, Copy, PartialEq)]
enum RouteState {
    Absent,
    Owned,
}

fn entries<'a>(
    state: &'a Value,
    field: &str,
) -> Result<impl Iterator<Item = (&'a String, &'a Value)>, String> {
    match state.get(field) {
        Some(v) if !v.is_null() && !v.is_object() => Err(format!("Invalid Serve {field} map")),
        _ => Ok(state
            .get(field)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()),
    }
}

fn route_state(
    state: &Value,
    routes: &Routes,
    index: usize,
    allow_public_mcp: bool,
) -> Result<RouteState, String> {
    let key = routes.authority(index);
    let port = routes.ports[index];
    let same_port = |host: &str| {
        host.rsplit_once(':')
            .and_then(|(_, tail)| tail.parse::<u16>().ok())
            == Some(port)
    };
    if entries(state, "AllowFunnel")?.any(|(host, enabled)| {
        same_port(host)
            && *enabled != false
            && !(allow_public_mcp && index == 0 && *host == key && *enabled == true)
    }) {
        return Err(format!(
            "Public Funnel policy collides with HTTPS port {port}"
        ));
    }
    for (_, foreground) in entries(state, "Foreground")? {
        if entries(foreground, "TCP")?.any(|(key, _)| key.parse() == Ok(port))
            || entries(foreground, "Web")?.any(|(key, _)| same_port(key))
            || entries(foreground, "AllowFunnel")?.any(|(key, _)| same_port(key))
        {
            return Err(format!(
                "Foreground Serve session occupies HTTPS port {port}"
            ));
        }
    }
    let expected = routes.handler(index);
    let mut seen = false;
    for (host, web) in entries(state, "Web")?.filter(|(host, _)| same_port(host)) {
        if seen || *host != key || *web != expected {
            return Err(format!("Another web route occupies HTTPS port {port}"));
        }
        seen = true;
    }
    let tcp =
        entries(state, "TCP")?.find_map(|(key, tcp)| (key.parse() == Ok(port)).then_some(tcp));
    match (seen, tcp) {
        (true, Some(tcp)) if *tcp == json!({"HTTPS":true}) => Ok(RouteState::Owned),
        (false, None) if state["AllowFunnel"][&key] != true => Ok(RouteState::Absent),
        _ => Err(format!("Another TCP listener occupies HTTPS port {port}")),
    }
}

fn transition(state: &Value, routes: &Routes, add: bool) -> Result<Value, String> {
    let statuses = [
        route_state(state, routes, 0, add)?,
        route_state(state, routes, 1, false)?,
    ];
    let mut new = state.clone();
    for (i, status) in statuses.into_iter().enumerate() {
        let key = routes.authority(i);
        let port = routes.ports[i].to_string();
        match (add, status) {
            (true, RouteState::Absent) => {
                new["TCP"][port] = json!({"HTTPS":true});
                new["Web"][key] = routes.handler(i);
            }
            (false, RouteState::Owned) => {
                new["TCP"].as_object_mut().unwrap().remove(&port);
                new["Web"].as_object_mut().unwrap().remove(&key);
            }
            _ => {}
        }
    }
    for field in ["TCP", "Web"] {
        if new
            .get(field)
            .is_some_and(|v| v.as_object().is_some_and(|m| m.is_empty()))
        {
            new.as_object_mut().unwrap().remove(field);
        }
    }
    Ok(new)
}

fn funnel_transition(state: &Value, routes: &Routes, enable: bool) -> Result<Value, String> {
    if route_state(state, routes, 0, true)? != RouteState::Owned
        || (enable && route_state(state, routes, 1, false)? != RouteState::Owned)
    {
        return Err("Funnel requires an owned Veyl MCP route with a private dashboard".into());
    }
    if !matches!(routes.ports[0], 8443 | 10000) {
        return Err("Funnel requires a dedicated MCP port of 8443 or 10000".into());
    }
    let mut next = state.clone();
    let authority = routes.authority(0);
    if enable {
        next["AllowFunnel"][authority] = json!(true);
    } else if let Some(entries) = next.get_mut("AllowFunnel").and_then(Value::as_object_mut) {
        entries.remove(&authority);
    }
    Ok(next)
}

#[derive(PartialEq, Eq)]
enum SharedState {
    Absent,
    Adapter,
    Enabled,
    Disabled,
}

fn under_shared_mount(path: &str) -> bool {
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }
    components.first() == Some(&"veyl")
}

fn shared_authority(routes: &Routes) -> String {
    format!("{}:443", routes.host)
}

fn shared_backend(routes: &Routes) -> Value {
    json!({"Proxy":format!("http://{}", routes.targets[0])})
}

fn shared_marker(routes: &Routes) -> Value {
    json!({"Text":format!("Veyl route {}", routes.id)})
}

fn shared_state(state: &Value, routes: &Routes) -> Result<SharedState, String> {
    let authority = shared_authority(routes);
    let handlers = state["Web"][&authority]["Handlers"]
        .as_object()
        .ok_or("Shared Funnel requires an existing HTTPS handler map on 443")?;
    if state["TCP"]["443"] != json!({"HTTPS":true})
        || state["AllowFunnel"][&authority] != true
        || !handlers
            .get("/")
            .is_some_and(|root| root["Proxy"].is_string())
    {
        return Err("Shared Funnel requires an existing public HTTPS root proxy on 443".into());
    }
    for (_, foreground) in entries(state, "Foreground")? {
        if entries(foreground, "TCP")?.any(|(key, _)| key == "443")
            || entries(foreground, "Web")?.any(|(key, _)| key == &authority)
            || entries(foreground, "AllowFunnel")?.any(|(key, _)| key == &authority)
        {
            return Err("Foreground Serve session occupies the shared Funnel authority".into());
        }
    }
    if handlers.keys().any(|path| {
        under_shared_mount(path) && !matches!(path.as_str(), SHARED_MOUNT | SHARED_MARKER)
    }) {
        return Err("Another handler occupies the Veyl path namespace on 443".into());
    }
    match (handlers.get(SHARED_MOUNT), handlers.get(SHARED_MARKER)) {
        (None, None) => Ok(SharedState::Absent),
        (Some(handler), None) if *handler == json!({"Proxy":ADAPTER_BACKEND}) => {
            Ok(SharedState::Adapter)
        }
        (Some(handler), Some(marker)) if *marker == shared_marker(routes) => {
            if *handler == shared_backend(routes) {
                Ok(SharedState::Enabled)
            } else if *handler == json!({"Text":SHARED_DISABLED}) {
                Ok(SharedState::Disabled)
            } else {
                Err("The owned Veyl path has a conflicting handler".into())
            }
        }
        _ => Err("Another handler owns the Veyl mount on 443".into()),
    }
}

fn shared_transition(
    state: &Value,
    routes: &Routes,
    enable: bool,
    adapter: bool,
) -> Result<Value, String> {
    let current = shared_state(state, routes)?;
    let mut next = state.clone();
    let handlers = next["Web"][shared_authority(routes)]["Handlers"]
        .as_object_mut()
        .expect("validated shared handler map");
    if enable {
        if current == SharedState::Adapter && !adapter {
            return Err(
                "Existing adapter owns the route. Use --adapter to adopt it explicitly".into(),
            );
        }
        if current == SharedState::Absent && adapter {
            return Err("The expected adapter route is absent".into());
        }
        handlers.insert(SHARED_MOUNT.into(), shared_backend(routes));
        handlers.insert(SHARED_MARKER.into(), shared_marker(routes));
    } else if matches!(current, SharedState::Enabled | SharedState::Disabled) {
        if adapter {
            handlers.insert(SHARED_MOUNT.into(), json!({"Proxy":ADAPTER_BACKEND}));
            handlers.remove(SHARED_MARKER);
        } else {
            // Keep a non-proxy handler so retired connector URLs cannot fall
            // through to the unrelated root proxy with their credentials.
            handlers.insert(SHARED_MOUNT.into(), json!({"Text":SHARED_DISABLED}));
        }
    } else if !(current == SharedState::Adapter && adapter) && current != SharedState::Absent {
        return Err("The adapter route is not owned by Veyl".into());
    }
    Ok(next)
}

fn node_allows_funnel(status: &Value, port: u16) -> bool {
    let Some(caps) = status["Self"]["CapMap"].as_object() else {
        return false;
    };
    caps.contains_key("funnel")
        && caps
            .keys()
            .filter_map(|cap| cap.strip_prefix("https://tailscale.com/cap/funnel-ports?ports="))
            .flat_map(|ports| ports.split(','))
            .any(|entry| match entry.split_once('-') {
                Some((first, last)) => first
                    .parse::<u16>()
                    .ok()
                    .zip(last.parse::<u16>().ok())
                    .is_some_and(|(first, last)| (first..=last).contains(&port)),
                None => entry.parse::<u16>() == Ok(port),
            })
}

async fn local_request(
    socket: &Path,
    method: Method,
    path: &str,
    etag: Option<&str>,
    body: Vec<u8>,
) -> Result<(Value, String), String> {
    tokio::time::timeout(Duration::from_secs(4), async {
        let socket = UnixStream::connect(socket).await.map_err(|_| "Cannot reach local tailscaled socket")?;
        let (mut sender, connection) = http1::Builder::new().max_buf_size(32_768).handshake(TokioIo::new(socket))
            .await.map_err(|_| "Tailscale LocalAPI handshake failed")?;
        let task = tokio::spawn(connection);
        let result = async {
            let mut builder = Request::builder().method(method).uri(path)
                .header(header::HOST, "local-tailscaled.sock").header(header::CONNECTION, "close");
            if let Some(etag) = etag {
                builder = builder.header(header::IF_MATCH, etag).header(header::CONTENT_TYPE, "application/json");
            }
            let request = builder.body(Full::new(Bytes::from(body))).map_err(|_| "Invalid LocalAPI request")?;
            let reply = sender.send_request(request).await.map_err(|_| "Tailscale LocalAPI request failed")?;
            match reply.status() {
                StatusCode::OK => (),
                StatusCode::PRECONDITION_FAILED => return Err("Serve changed concurrently. Review the new state before retrying."),
                StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => return Err("Tailscale denied this operation. Use the existing authorized local operator."),
                _ => return Err("Tailscale rejected the request"),
            }
            let etag = reply.headers().get(header::ETAG).and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned();
            let bytes = Limited::new(reply.into_body(), 1_048_576).collect().await.map_err(|_| "Invalid or oversized Tailscale reply")?.to_bytes();
            let value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).map_err(|_| "Invalid Tailscale JSON")? };
            Ok((value, etag))
        }.await;
        task.abort();
        result
    }).await.map_err(|_| "Tailscale LocalAPI timed out")?.map_err(str::to_owned)
}

fn state_object(value: Value) -> Result<Value, String> {
    if value.is_null() {
        return Ok(json!({}));
    }
    if !value.is_object() {
        return Err("Invalid Serve configuration object".into());
    }
    Ok(value)
}

const HELP: &str = "usage: veyl serve <plan|validate|inspect|apply|remove|rollback|funnel-plan|funnel-apply|funnel-rollback|funnel-retire-dedicated> --config PATH [--listen 127.0.0.1:PORT] [--state-file PATH | --live] [--socket PATH] [--adapter] [--confirm]";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args.iter().any(|a| a == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let action = args.first().and_then(|s| s.to_str()).ok_or(HELP)?;
    if !matches!(
        action,
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
    ) {
        return Err(HELP.into());
    }
    let change = matches!(
        action,
        "apply"
            | "remove"
            | "rollback"
            | "funnel-apply"
            | "funnel-rollback"
            | "funnel-retire-dedicated"
    );
    let funnel_only = action.starts_with("funnel-");
    let disable_funnel = action == "funnel-rollback";
    let retire_dedicated = action == "funnel-retire-dedicated";
    let mut config = None;
    let mut fixture = None;
    let mut address = None;
    let mut socket_path = None;
    let mut confirm = false;
    let mut live = false;
    let mut adapter = false;
    let mut args = args[1..].iter();
    while let Some(key) = args.next() {
        match key.to_str() {
            Some("--config") if config.is_none() => {
                config = Some(PathBuf::from(args.next().ok_or(HELP)?))
            }
            Some("--state-file") if fixture.is_none() => {
                fixture = Some(PathBuf::from(args.next().ok_or(HELP)?))
            }
            Some("--listen") if address.is_none() => {
                address = Some(
                    args.next()
                        .and_then(|v| v.to_str())
                        .ok_or(HELP)?
                        .parse::<SocketAddrV4>()
                        .map_err(|_| HELP)?,
                )
            }
            Some("--socket") if socket_path.is_none() => {
                let absolute = PathBuf::from(args.next().ok_or(HELP)?);
                use std::os::unix::fs::FileTypeExt;
                if !absolute.is_absolute()
                    || !absolute
                        .symlink_metadata()
                        .is_ok_and(|m| m.file_type().is_socket())
                {
                    return Err("Expected an absolute path to a local Unix socket".into());
                }
                socket_path = Some(absolute);
            }
            Some("--confirm") if !confirm => confirm = true,
            Some("--live") if !live => live = true,
            Some("--adapter") if !adapter && funnel_only && !retire_dedicated => adapter = true,
            _ => return Err(HELP.into()),
        }
    }
    if change != confirm || (fixture.is_some() && (change || live || socket_path.is_some())) {
        return Err(HELP.into());
    }
    let path = config.ok_or(HELP)?;
    let policy = change.then(|| PolicyFile::lock(&path, true)).transpose()?;
    let settings = if let Some(policy) = &policy {
        policy.snapshot()?
    } else {
        PolicyFile::preview(&path)?
    };
    verify_approvals(&settings)?;
    let receipt = PolicyFile::read_serve_receipt(&path)?
        .map(|bytes| {
            serde_json::from_slice::<Routes>(&bytes)
                .map_err(|_| "Invalid Veyl Serve ownership receipt")
        })
        .transpose()?;
    let mcp = address.unwrap_or_else(|| "127.0.0.1:7331".parse().unwrap());
    let add = !matches!(action, "remove" | "rollback");
    let public = settings
        .tailnet
        .as_ref()
        .and_then(|serve| serve.funnel.as_ref());
    let shared = settings
        .tailnet
        .as_ref()
        .is_some_and(|serve| serve.shared_funnel);
    if !shared && (adapter || retire_dedicated) {
        return Err("This command requires tailscale_serve.shared_funnel".into());
    }
    if funnel_only && !disable_funnel && public.is_none() {
        return Err("Configure tailscale_serve.funnel before enabling public MCP".into());
    }
    if action == "funnel-apply" {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let client = settings
            .clients
            .iter()
            .find(|client| {
                public.is_some_and(|public| client.id == public.client)
                    && client.mode == mcp_gateway::security::policy::ExecutionMode::BroadYolo
                    && now < client.expires_at
            })
            .ok_or("Funnel needs its approved, unexpired Broad YOLO client")?;
        crate::jobs::broad::Broad::prepare(&path, &settings)?
            .probe(&client.root)
            .map_err(|_| "Broad YOLO sandbox preflight failed")?;
    }
    let routes = if !add || disable_funnel {
        let Some(known) = receipt.clone() else {
            println!(
                "{}",
                json!({"action": action,"changed":false,"ownership":"absent"})
            );
            return Ok(());
        };
        known
    } else {
        let tail = settings
            .tailnet
            .as_ref()
            .ok_or("Configure tailscale_serve first")?;
        let admin = settings
            .admin_listen
            .ok_or("Configure admin_listen first")?;
        let std::net::SocketAddr::V4(admin) = admin else {
            return Err("Use IPv4 admin loopback".into());
        };
        if !mcp.ip().is_loopback()
            || mcp.ip().octets() != [127, 0, 0, 1]
            || mcp.port() == 0
            || admin.port() == 0
            || admin == mcp
        {
            return Err("Two distinct fixed 127.0.0.1 backend ports are required".into());
        }
        let id = receipt
            .as_ref()
            .map(|value| value.id.clone())
            .unwrap_or(revision().map_err(|_| "Randomness unavailable")?);
        let routes = Routes::of(tail, mcp, admin, id);
        if let Some(known) = &receipt
            && (known.targets != routes.targets
                || known.host != routes.host
                || known.ports != routes.ports)
        {
            return Err("Current plan differs from recorded routes. Roll back the recorded pair before changing it.".into());
        }
        routes
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Cannot initialize LocalAPI client")?;
    let socket = socket_path.as_deref().unwrap_or(Path::new(SOCKET));
    let use_live =
        change || live || (matches!(action, "inspect" | "funnel-plan") && fixture.is_none());
    let (state, etag) = if use_live {
        let (status, _) = runtime.block_on(local_request(
            socket,
            Method::GET,
            "/localapi/v0/status?peers=false",
            None,
            vec![],
        ))?;
        if status["BackendState"] != "Running"
            || status["Self"]["DNSName"]
                .as_str()
                .map(|name| name.trim_end_matches('.'))
                != Some(&routes.host)
        {
            return Err("Serve hostname does not match this running Tailscale node".into());
        }
        if add
            && !disable_funnel
            && !status["CertDomains"]
                .as_array()
                .is_some_and(|domains| domains.iter().any(|domain| domain == &routes.host))
        {
            return Err(
                "This tailnet has not enabled a certificate for the configured hostname".into(),
            );
        }
        if funnel_only
            && !disable_funnel
            && !retire_dedicated
            && !node_allows_funnel(&status, if shared { 443 } else { routes.ports[0] })
        {
            return Err(
                "This Tailscale node is not authorized for Funnel on the configured MCP port"
                    .into(),
            );
        }
        let (state, etag) =
            runtime.block_on(local_request(socket, Method::GET, API, None, vec![]))?;
        (state_object(state)?, etag)
    } else if let Some(path) = &fixture {
        (
            state_object(crate::serve_plan::read_snapshot(path)?)?,
            String::new(),
        )
    } else {
        (json!({}), String::new())
    };

    let allow_public = public.is_some() || disable_funnel;
    let owned = [
        route_state(&state, &routes, 0, allow_public)? == RouteState::Owned,
        route_state(&state, &routes, 1, false)? == RouteState::Owned,
    ];
    let next = if funnel_only {
        if receipt.is_none() {
            return Err("Apply private Serve before changing Funnel".into());
        }
        if retire_dedicated {
            if shared_state(&state, &routes)? != SharedState::Enabled || !owned[1] {
                return Err(
                    "Activate native shared Funnel and verify the private dashboard first".into(),
                );
            }
            funnel_transition(&state, &routes, false)?
        } else if shared {
            if !disable_funnel && (!owned[0] || !owned[1]) {
                return Err("Shared Funnel needs the owned private Serve route pair".into());
            }
            shared_transition(&state, &routes, !disable_funnel, adapter)?
        } else {
            funnel_transition(&state, &routes, !disable_funnel)?
        }
    } else {
        if !add
            && shared
            && matches!(
                shared_state(&state, &routes),
                Ok(SharedState::Enabled | SharedState::Disabled)
            )
        {
            return Err("The owned shared mount depends on the Serve receipt. Roll back the public path separately".into());
        }
        transition(&state, &routes, add)?
    };
    if let Some(config) = &policy
        && next != state
    {
        if etag.is_empty() || etag == "*" {
            return Err("LocalAPI did not provide the conditional Serve version".into());
        }
        let audit = AuditSink::open_with_limits(
            settings
                .audit_log
                .as_deref()
                .ok_or("Serve mutation requires audit logging")?,
            settings.audit_limits,
        )
        .map_err(|_| "Serve mutation requires a healthy audit ledger")?;
        let audit_name = match action {
            "funnel-apply" => "funnel_apply",
            "funnel-rollback" => "funnel_rollback",
            "funnel-retire-dedicated" => "funnel_retire_dedicated",
            _ if add => "serve_apply",
            _ => "serve_remove",
        };
        let record = |phase| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            audit.record_runtime_mode("local_operator", audit_name, "standard", phase, now)
        };
        record(AuditPhase::Intent).map_err(|_| "Cannot audit Serve intent")?;
        if receipt.is_none() {
            config.write_serve_receipt(
                &serde_json::to_vec(&routes).map_err(|_| "Cannot encode route receipt")?,
            )?;
        }
        let result = runtime.block_on(local_request(
            socket,
            Method::POST,
            API,
            Some(&etag),
            serde_json::to_vec(&next).map_err(|_| "Cannot encode Serve configuration")?,
        ));
        if let Err(error) = result {
            if receipt.is_none() && error.starts_with("Serve changed concurrently") {
                config.remove_serve_receipt()?;
            }
            return Err(error);
        }
        let (response, _) =
            runtime.block_on(local_request(socket, Method::GET, API, None, vec![]))?;
        let response = state_object(response)?;
        let expected = [if add {
            RouteState::Owned
        } else {
            RouteState::Absent
        }; 2];
        let verified = if funnel_only {
            response["AllowFunnel"][routes.authority(0)] == next["AllowFunnel"][routes.authority(0)]
                && response["Web"] == next["Web"]
                && response["TCP"] == next["TCP"]
                && response["AllowFunnel"] == next["AllowFunnel"]
        } else {
            [
                route_state(&response, &routes, 0, allow_public)?,
                route_state(&response, &routes, 1, false)?,
            ] == expected
        };
        if !verified {
            let _ = record(AuditPhase::Uncertain);
            return Err("Serve update could not be verified. Inspect current routes.".into());
        }
        record(AuditPhase::Success)
            .map_err(|_| "Serve outcome could not be audited. Inspect current routes.")?;
    }
    if let Some(config) = &policy
        && !add
    {
        config.remove_serve_receipt()?;
    }
    let effective = if change { &next } else { &state };
    let shared_active = shared
        && shared_state(effective, &routes).is_ok_and(|status| status == SharedState::Enabled);
    let dedicated_mcp = format!("https://{}/mcp", routes.authority(0));
    println!(
        "{}",
        json!({
            "action": action, "source": if use_live {"tailscaled"} else if fixture.is_some() {"snapshot"} else {"configuration-only"},
            "changed": change && next != state, "owned_before": owned,
            "private": !shared_active && effective["AllowFunnel"][routes.authority(0)] != true,
            "funnel_configured": public.is_some(),
            "shared_funnel_active": shared_active,
            "dedicated_funnel_active": effective["AllowFunnel"][routes.authority(0)] == true,
            "mcp": if shared_active || (shared && action == "funnel-plan") { format!("https://{}/veyl/mcp", routes.host) } else { dedicated_mcp.clone() },
            "dedicated_mcp": dedicated_mcp,
            "dashboard": format!("https://{}/dashboard", routes.authority(1)),
            "backends": routes.targets
        })
    );
    Ok(())
}

/// Small operator-facing diagnostic. It never reads other handlers into output.
pub(crate) fn health(config: &Path, settings: Option<&Settings>) -> Value {
    let Some(settings) = settings else {
        return json!({"state":"unconfigured"});
    };
    let routes = || -> Result<Option<Routes>, String> {
        PolicyFile::read_serve_receipt(config)?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|_| "Invalid Veyl Serve receipt".into())
            })
            .transpose()
    };
    let (state, shared_active, dedicated_public) = match routes() {
        Ok(None) => ("untracked", false, false),
        Ok(Some(routes)) => {
            let actual = || -> Result<([bool; 2], bool, bool), String> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| "LocalAPI runtime unavailable")?;
                let (document, _) = runtime.block_on(local_request(
                    Path::new(SOCKET),
                    Method::GET,
                    API,
                    None,
                    vec![],
                ))?;
                let document = state_object(document)?;
                let owned = [
                    route_state(&document, &routes, 0, settings.funnel.is_some())?
                        == RouteState::Owned,
                    route_state(&document, &routes, 1, false)? == RouteState::Owned,
                ];
                let shared = settings.shared_funnel
                    && shared_state(&document, &routes)? == SharedState::Enabled;
                Ok((
                    owned,
                    shared,
                    document["AllowFunnel"][routes.authority(0)] == true,
                ))
            };
            match actual() {
                Ok(([true, true], shared, dedicated)) => ("active", shared, dedicated),
                Ok(([false, false], false, false)) => ("inactive", false, false),
                Ok((_, shared, dedicated)) => ("partial", shared, dedicated),
                Err(_) => ("unavailable-or-colliding", false, false),
            }
        }
        Err(_) => ("unavailable", false, false),
    };
    let mcp = if shared_active {
        format!("https://{}/veyl/mcp", settings.hostname)
    } else {
        format!("https://{}/mcp", settings.authority(false))
    };
    json!({"state":state,"mcp":mcp,"public":shared_active || dedicated_public,
        "dashboard":format!("https://{}/dashboard", settings.authority(true))})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collision_check_and_rollback_preserve_other_ingress() {
        let routes = Routes::of(&Settings::parse(&json!({"hostname":"node.demo.ts.net","mcp_https_port":8443,"admin_https_port":9443})).unwrap(),
            "127.0.0.1:7331".parse().unwrap(), "127.0.0.1:7332".parse().unwrap(), "owner-proof".into());
        let initial = json!({"TCP":{"443":{"HTTPS":true}},"Web":{"node.demo.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}}, "AllowFunnel":{"node.demo.ts.net:443":true}});
        let next = transition(&initial, &routes, true).unwrap();
        assert_eq!(next, transition(&next, &routes, true).unwrap());
        assert_eq!(transition(&next, &routes, false).unwrap(), initial);
        for collision in [
            json!({"TCP":{"8443":{"HTTPS":true}}}),
            json!({"AllowFunnel":{"alternate.demo.ts.net:9443":true}}),
            json!({"Foreground":{"xyz":{"TCP":{"9443":{"HTTPS":true}}}}}),
            json!({"Web":{"other.demo.ts.net:8443":{"Handlers":{}}}}),
        ] {
            assert!(transition(&collision, &routes, true).is_err());
            assert!(transition(&collision, &routes, false).is_err());
        }
    }
}
