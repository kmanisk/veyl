//! Private, compare-and-swap updates to the local Tailscale Serve configuration.

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

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub hostname: String,
    pub mcp_https_port: u16,
    pub admin_https_port: u16,
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

fn route_state(state: &Value, routes: &Routes, index: usize) -> Result<RouteState, String> {
    let key = routes.authority(index);
    let port = routes.ports[index];
    let same_port = |host: &str| {
        host.rsplit_once(':')
            .and_then(|(_, tail)| tail.parse::<u16>().ok())
            == Some(port)
    };
    if entries(state, "AllowFunnel")?.any(|(host, enabled)| same_port(host) && *enabled != false) {
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
        (false, None) => Ok(RouteState::Absent),
        _ => Err(format!("Another TCP listener occupies HTTPS port {port}")),
    }
}

fn transition(state: &Value, routes: &Routes, add: bool) -> Result<Value, String> {
    let statuses = [
        route_state(state, routes, 0)?,
        route_state(state, routes, 1)?,
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

const HELP: &str = "usage: mcp-gateway serve <plan|validate|inspect|apply|remove|rollback> --config PATH [--listen 127.0.0.1:PORT] [--state-file PATH | --live] [--socket PATH] [--confirm]";

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args.iter().any(|a| a == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let action = args.first().and_then(|s| s.to_str()).ok_or(HELP)?;
    if !matches!(
        action,
        "plan" | "validate" | "inspect" | "apply" | "remove" | "rollback"
    ) {
        return Err(HELP.into());
    }
    let change = matches!(action, "apply" | "remove" | "rollback");
    let mut config = None;
    let mut fixture = None;
    let mut address = None;
    let mut socket_path = None;
    let mut confirm = false;
    let mut live = false;
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
    let add = action != "remove" && action != "rollback";
    let routes = if !add {
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
    let use_live = change || live || (action == "inspect" && fixture.is_none());
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
            && !status["CertDomains"]
                .as_array()
                .is_some_and(|domains| domains.iter().any(|domain| domain == &routes.host))
        {
            return Err(
                "This tailnet has not enabled a certificate for the configured hostname".into(),
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

    let owned = [
        route_state(&state, &routes, 0)? == RouteState::Owned,
        route_state(&state, &routes, 1)? == RouteState::Owned,
    ];
    let next = transition(&state, &routes, add)?;
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
        let audit_name = if add { "serve_apply" } else { "serve_remove" };
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
        if [
            route_state(&response, &routes, 0)?,
            route_state(&response, &routes, 1)?,
        ] != [if add {
            RouteState::Owned
        } else {
            RouteState::Absent
        }; 2]
        {
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
    println!(
        "{}",
        json!({
            "action": action, "source": if use_live {"tailscaled"} else if fixture.is_some() {"snapshot"} else {"configuration-only"},
            "changed": change && next != state, "owned_before": owned, "private":true,
            "mcp": format!("https://{}/mcp", routes.authority(0)),
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
    let state = match routes() {
        Ok(None) => "untracked",
        Ok(Some(routes)) => {
            let actual = || -> Result<[bool; 2], String> {
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
                Ok([
                    route_state(&document, &routes, 0)? == RouteState::Owned,
                    route_state(&document, &routes, 1)? == RouteState::Owned,
                ])
            };
            match actual() {
                Ok([true, true]) => "active",
                Ok([false, false]) => "inactive",
                Ok(_) => "partial",
                Err(_) => "unavailable-or-colliding",
            }
        }
        Err(_) => "unavailable",
    };
    json!({"state":state,"mcp":format!("https://{}/mcp", settings.authority(false)),
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
