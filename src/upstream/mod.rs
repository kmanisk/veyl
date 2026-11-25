//! Operator-configured MCP upstreams. Upstreams never inherit client credentials.
pub(crate) mod admin;
mod http;
pub(crate) mod installer;
mod stdio;
mod workspace;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hyper::Uri;
use serde_json::{Value, json};

use crate::tools::registry::Tool;

const MAX_SERVERS: usize = 8;
const MAX_TOOLS: usize = 48;
const MAX_FRAME: usize = 65_536;
const VERSION: &str = "2025-11-25";
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
pub(crate) struct Grants {
    pub servers: BTreeSet<String>,
    pub tools: Option<BTreeMap<String, BTreeSet<String>>>,
    workspaces: BTreeMap<String, workspace::Grant>,
}

impl Grants {
    pub(crate) fn parse(entry: &Value, catalog: &Catalog) -> Result<Self, String> {
        let servers = names(entry.get("allowed_servers"), MAX_SERVERS, server_name)?;
        let tools = entry
            .get("allowed_server_tools")
            .map(|value| {
                let map = value
                    .as_object()
                    .ok_or("Expected allowed_server_tools object")?;
                let mut grants = BTreeMap::new();
                for (id, raw) in map {
                    if !servers.contains(id) || !catalog.0.contains_key(id) {
                        return Err(
                            "Tool grants require a registered and granted server".to_owned()
                        );
                    }
                    grants.insert(id.clone(), names(Some(raw), MAX_TOOLS, tool_name)?);
                }
                Ok(grants)
            })
            .transpose()?;
        if servers.iter().any(|id| !catalog.0.contains_key(id)) {
            return Err("Unknown upstream server in client grant".into());
        }
        let mut workspaces = BTreeMap::new();
        if let Some(raw) = entry.get("upstream_workspace_roots") {
            let map = raw
                .as_object()
                .ok_or("Expected upstream_workspace_roots object")?;
            for (id, path) in map {
                if !matches!(id.as_str(), "rea" | "rust-anything")
                    || !servers.contains(id)
                    || tools.is_none()
                    || !catalog.0.get(id).is_some_and(|s| {
                        matches!(&s.transport, Transport::Stdio { bundle: true, .. })
                    })
                {
                    return Err("Workspace access requires a supported, bundled and explicitly granted provider".into());
                }
                workspaces.insert(id.clone(), workspace::Grant::parse(path)?);
            }
        }
        Ok(Self {
            servers,
            tools,
            workspaces,
        })
    }

    pub(crate) fn workspace_metadata(&self) -> Value {
        json!(
            self.workspaces
                .iter()
                .map(|(id, grant)| (
                    id,
                    json!({
                        "root":grant.root,"provider_only":grant.provider_only
                    })
                ))
                .collect::<BTreeMap<_, _>>()
        )
    }

    pub(crate) fn validate_workspaces(
        &self,
        config: &Path,
        settings: &crate::http::admission::Configuration,
        client: &crate::http::admission::Client,
    ) -> Result<(), String> {
        for grant in self.workspaces.values() {
            grant.validate(config, settings, client)?;
        }
        Ok(())
    }

    pub(crate) fn scoped_call(&self, payload: &Value) -> bool {
        if payload["method"] != "tools/call" {
            return false;
        }
        let params = &payload["params"];
        let Some(requested) = params["name"].as_str() else {
            return false;
        };
        let (requested, args) = if requested == "mcp_servers_call" {
            let call = &params["arguments"];
            let Some(name) = call["name"].as_str() else {
                return false;
            };
            (name, &call["arguments"])
        } else {
            (requested, &params["arguments"])
        };
        let Some((id, name)) = requested.split_once("__") else {
            return false;
        };
        if !self.allows(id, name) || !args.is_object() || args.to_string().len() > MAX_FRAME / 2 {
            return false;
        }
        self.workspaces
            .get(id)
            .is_some_and(|grant| matches!(grant.prepare(id, name, &mut args.clone()), Ok(Some(_))))
    }

    pub fn allows(&self, id: &str, tool: &str) -> bool {
        self.servers.contains(id)
            && self
                .tools
                .as_ref()
                .is_none_or(|map| map.get(id).is_some_and(|names| names.contains(tool)))
    }

    fn has_tools(&self, id: &str) -> bool {
        self.servers.contains(id)
            && self
                .tools
                .as_ref()
                .is_none_or(|map| map.get(id).is_some_and(|names| !names.is_empty()))
    }
}

#[derive(Default)]
pub(crate) struct Catalog(BTreeMap<String, Server>);

struct Server {
    transport: Transport,
    disabled: bool,
}

enum Transport {
    Stdio {
        command: String,
        args: Vec<String>,
        bundle: bool,
    },
    Http {
        uri: Uri,
        route: SocketAddr,
        use_token: bool,
        private_ca: bool,
    },
}

impl Catalog {
    pub(crate) fn parse(document: &Value) -> Result<Self, String> {
        let Some(value) = document.get("mcp_servers") else {
            return Ok(Self::default());
        };
        let entries = value.as_object().ok_or("Expected mcp_servers object")?;
        if entries.len() > MAX_SERVERS {
            return Err("Too many upstream servers".into());
        }
        let mut servers = BTreeMap::new();
        for (id, raw) in entries {
            if !server_name(id) {
                return Err("Invalid upstream server identifier".into());
            }
            servers.insert(id.clone(), Server::parse(raw)?);
        }
        Ok(Self(servers))
    }

    pub fn empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains_server(&self, id: &str) -> bool {
        self.0.contains_key(id)
    }

    pub fn fingerprint_and_info(&self, grants: &Grants, id: &str) -> Result<Value, &'static str> {
        use sha2::{Digest, Sha256};

        if !server_name(id) || !grants.servers.contains(id) {
            return Err("PROVIDER_NOT_FOUND");
        }
        let server = self.0.get(id).ok_or("PROVIDER_NOT_FOUND")?;
        let canonical = match &server.transport {
            Transport::Stdio {
                command,
                args,
                bundle,
            } => {
                let mut value = json!({
                    "id": id, "enabled": !server.disabled, "transport": "stdio",
                    "command": command, "args": args,
                });
                if *bundle {
                    value["runtime_bundle"] = json!(true);
                }
                value
            }
            Transport::Http {
                uri,
                route,
                use_token,
                private_ca,
            } => json!({
                "id": id,
                "enabled": !server.disabled,
                "transport": "http",
                "url": uri.to_string(),
                "route": route.to_string(),
                "use_token": use_token,
                "private_ca": private_ca,
            }),
        };
        let mut canonical = canonical;
        if let Some(grant) = grants.workspaces.get(id) {
            canonical["workspace_root"] = json!(grant.root);
            canonical["workspace_identity"] = json!(grant.identity);
            canonical["workspace_provider_only"] = json!(grant.provider_only);
        }
        let provider_fingerprint =
            format!("{:x}", Sha256::digest(canonical.to_string().as_bytes()));
        let mut granted_tools: Vec<&str> = grants
            .tools
            .as_ref()
            .and_then(|map| map.get(id))
            .map(|set| set.iter().map(String::as_str).collect())
            .unwrap_or_default();
        granted_tools.sort();
        Ok(json!({
            "id": id,
            "enabled": !server.disabled,
            "provider_fingerprint": provider_fingerprint,
            "config": {
                "transport": canonical["transport"],
                "command": canonical
                    .get("command")
                    .and_then(Value::as_str)
                    .and_then(|p| Path::new(p).file_name())
                    .and_then(|s| s.to_str()),
                "url": match &server.transport {
                    Transport::Http { uri, .. } => Some(format!(
                        "{}://{}",
                        uri.scheme_str().unwrap_or("https"),
                        uri.authority().map_or("", hyper::http::uri::Authority::as_str)
                    )),
                    Transport::Stdio { .. } => None,
                },
                "credentials": matches!(server.transport, Transport::Http { use_token: true, .. }),
                "granted_tools": granted_tools,
                "workspace_root": canonical.get("workspace_root"),
                "workspace_provider_only": canonical.get("workspace_provider_only"),
            },
        }))
    }

    pub fn listing(&self, grants: Option<&Grants>) -> Value {
        Value::Array(self.0.iter().filter_map(|(id, server)| {
            if grants.is_some_and(|grants| !grants.servers.contains(id) || server.disabled) {
                return None;
            }
            Some(json!({
                "id": id, "enabled": !server.disabled,
                "transport": match &server.transport {
                    Transport::Stdio {..} => "stdio",
                    Transport::Http {uri, ..} => uri.scheme_str().unwrap_or("http"),
                },
                "credentials": matches!(server.transport, Transport::Http {use_token: true, ..}),
            }))
        }).collect())
    }

    pub fn discover(&self, config: &Path, grants: &Grants) -> Vec<Value> {
        let Ok(_slot) = Slot::acquire() else {
            return Vec::new();
        };
        let overall = Instant::now() + Duration::from_secs(3);
        let mut result = Vec::new();
        for (id, server) in self
            .0
            .iter()
            .filter(|(id, server)| !server.disabled && grants.has_tools(id))
        {
            if Instant::now() >= overall {
                break;
            }
            if let Ok(tools) = with_link(config, id, server, overall, Link::discover) {
                for (name, mut value) in tools {
                    if grants.allows(id, &name) {
                        value["name"] = json!(qualified(id, &name));
                        result.push(value);
                    }
                    if result.len() >= MAX_TOOLS {
                        return result;
                    }
                }
            }
        }
        result
    }

    pub fn call(
        &self,
        config: &Path,
        grants: &Grants,
        requested: &str,
        args: Option<&Value>,
        mut audit: impl FnMut(&str, bool, bool) -> bool,
    ) -> Result<Value, &'static str> {
        if grants.servers.is_empty() || Tool::parse(requested).is_some() {
            return Err("Upstream tool not granted");
        }
        let empty = json!({});
        let args = args.unwrap_or(&empty);
        if !args.is_object() || args.to_string().len() > MAX_FRAME / 2 {
            return Err("Invalid upstream arguments");
        }
        let _slot = Slot::acquire().map_err(|_| "Upstream capacity reached")?;
        let overall = Instant::now() + Duration::from_secs(3);
        let (id, name) = if let Some((id, name)) = requested.split_once("__") {
            if !server_name(id) || !tool_name(name) || !grants.allows(id, name) {
                return Err("Upstream tool not granted");
            }
            (id.to_owned(), name)
        } else {
            if !tool_name(requested) || grants.tools.is_some() {
                return Err("Use a granted namespaced upstream tool");
            }
            // Compatibility for explicitly server-wide legacy grants. Never
            // choose an unqualified name if another server might implement it.
            if !audit("upstream_alias_resolution", true, false) {
                return Err("Upstream audit intent unavailable");
            }
            let resolve = || {
                let mut found = None;
                for (id, server) in self
                    .0
                    .iter()
                    .filter(|(id, server)| !server.disabled && grants.allows(id, requested))
                {
                    let tools = with_link(config, id, server, overall, Link::discover)
                        .map_err(|_| "Cannot resolve unqualified upstream tool")?;
                    if tools.contains_key(requested) && found.replace(id.clone()).is_some() {
                        return Err("Ambiguous upstream name; use the namespaced tool");
                    }
                }
                found.ok_or("Upstream tool not found")
            };
            let selected = resolve();
            if !audit("upstream_alias_resolution", false, selected.is_ok()) {
                return Err("Upstream outcome could not be audited");
            }
            (selected?, requested)
        };
        let server = self
            .0
            .get(&id)
            .filter(|server| !server.disabled)
            .ok_or("Upstream server unavailable")?;
        let public = qualified(&id, name);
        if !audit(&public, true, false) {
            return Err("Upstream audit intent unavailable");
        }
        // An explicitly configured runtime bundle may need additional cold-start
        // time for its language runtime. Keep ordinary providers and discovery
        // at their existing limits, and stay below the HTTP request deadline.
        let bundled = matches!(&server.transport, Transport::Stdio { bundle: true, .. });
        let budget = if bundled {
            Duration::from_secs(4)
        } else {
            Duration::from_millis(1700)
        };
        let overall = if bundled && requested.contains("__") {
            Instant::now() + budget
        } else {
            overall
        };
        let mut translated = args.clone();
        let result = (|| {
            let workspace = grants
                .workspaces
                .get(&id)
                .map(|grant| grant.prepare(&id, name, &mut translated))
                .transpose()
                .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))?
                .flatten();
            let (overall, budget) = if workspace.is_some() {
                let budget = Duration::from_secs(8);
                (Instant::now() + budget, budget)
            } else {
                (overall, budget)
            };
            with_link_budget(
                config,
                &id,
                server,
                overall,
                budget,
                workspace.as_ref(),
                |link| {
                    if !link.discover()?.contains_key(name) {
                        return Err(io::Error::other("Tool not discovered"));
                    }
                    let result =
                        link.request("tools/call", json!({"name":name,"arguments":translated}))?;
                    if !result.get("content").is_some_and(Value::is_array) {
                        return Err(io::Error::other("Invalid upstream tool result"));
                    }
                    Ok(result)
                },
            )
        })();
        if !audit(
            &public,
            false,
            result.as_ref().is_ok_and(|value| value["isError"] != true),
        ) {
            return Err("Upstream outcome could not be audited");
        }
        result.map_err(|error| match error.kind() {
            io::ErrorKind::TimedOut => "Upstream call timed out",
            io::ErrorKind::PermissionDenied => {
                "Upstream input outside granted workspace or invalid"
            }
            _ => "Upstream rejected the call or became unavailable",
        })
    }

    pub(crate) fn probe(&self, config: &Path, id: &str) -> Result<Value, String> {
        let server = self.0.get(id).ok_or("Unknown upstream server")?;
        if server.disabled {
            return Ok(json!({"id":id,"health":"disabled","tools":[]}));
        }
        let _slot = Slot::acquire().map_err(|_| "Upstream capacity reached")?;
        let bundled = matches!(&server.transport, Transport::Stdio { bundle: true, .. });
        let budget = if bundled {
            Duration::from_secs(4)
        } else {
            Duration::from_millis(1700)
        };
        let deadline = Instant::now() + budget;
        Ok(
            match with_link_budget(config, id, server, deadline, budget, None, Link::discover) {
                Ok(discovered) => {
                    json!({"id":id,"health":"ready","tools":discovered.keys().collect::<Vec<_>>()})
                }
                Err(_) => json!({"id":id,"health":"unavailable","tools":[]}),
            },
        )
    }
}

impl Server {
    fn parse(raw: &Value) -> Result<Self, String> {
        let fields = raw
            .as_object()
            .ok_or("Expected an upstream configuration object")?;
        let disabled = fields
            .get("enabled")
            .map_or(Some(false), |value| value.as_bool().map(|enabled| !enabled))
            .ok_or("Invalid upstream enabled flag")?;
        let transport = match fields.get("transport").and_then(Value::as_str) {
            Some("stdio")
                if fields.keys().all(|k| {
                    matches!(
                        k.as_str(),
                        "transport" | "command" | "args" | "env" | "enabled" | "runtime_bundle"
                    )
                }) =>
            {
                if fields
                    .get("env")
                    .is_some_and(|env| !env.as_object().is_some_and(serde_json::Map::is_empty))
                {
                    return Err("Stdio upstreams run with an isolated environment".into());
                }
                let command = fields
                    .get("command")
                    .and_then(Value::as_str)
                    .filter(|path| absolute(path))
                    .ok_or("Expected an absolute upstream executable path")?;
                let args = match fields.get("args") {
                    None => Vec::new(),
                    Some(args) => args
                        .as_array()
                        .filter(|args| args.len() <= 24)
                        .ok_or("Invalid upstream argv")?
                        .iter()
                        .map(|arg| {
                            arg.as_str()
                                .filter(|arg| arg.len() <= 512 && !arg.contains('\0'))
                                .map(str::to_owned)
                                .ok_or("Invalid upstream argv")
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                };
                let bundle = fields
                    .get("runtime_bundle")
                    .map_or(Some(false), Value::as_bool)
                    .ok_or("Invalid runtime bundle flag")?;
                Transport::Stdio {
                    command: command.to_owned(),
                    args,
                    bundle,
                }
            }
            Some("http")
                if fields.keys().all(|k| {
                    matches!(
                        k.as_str(),
                        "transport" | "url" | "enabled" | "use_token" | "connect_ip" | "private_ca"
                    )
                }) =>
            {
                let url = fields
                    .get("url")
                    .and_then(Value::as_str)
                    .filter(|url| url.len() <= 600)
                    .ok_or("Expected upstream URL")?;
                let address = fields
                    .get("connect_ip")
                    .map(|raw| raw.as_str().ok_or("Expected numeric connect_ip"))
                    .transpose()?;
                let (uri, route) =
                    http::endpoint(url, address).map_err(|error| error.to_string())?;
                let use_token = fields
                    .get("use_token")
                    .map_or(Some(false), Value::as_bool)
                    .ok_or("Invalid upstream credential flag")?;
                let private_ca = fields
                    .get("private_ca")
                    .map_or(Some(false), Value::as_bool)
                    .ok_or("Invalid private_ca flag")?;
                if uri.scheme_str() != Some("https") && (use_token || private_ca) {
                    return Err("Upstream credentials and private CAs require HTTPS".into());
                }
                Transport::Http {
                    uri,
                    route,
                    use_token,
                    private_ca,
                }
            }
            _ => return Err("Invalid or unsupported upstream transport configuration".into()),
        };
        Ok(Self {
            transport,
            disabled,
        })
    }
}

fn names(
    raw: Option<&Value>,
    max: usize,
    valid: fn(&str) -> bool,
) -> Result<BTreeSet<String>, String> {
    let Some(raw) = raw else {
        return Ok(BTreeSet::new());
    };
    let values = raw
        .as_array()
        .filter(|values| values.len() <= max)
        .ok_or("Invalid upstream grant list")?;
    let mut result = BTreeSet::new();
    for item in values {
        let name = item
            .as_str()
            .filter(|name| valid(name))
            .ok_or("Invalid upstream grant target")?;
        if !result.insert(name.to_owned()) {
            return Err("Duplicate upstream grant".into());
        }
    }
    Ok(result)
}

fn absolute(path: &str) -> bool {
    path.len() <= 1024
        && path.starts_with('/')
        && !path.contains('\0')
        && !path.split('/').any(|part| part == "." || part == "..")
}

pub(crate) fn server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 24
        && !name.contains("__")
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}
pub(crate) fn tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 37
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn qualified(id: &str, name: &str) -> String {
    format!("{id}__{name}")
}

struct Slot;
impl Slot {
    fn acquire() -> io::Result<Self> {
        ACTIVE
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                (n < 6).then_some(n + 1)
            })
            .map(|_| Self)
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Release);
    }
}

struct Link {
    connection: Connection,
    deadline: Instant,
    next: u32,
    remaining: usize,
}

enum Connection {
    Stdio(stdio::Process),
    Http(Box<http::Http>),
}

fn with_link<T>(
    config: &Path,
    id: &str,
    server: &Server,
    overall: Instant,
    f: impl FnOnce(&mut Link) -> io::Result<T>,
) -> io::Result<T> {
    with_link_budget(
        config,
        id,
        server,
        overall,
        Duration::from_millis(1700),
        None,
        f,
    )
}

fn with_link_budget<T>(
    config: &Path,
    id: &str,
    server: &Server,
    overall: Instant,
    budget: Duration,
    workspace: Option<&workspace::Input>,
    f: impl FnOnce(&mut Link) -> io::Result<T>,
) -> io::Result<T> {
    let deadline = overall.min(Instant::now() + budget);
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let connection = match &server.transport {
        Transport::Stdio {
            command,
            args,
            bundle,
        } => {
            let root = if *bundle {
                Some(
                    config
                        .parent()
                        .ok_or(io::ErrorKind::InvalidInput)?
                        .join("upstream-bundles")
                        .join(id),
                )
            } else {
                None
            };
            Connection::Stdio(stdio::Process::start(
                command,
                args,
                root.as_deref(),
                workspace,
            )?)
        }
        Transport::Http {
            uri,
            route,
            use_token,
            private_ca,
        } => {
            let token = if *use_token {
                Some(credential(config, id)?)
            } else {
                None
            };
            let ca = if *private_ca {
                Some(private_input(config, id, "ca.pem")?)
            } else {
                None
            };
            Connection::Http(Box::new(http::Http::new(uri.clone(), *route, token, ca)?))
        }
    };
    let mut link = Link {
        connection,
        deadline,
        next: 1,
        remaining: MAX_FRAME * 2,
    };
    let result = (|| {
        let result = link.request(
            "initialize",
            json!({"protocolVersion":VERSION,"capabilities":{},
            "clientInfo":{"name":"Veyl","version":env!("CARGO_PKG_VERSION")}}),
        )?;
        let version = http::version(&result["protocolVersion"])
            .ok_or_else(|| io::Error::other("Unsupported upstream protocol"))?;
        if let Connection::Http(http) = &mut link.connection {
            http.negotiate(version);
        }
        link.notify()?;
        f(&mut link)
    })();
    if let Connection::Http(http) = &mut link.connection {
        http.close(overall.min(Instant::now() + Duration::from_millis(200)));
    }
    result
}

impl Link {
    fn request(&mut self, method: &str, params: Value) -> io::Result<Value> {
        let id = self.next;
        self.next += 1;
        let message = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        let response = match &mut self.connection {
            Connection::Stdio(process) => {
                process.send(&message, self.deadline)?;
                loop {
                    let response = process.read(self.deadline, &mut self.remaining)?;
                    if response["id"] == id {
                        break response;
                    }
                    // An upstream may emit an uncorrelated JSON-RPC error
                    // while processing the initialized notification. It cannot
                    // satisfy this request and remains subject to the frame budget.
                    if response["jsonrpc"] != "2.0"
                        || !(response.get("id").is_none() && response["method"].is_string()
                            || response["id"].is_null() && response["error"].is_object())
                    {
                        return Err(io::Error::other("Unexpected upstream message"));
                    }
                }
            }
            Connection::Http(http) => http
                .exchange(&message, Some(id), self.deadline)?
                .ok_or_else(|| io::Error::other("Empty upstream response"))?,
        };
        if response["id"] != id || response["jsonrpc"] != "2.0" || response.get("error").is_some() {
            return Err(io::Error::other("Invalid response or upstream RPC error"));
        }
        response
            .get("result")
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| io::Error::other("Missing upstream result"))
    }

    fn notify(&mut self) -> io::Result<()> {
        let notification = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        match &mut self.connection {
            Connection::Stdio(process) => process.send(&notification, self.deadline),
            Connection::Http(http) => http
                .exchange(&notification, None, self.deadline)
                .map(|_| ()),
        }
    }

    fn discover(&mut self) -> io::Result<BTreeMap<String, Value>> {
        let mut tools = BTreeMap::new();
        let mut params = json!({});
        for _ in 0..4 {
            let result = self.request("tools/list", params)?;
            let next_cursor = result.get("nextCursor");
            let entries = result["tools"]
                .as_array()
                .ok_or_else(|| io::Error::other("Invalid upstream tools list"))?;
            for tool in entries {
                let name = tool["name"]
                    .as_str()
                    .filter(|name| tool_name(name))
                    .ok_or_else(|| io::Error::other("Invalid upstream tool name"))?;
                if Tool::parse(name).is_some()
                    || tools.len() >= MAX_TOOLS
                    || !tool["inputSchema"].is_object()
                    || tool["inputSchema"]["type"] != "object"
                    || tool["inputSchema"].to_string().len() > 4096
                {
                    continue;
                }
                let description = tool["description"]
                    .as_str()
                    .unwrap_or_default()
                    .chars()
                    .take(512)
                    .collect::<String>();
                if tools.insert(name.to_owned(), json!({"name":name,"description":description,"inputSchema":tool["inputSchema"]})).is_some() {
                    return Err(io::Error::other("Duplicate upstream tool name"));
                }
            }
            let Some(cursor) = next_cursor else {
                return Ok(tools);
            };
            let cursor = cursor
                .as_str()
                .filter(|s| s.len() <= 256)
                .ok_or_else(|| io::Error::other("Invalid upstream cursor"))?;
            params = json!({"cursor":cursor});
        }
        Err(io::Error::other("Upstream discovery exceeded page limit"))
    }
}

fn sidecar(config: &Path, id: &str, suffix: &str) -> io::Result<PathBuf> {
    if !server_name(id) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(config
        .parent()
        .ok_or(io::ErrorKind::InvalidInput)?
        .join(format!(".mcp-upstream-{id}.{suffix}")))
}

fn credential(config: &Path, id: &str) -> io::Result<String> {
    String::from_utf8(private_input(config, id, "token")?)
        .map_err(io::Error::other)
        .and_then(valid_token)
}

fn private_input(config: &Path, id: &str, suffix: &str) -> io::Result<Vec<u8>> {
    crate::http::admission::read_config(&sidecar(config, id, suffix)?).map_err(io::Error::other)
}

fn valid_token(value: String) -> io::Result<String> {
    let token = value.trim_end_matches(['\r', '\n']);
    if token.is_empty()
        || token.len() > 4096
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
    {
        return Err(io::Error::other("Invalid upstream bearer credential"));
    }
    Ok(token.to_owned())
}
