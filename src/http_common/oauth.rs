//! Direct-remote OAuth preview: registration and metadata contract.
//! These route identifiers are not installed in the live HTTP gateway.
use hyper::Uri;
use serde_json::{Value, json};
use std::net::IpAddr;

use crate::core::credential::token_shape;
use crate::core::oauth::{AuthorizationRequest, Binding, ConnectionMode, Error, GrantStore, bounded};
use crate::core::session::random_id;

const MAX_CLIENTS: usize = 128;
const MAX_REDIRECTS: usize = 4;
pub const SCOPE: &str = "mcp";

/// Deliberately narrow first checkpoint: HTTPS DNS names only. Do not
/// normalize a registered redirect into another URI. Loopback desktop
/// redirects, query-bearing callbacks and CIMD need separate acceptance.
fn https_uri(value: &str) -> Option<Uri> {
    if !bounded(value, 2048)
        || !value.starts_with("https://")
        || value
            .bytes()
            .any(|c| c.is_ascii_whitespace() || matches!(c, b'#' | b'\\'))
    {
        return None;
    }
    let uri: Uri = value.parse().ok()?;
    let authority = uri.authority()?;
    if uri.scheme_str() != Some("https") || authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host();
    if host.len() > 253
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return None;
    }
    if let Some((_, raw_port)) = authority.as_str().split_once(':')
        && (raw_port.is_empty()
            || !raw_port.bytes().all(|c| c.is_ascii_digit())
            || authority.port_u16().is_none_or(|port| port == 0))
    {
        return None;
    }
    // The future response builder must safely append code/state. Until
    // then, reject query-bearing redirect registrations rather than allow
    // pre-existing code/error/state fields or ambiguous delimiters.
    if uri.query().is_some() {
        return None;
    }
    Some(uri)
}

/// Explicitly configured public HTTPS origin, never inferred from Host.
/// One dedicated root origin in this checkpoint; shared /veyl mounts
/// remain on the existing legacy adapter.
pub struct Resource {
    origin: String,
    resource: String,
}

impl Resource {
    pub fn new(origin: &str) -> Result<Self, Error> {
        let uri = https_uri(origin).ok_or(Error::InvalidRequest)?;
        let authority = uri.authority().ok_or(Error::InvalidRequest)?;
        if origin != format!("https://{authority}") {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            origin: origin.into(),
            resource: format!("{origin}/mcp"),
        })
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn protected_metadata(&self) -> Value {
        json!({
            "resource": self.resource,
            "authorization_servers": [self.origin],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"]
        })
    }

    /// Contract for the future complete HTTP adapter; never advertise
    /// these endpoints in production until every handler is implemented.
    pub fn authorization_metadata(&self) -> Value {
        json!({
            "issuer": self.origin,
            "authorization_endpoint": format!("{}/oauth/authorize", self.origin),
            "token_endpoint": format!("{}/oauth/token", self.origin),
            "registration_endpoint": format!("{}/oauth/register", self.origin),
            "scopes_supported": [SCOPE],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"]
        })
    }

    pub fn challenge(&self) -> String {
        format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"{SCOPE}\"",
            self.origin
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Mcp,
    ProtectedResource,
    AuthorizationServer,
    Register,
    Authorize,
    Token,
}

/// Exact allowlist on the raw request path. Do not use path prefix matching
/// for OAuth, and never route the local dashboard or operator actions here.
pub fn public_route(path: &str) -> Option<Route> {
    match path {
        "/mcp" => Some(Route::Mcp),
        "/.well-known/oauth-protected-resource" | "/.well-known/oauth-protected-resource/mcp" => {
            Some(Route::ProtectedResource)
        }
        "/.well-known/oauth-authorization-server" => Some(Route::AuthorizationServer),
        "/oauth/register" => Some(Route::Register),
        "/oauth/authorize" => Some(Route::Authorize),
        "/oauth/token" => Some(Route::Token),
        _ => None,
    }
}

pub struct Registration {
    client_id: String,
    client_name: String,
    redirects: Vec<String>,
    mode: ConnectionMode,
}

impl Registration {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn client_name(&self) -> &str {
        &self.client_name
    }
    pub fn redirects(&self) -> &[String] {
        &self.redirects
    }
    pub fn mode(&self) -> ConnectionMode {
        self.mode
    }

    pub fn response(&self) -> Value {
        json!({
            "client_id": self.client_id,
            "client_name": self.client_name,
            "redirect_uris": self.redirects,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": SCOPE
        })
    }
}

/// Preview of public-client DCR. No authentication or native permission
/// follows merely from registration. Adapter must impose body limits,
/// rate limiting, durable storage and local consent before exposure.
pub struct ClientRegistry {
    resource: Resource,
    clients: Vec<Registration>,
}

pub struct AuthorizationParameters<'a> {
    pub client_id: &'a str,
    pub redirect: &'a str,
    pub resource: &'a str,
    pub scope: &'a str,
    pub challenge: &'a str,
    pub method: &'a str,
    pub state: Option<&'a str>,
}

fn valid_registration(name: &str, redirects: &[&str]) -> bool {
    bounded(name, 128)
        && !name.trim().is_empty()
        && !redirects.is_empty()
        && redirects.len() <= MAX_REDIRECTS
        && redirects
            .iter()
            .enumerate()
            .all(|(index, value)| https_uri(value).is_some() && !redirects[..index].contains(value))
}

impl ClientRegistry {
    pub fn new(resource: Resource) -> Self {
        Self {
            resource,
            clients: Vec::new(),
        }
    }

    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    pub fn register(
        &mut self,
        name: &str,
        redirects: &[&str],
        token_endpoint_auth_method: &str,
        grant_types: &[&str],
        response_types: &[&str],
        scope: &str,
    ) -> Result<&Registration, Error> {
        if self.clients.len() >= MAX_CLIENTS {
            return Err(Error::Capacity);
        }
        if !valid_registration(name, redirects)
            || token_endpoint_auth_method != "none"
            || grant_types.len() != 2
            || !grant_types.contains(&"authorization_code")
            || !grant_types.contains(&"refresh_token")
            || response_types != ["code"]
            || scope != SCOPE
        {
            return Err(Error::InvalidRequest);
        }
        let client_id = random_id::<32>().map_err(|_| Error::Unavailable)?;
        if self.clients.iter().any(|c| c.client_id == client_id) {
            return Err(Error::Unavailable);
        }
        self.clients.push(Registration {
            client_id,
            client_name: name.into(),
            redirects: redirects.iter().map(|r| (*r).into()).collect(),
            mode: ConnectionMode::Standard,
        });
        Ok(self.clients.last().expect("registration inserted"))
    }

    pub fn get(&self, client_id: &str) -> Option<&Registration> {
        self.clients.iter().find(|c| c.client_id == client_id)
    }

    pub fn clients(&self) -> &[Registration] {
        &self.clients
    }

    pub fn set_mode(&mut self, client_id: &str, mode: ConnectionMode) -> Option<ConnectionMode> {
        let client = self.clients.iter_mut().find(|c| c.client_id == client_id)?;
        let prev = client.mode;
        client.mode = mode;
        Some(prev)
    }

    /// Registration-only durable snapshot. No consent handles, codes or
    /// token verifiers are included; a restart still invalidates all grants.
    pub fn snapshot(&self) -> Value {
        json!({"version":1,"resource":self.resource.resource(),"clients":
            self.clients.iter().map(|c| json!({"client_id":c.client_id,
                "client_name":c.client_name,"redirect_uris":c.redirects,
                "mode":c.mode.as_str()})).collect::<Vec<_>>()})
    }

    pub fn restore(resource: Resource, snapshot: &Value) -> Result<Self, Error> {
        if snapshot.as_object().is_none_or(|v| v.len() != 3)
            || snapshot["version"].as_u64() != Some(1)
            || snapshot["resource"].as_str() != Some(resource.resource())
        {
            return Err(Error::InvalidRequest);
        }
        let clients = snapshot["clients"]
            .as_array()
            .ok_or(Error::InvalidRequest)?;
        if clients.len() > MAX_CLIENTS {
            return Err(Error::Capacity);
        }
        let mut registry = Self::new(resource);
        for client in clients {
            let Some(obj) = client.as_object() else {
                return Err(Error::InvalidRequest);
            };
            if !obj.keys().all(|k| {
                matches!(
                    k.as_str(),
                    "client_id" | "client_name" | "redirect_uris" | "mode"
                )
            }) || !obj.contains_key("client_id")
                || !obj.contains_key("client_name")
                || !obj.contains_key("redirect_uris")
            {
                return Err(Error::InvalidRequest);
            }
            let mode = match obj.get("mode") {
                None => ConnectionMode::Standard,
                Some(raw) => raw
                    .as_str()
                    .and_then(ConnectionMode::parse)
                    .ok_or(Error::InvalidRequest)?,
            };
            let id = client["client_id"]
                .as_str()
                .filter(|v| token_shape(v))
                .ok_or(Error::InvalidRequest)?;
            let name = client["client_name"]
                .as_str()
                .ok_or(Error::InvalidRequest)?;
            let redirects: Vec<&str> = client["redirect_uris"]
                .as_array()
                .ok_or(Error::InvalidRequest)?
                .iter()
                .map(Value::as_str)
                .collect::<Option<_>>()
                .ok_or(Error::InvalidRequest)?;
            if registry.get(id).is_some() || !valid_registration(name, &redirects) {
                return Err(Error::InvalidRequest);
            }
            registry.clients.push(Registration {
                client_id: id.into(),
                client_name: name.into(),
                redirects: redirects.into_iter().map(str::to_owned).collect(),
                mode,
            });
        }
        Ok(registry)
    }

    /// Re-resolve registration at every authorization or token exchange.
    /// A validated Binding is request-local, not a durable authorization.
    pub fn binding(
        &self,
        client_id: &str,
        redirect: &str,
        resource: &str,
    ) -> Result<Binding, Error> {
        if resource != self.resource.resource()
            || !self
                .get(client_id)
                .is_some_and(|c| c.redirects.iter().any(|r| r == redirect))
        {
            return Err(Error::InvalidRequest);
        }
        Binding::new(client_id, redirect, resource)
    }

    pub fn authorization(
        &self,
        parameters: AuthorizationParameters<'_>,
    ) -> Result<AuthorizationRequest, Error> {
        if parameters.scope != SCOPE {
            return Err(Error::InvalidRequest);
        }
        AuthorizationRequest::new(
            self.binding(
                parameters.client_id,
                parameters.redirect,
                parameters.resource,
            )?,
            parameters.challenge,
            parameters.method,
            parameters.state,
        )
    }

    /// Local-only operation. Cancels pending requests, codes and active
    /// token families belonging to this OAuth registration.
    pub fn revoke_local(&mut self, client_id: &str, grants: &mut GrantStore) {
        self.clients.retain(|c| c.client_id != client_id);
        grants.revoke_oauth_client(client_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    const ORIGIN: &str = "https://node.example:8443";
    const CALLBACK: &str = "https://chat.example/callback";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn registry() -> ClientRegistry {
        ClientRegistry::new(Resource::new(ORIGIN).unwrap())
    }

    fn register(registry: &mut ClientRegistry) -> String {
        registry
            .register(
                "Chat",
                &[CALLBACK],
                "none",
                &["authorization_code", "refresh_token"],
                &["code"],
                SCOPE,
            )
            .unwrap()
            .client_id()
            .into()
    }

    #[test]
    fn metadata_uses_configured_origin_only() {
        let resource = Resource::new(ORIGIN).unwrap();
        assert_eq!(resource.resource(), format!("{ORIGIN}/mcp"));
        let metadata = resource.authorization_metadata();
        assert_eq!(metadata["issuer"], ORIGIN);
        assert_eq!(
            metadata["registration_endpoint"],
            format!("{ORIGIN}/oauth/register")
        );
        assert_eq!(
            metadata["code_challenge_methods_supported"],
            json!(["S256"])
        );
        assert_eq!(
            resource.protected_metadata()["authorization_servers"],
            json!([ORIGIN])
        );
        assert_eq!(
            resource.challenge(),
            format!(
                "Bearer resource_metadata=\"{ORIGIN}/.well-known/oauth-protected-resource/mcp\", scope=\"mcp\""
            )
        );
        for origin in [
            "http://node.example",
            "https://node.example/",
            "https://node.example/mcp",
            "https://node.example?x=1",
            "https://user@node.example",
            "https://node.example:0",
            "https://node.example:65536",
            "https://node.example:bad",
            "https://127.0.0.1",
            "https://node.example#x",
            "https://node..example",
            "https://node.example\r\nX: a",
        ] {
            assert!(Resource::new(origin).is_err(), "{origin:?}");
        }
    }

    #[test]
    fn exact_public_paths_never_include_admin_or_secret_routes() {
        for path in [
            "/mcp",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-authorization-server",
            "/oauth/register",
            "/oauth/authorize",
            "/oauth/token",
        ] {
            assert!(public_route(path).is_some(), "{path}");
        }
        for path in [
            "/",
            "/dashboard",
            "/api/dashboard/pair",
            "/oauth/approve",
            "/oauth/revoke",
            "/oauth/token/extra",
            "/oauth/../dashboard",
            "/oauth%2ftoken",
            "/mcp/",
            "/mcp/secret",
            "/veyl/mcp",
            "//mcp",
            "/.well-known/other",
            "/oauth/token?x=1",
        ] {
            assert_eq!(public_route(path), None, "{path}");
        }
    }

    #[test]
    fn registration_validates_metadata_and_exact_callback() {
        let mut registry = registry();
        let id = register(&mut registry);
        let resource = format!("{ORIGIN}/mcp");
        assert_eq!(
            registry.get(&id).unwrap().response()["token_endpoint_auth_method"],
            "none"
        );
        assert!(registry.binding(&id, CALLBACK, &resource).is_ok());
        for redirect in [
            "http://chat.example/callback",
            "https://chat.example/callback/",
            "https://chat.example.evil/callback",
            "https://chat.example/callback?x=1",
        ] {
            assert!(registry.binding(&id, redirect, &resource).is_err());
        }
        for redirect in [
            "http://chat.example/callback",
            "https://user@chat.example/callback",
            "https://chat.example/callback#fragment",
            "https://chat.example/callback?code=x",
            "https://chat.example:0/callback",
            "https://chat.example/\\evil",
            "https://localhost/callback",
        ] {
            assert!(
                registry
                    .register(
                        "Chat",
                        &[redirect],
                        "none",
                        &["authorization_code", "refresh_token"],
                        &["code"],
                        SCOPE
                    )
                    .is_err(),
                "{redirect}"
            );
        }
        assert!(registry.binding("unknown", CALLBACK, &resource).is_err());
        assert!(
            registry
                .binding(&id, CALLBACK, "https://other.example/mcp")
                .is_err()
        );
        assert!(
            registry
                .authorization(AuthorizationParameters {
                    client_id: &id,
                    redirect: CALLBACK,
                    resource: &resource,
                    scope: "full",
                    challenge: CHALLENGE,
                    method: "S256",
                    state: None
                })
                .is_err()
        );
        assert!(
            registry
                .register(
                    "Chat",
                    &[CALLBACK],
                    "client_secret_basic",
                    &["authorization_code", "refresh_token"],
                    &["code"],
                    SCOPE
                )
                .is_err()
        );
        assert!(
            registry
                .register(
                    "Chat",
                    &[CALLBACK],
                    "none",
                    &["authorization_code", "client_credentials"],
                    &["code"],
                    SCOPE
                )
                .is_err()
        );
        assert!(
            registry
                .register(
                    "Chat",
                    &[CALLBACK, CALLBACK],
                    "none",
                    &["authorization_code", "refresh_token"],
                    &["code"],
                    SCOPE
                )
                .is_err()
        );
        assert!(
            registry
                .register(
                    "Chat",
                    &[CALLBACK],
                    "none",
                    &["authorization_code", "refresh_token"],
                    &["token"],
                    SCOPE
                )
                .is_err()
        );
    }

    #[test]
    fn local_registration_revocation_invalidates_grants_and_pending() {
        let mut registry = registry();
        let a = register(&mut registry);
        let b = register(&mut registry);
        let resource = format!("{ORIGIN}/mcp");
        let now = Instant::now();
        let mut store = GrantStore::default();
        let mut issue = |id: &str| {
            let pending = store
                .begin(
                    registry
                        .authorization(AuthorizationParameters {
                            client_id: id,
                            redirect: CALLBACK,
                            resource: &resource,
                            scope: SCOPE,
                            challenge: CHALLENGE,
                            method: "S256",
                            state: None,
                        })
                        .unwrap(),
                    now,
                )
                .unwrap();
            let code = store.approve_local(&pending, "native-client", now).unwrap();
            store
                .exchange(
                    &code.code,
                    &registry.binding(id, CALLBACK, &resource).unwrap(),
                    VERIFIER,
                    now,
                )
                .unwrap()
        };
        let at = issue(&a);
        let bt = issue(&b);
        let pending = store
            .begin(
                registry
                    .authorization(AuthorizationParameters {
                        client_id: &a,
                        redirect: CALLBACK,
                        resource: &resource,
                        scope: SCOPE,
                        challenge: CHALLENGE,
                        method: "S256",
                        state: None,
                    })
                    .unwrap(),
                now,
            )
            .unwrap();
        registry.revoke_local(&a, &mut store);
        assert!(registry.get(&a).is_none());
        assert!(store.approve_local(&pending, "native-client", now).is_err());
        assert!(
            store
                .authenticate(&at.access_token, &resource, now)
                .is_none()
        );
        assert!(
            store
                .refresh(&at.refresh_token, &a, &resource, now)
                .is_err()
        );
        assert_eq!(
            store
                .authenticate(&bt.access_token, &resource, now)
                .unwrap()
                .oauth_client,
            b
        );
    }

    #[test]
    fn registration_budget_is_bounded() {
        let mut registry = registry();
        for _ in 0..MAX_CLIENTS {
            register(&mut registry);
        }
        assert!(matches!(
            registry.register(
                "Chat",
                &[CALLBACK],
                "none",
                &["authorization_code", "refresh_token"],
                &["code"],
                SCOPE
            ),
            Err(Error::Capacity)
        ));
    }
}
