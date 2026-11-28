//! Shared loopback OAuth HTTP preview. No public tunnel activation.
mod durable;
use crate::platform::private_store::Store;
use crate::{
    core::{
        credential::token_digest,
        oauth::{ApprovedCode, AuthorizationRequest, ConnectionMode, Error, GrantStore, Tokens},
    },
    http_common::{
        bearer_text,
        oauth::{AuthorizationParameters, ClientRegistry, Resource, Route, SCOPE, public_route},
        one,
    },
};
use bytes::Bytes;
use durable::{Durable, Transition};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Incoming},
    header,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::de::{self, MapAccess, Visitor};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    fmt,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Semaphore};

pub use durable::{
    active_family_guard, active_family_guard_with_mode, verify_active_family,
    verify_active_family_with_mode,
};

type Reply = Response<Full<Bytes>>;
type Fields = BTreeMap<String, String>;
const BODY_LIMIT: usize = 16_384;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const DELIVERY_TTL: Duration = Duration::from_secs(60);

/// An authenticated OAuth grant family, not native execution authority.
#[derive(Clone)]
pub struct Identity {
    pub local_client: String,
    pub oauth_client: String,
    pub family: [u8; 32],
    pub mode: ConnectionMode,
    pub expires_at: u64,
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.local_client == other.local_client
            && self.oauth_client == other.oauth_client
            && self.family == other.family
    }
}

impl Eq for Identity {}

fn identity(state: &State, bearer: Option<&str>) -> Option<Identity> {
    if state.failed {
        return None;
    }
    let raw = bearer?.strip_prefix("Bearer ")?;
    let id =
        state
            .grants
            .authenticate(raw, state.registry.resource().resource(), Instant::now())?;
    let registration = state.registry.get(id.oauth_client)?;
    if id.local_client != state.local_client {
        return None;
    }
    let mode = if registration.mode() == ConnectionMode::Yolo && id.mode == ConnectionMode::Yolo {
        ConnectionMode::Yolo
    } else {
        ConnectionMode::Standard
    };
    let expires_at = (SystemTime::now() + id.access_remaining)
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(Identity {
        local_client: id.local_client.into(),
        oauth_client: id.oauth_client.into(),
        family: id.family,
        mode,
        expires_at,
    })
}

fn unauthorized(state: &State) -> Reply {
    let mut response = error(StatusCode::UNAUTHORIZED, "invalid_token");
    if let Ok(challenge) = header::HeaderValue::from_str(&state.registry.resource().challenge()) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
    }
    response
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressKind {
    Direct,
    TailscaleFunnel,
    CloudflareTunnel,
}

#[derive(Clone)]
pub struct Server {
    shared: Arc<Shared>,
    authority: String,
    local_client: String,
    operator_digest: [u8; 32],
    ingress: IngressKind,
}

// Separate bounded slots for public and operator work. A timed-out HTTP
// future cannot release a slot while its blocking transaction still runs.
// This preserves serialization and commit-before-response without blocking
// the async runtime on disk or on the state mutex.
struct Shared {
    state: Mutex<State>,
    public: Arc<Semaphore>,
    admin: Arc<Semaphore>,
}

impl Shared {
    fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, State>> {
        self.state.lock()
    }
    async fn blocking<T: Send + 'static>(
        &self,
        admin: bool,
        run: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Error> {
        let slots = if admin { &self.admin } else { &self.public };
        let permit = slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Capacity)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            run()
        })
        .await
        .map_err(|_| Error::Unavailable)
    }
    async fn work<T: Send + 'static>(
        self: &Arc<Self>,
        admin: bool,
        run: impl FnOnce(&mut State) -> T + Send + 'static,
    ) -> Result<T, Error> {
        let shared = self.clone();
        self.blocking(admin, move || {
            let mut state = shared.lock().map_err(|_| Error::Unavailable)?;
            if !state.clock_valid() {
                return Err(Error::Unavailable);
            }
            Ok(run(&mut state))
        })
        .await?
    }
}

impl Server {
    /// Only the isolated native foreground provider may select this
    /// ingress shape. Proxy metadata never supplies authentication.
    pub fn with_funnel_ingress(mut self) -> Self {
        self.ingress = IngressKind::TailscaleFunnel;
        self
    }

    pub fn with_cloudflare_ingress(mut self) -> Self {
        self.ingress = IngressKind::CloudflareTunnel;
        self
    }
    /// Run native policy/admission work off the HTTP runtime, using the
    /// same bounded worker slots as OAuth requests. The caller must not
    /// hold the OAuth state mutex when calling this.
    pub async fn admission_work<T: Send + 'static>(
        &self,
        admin: bool,
        run: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Error> {
        self.shared.blocking(admin, run).await
    }
    /// Called only by the authenticated local dashboard adapter, after
    /// its own session and CSRF checks. Never wire to the public listener.
    pub fn local_consent(&self, body: &[u8], eligible: bool, native_scope: Value) -> Reply {
        self.local_consent_with_default(body, eligible, native_scope, None, ConnectionMode::Standard)
    }

    /// Local consent with optional Broad YOLO scope when explicitly supported
    /// by the isolated gateway runtime. Never wire to the public listener.
    pub fn local_consent_with_modes(
        &self,
        body: &[u8],
        eligible: bool,
        native_scope: Value,
        yolo_scope: Option<Value>,
    ) -> Reply {
        self.local_consent_with_default(
            body,
            eligible,
            native_scope,
            yolo_scope,
            ConnectionMode::Standard,
        )
    }

    /// Local consent with an explicit configured default mode for initial
    /// unapproved DCR consent preselection. Never wire to the public listener.
    pub fn local_consent_with_default(
        &self,
        body: &[u8],
        eligible: bool,
        native_scope: Value,
        yolo_scope: Option<Value>,
        default_mode: ConnectionMode,
    ) -> Reply {
        let Ok(mut state) = self.shared.lock() else {
            return oauth_error(Error::Unavailable);
        };
        if !state.clock_valid() {
            return oauth_error(Error::Unavailable);
        }
        if !state.admin_budget.take(30) {
            return oauth_error(Error::Capacity);
        }
        consent(
            &mut state,
            body,
            eligible,
            native_scope,
            yolo_scope.as_ref(),
            default_mode,
        )
    }
    pub fn local_client(&self) -> &str {
        &self.local_client
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn authenticate(&self, bearer: Option<&str>) -> Option<Identity> {
        let mut state = self.shared.lock().ok()?;
        if !state.clock_valid() {
            return None;
        }
        identity(&state, bearer)
    }

    pub fn operator_matches(&self, verifier: &[u8; 32]) -> bool {
        bool::from(verifier.ct_eq(&self.operator_digest))
    }

    pub async fn handle<F, Fut>(
        &self,
        request: Request<Incoming>,
        admin_authority: Option<&str>,
        native: F,
    ) -> Reply
    where
        F: FnOnce(Request<Incoming>) -> Fut,
        Fut: std::future::Future<Output = Reply>,
    {
        handle(
            request,
            self.shared.clone(),
            admin_authority.unwrap_or(&self.authority),
            admin_authority.is_some(),
            if admin_authority.is_some() {
                IngressKind::Direct
            } else {
                self.ingress
            },
            native,
        )
        .await
    }
}

struct Budget {
    until: Instant,
    count: usize,
}
impl Budget {
    fn new() -> Self {
        Self {
            until: Instant::now(),
            count: 0,
        }
    }
    fn take(&mut self, limit: usize) -> bool {
        let now = Instant::now();
        if now >= self.until {
            self.until = now + Duration::from_secs(10);
            self.count = 0;
        }
        if self.count >= limit {
            return false;
        }
        self.count += 1;
        true
    }
}
enum Decision {
    Approved(ApprovedCode),
    Denied(AuthorizationRequest),
}
impl Decision {
    fn client_id(&self) -> &str {
        match self {
            Self::Approved(code) => code.binding.client_id(),
            Self::Denied(request) => request.binding().client_id(),
        }
    }
    fn callback(self) -> Reply {
        match self {
            Self::Approved(code) => callback(
                code.binding.redirect_uri(),
                code.state.as_deref(),
                Some(&code.code),
            ),
            Self::Denied(request) => {
                callback(request.binding().redirect_uri(), request.state(), None)
            }
        }
    }
}
struct Delivery {
    decision: Decision,
    until: Instant,
}
struct State {
    registry: ClientRegistry,
    grants: GrantStore,
    deliveries: BTreeMap<[u8; 32], Delivery>,
    operator: [u8; 32],
    local_client: String,
    public_budget: Budget,
    admin_budget: Budget,
    persistence: Option<(Store, Value)>,
    durable: Option<Durable>,
    failed: bool,
}
impl State {
    fn clock_valid(&mut self) -> bool {
        if self.failed {
            return false;
        }
        if self
            .durable
            .as_ref()
            .is_some_and(|d| d.clock(Instant::now()).is_err())
        {
            self.fail_storage();
            return false;
        }
        true
    }

    fn transaction(
        &mut self,
        operation: &str,
        client: Option<String>,
        run: impl FnOnce(&mut Self, Instant) -> Reply,
    ) -> Reply {
        let now = Instant::now();
        let Some(durable) = self.durable.as_mut() else {
            return run(self, now);
        };
        let Ok(epoch) = durable.begin(operation, now) else {
            self.fail_storage();
            return oauth_error(Error::Unavailable);
        };
        let response = run(self, now);
        let transition = Transition {
            operation,
            status: response.status().as_u16(),
            client,
            now,
            epoch,
        };
        let result = self.durable.as_mut().expect("transaction state").finish(
            transition,
            &self.registry,
            &self.grants,
        );
        if result.is_err() {
            self.fail_storage();
            return oauth_error(Error::Unavailable);
        }
        response
    }
    fn prune_deliveries(&mut self, now: Instant) {
        self.deliveries.retain(|_, v| now < v.until);
    }

    fn fail_storage(&mut self) {
        self.failed = true;
        self.grants = GrantStore::default();
        self.deliveries.clear();
        audit("storage_failed");
    }

    fn persist(&mut self) -> Result<(), Error> {
        let Some((store, previous)) = &mut self.persistence else {
            return Ok(());
        };
        let snapshot = self.registry.snapshot();
        let result = (|| -> Result<(), String> {
            if store.read()? != *previous {
                return Err("Registry changed outside preview".into());
            }
            store.write(&snapshot, false)?;
            if store.read()? != snapshot {
                return Err("Registry verification failed".into());
            }
            Ok(())
        })();
        if result.is_err() {
            self.fail_storage();
            return Err(Error::Unavailable);
        }
        *previous = snapshot;
        Ok(())
    }
}

fn reply(status: StatusCode, content_type: &'static str, body: impl Into<Bytes>) -> Reply {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    headers.insert("pragma", header::HeaderValue::from_static("no-cache"));
    headers.insert(
        "referrer-policy",
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "x-content-type-options",
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "content-security-policy",
        header::HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );
    response
}
fn json_reply(status: StatusCode, value: Value) -> Reply {
    reply(status, "application/json", value.to_string())
}
fn error(status: StatusCode, name: &'static str) -> Reply {
    json_reply(status, json!({"error":name}))
}
fn oauth_error(e: Error) -> Reply {
    match e {
        Error::InvalidRequest => error(StatusCode::BAD_REQUEST, "invalid_request"),
        Error::InvalidGrant => error(StatusCode::BAD_REQUEST, "invalid_grant"),
        Error::Capacity => error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable"),
        Error::Unavailable => error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    }
}
fn tokens(t: Tokens) -> Reply {
    json_reply(
        StatusCode::OK,
        json!({"access_token":t.access_token,"token_type":"Bearer",
        "refresh_token":t.refresh_token,"expires_in":t.expires_in,"scope":SCOPE}),
    )
}
fn audit(event: &'static str) {
    // Preview diagnostics only. Never log raw inputs, redirect, handle, or token.
    eprintln!("OAUTH_PREVIEW_EVENT={event}");
}

fn decode_component(raw: &str) -> Option<String> {
    let mut out = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(c) = bytes.next() {
        match c {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = (bytes.next()? as char).to_digit(16)?;
                let lo = (bytes.next()? as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
            }
            c => out.push(c),
        }
    }
    let decoded = String::from_utf8(out).ok()?;
    (!decoded.chars().any(char::is_control)).then_some(decoded)
}
fn form(raw: &[u8]) -> Option<Fields> {
    if raw.len() > BODY_LIMIT {
        return None;
    }
    let raw = std::str::from_utf8(raw).ok()?;
    let mut values = Fields::new();
    for pair in raw.split('&') {
        let (k, v) = pair.split_once('=')?;
        let key = decode_component(k)?;
        let value = decode_component(v)?;
        if key.is_empty() || values.len() >= 16 || values.insert(key, value).is_some() {
            return None;
        }
    }
    Some(values)
}
fn field<'a>(fields: &'a Fields, name: &str) -> Option<&'a str> {
    fields.get(name).map(String::as_str)
}
fn allowed(fields: &Fields, names: &[&str]) -> bool {
    fields.keys().all(|key| names.contains(&key.as_str()))
}
fn encode(value: &str) -> String {
    use std::fmt::Write;
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            result.push(byte as char);
        } else {
            let _ = write!(result, "%{byte:02X}");
        }
    }
    result
}
fn callback(redirect: &str, state: Option<&str>, code: Option<&str>) -> Reply {
    let mut location = match code {
        Some(code) => format!("{redirect}?code={}", encode(code)),
        None => format!("{redirect}?error=access_denied"),
    };
    if let Some(state) = state {
        location.push_str("&state=");
        location.push_str(&encode(state));
    }
    let Ok(location) = header::HeaderValue::from_str(&location) else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let mut response = reply(
        StatusCode::SEE_OTHER,
        "text/plain; charset=utf-8",
        "Authorization complete.",
    );
    response.headers_mut().insert(header::LOCATION, location);
    response
}
fn waiting(handle: &str) -> Reply {
    // Only validated, generated lowercase hex enters HTML. No script,
    // external assets, redirect supplied by the client, or admin action.
    reply(
        StatusCode::OK,
        "text/html; charset=utf-8",
        format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Veyl authorization preview</title><h1>Local approval required</h1><p>Inspect and approve this request on the machine running Veyl. This page cannot grant access.</p><code id=\"request\">{handle}</code><p><a href=\"/oauth/authorize?request={handle}\">Check approval</a></p></html>"
        ),
    )
}

// Registration and operator requests are flat objects. Reject repeated
// decoded JSON property names; nested arbitrary objects are never accepted.
struct StrictObject(BTreeMap<String, Value>);
impl<'de> serde::Deserialize<'de> for StrictObject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = StrictObject;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a unique-key JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if values.len() >= 16 || values.insert(key, value).is_some() {
                        return Err(de::Error::custom("invalid object"));
                    }
                }
                Ok(StrictObject(values))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}
fn object(body: &[u8]) -> Option<BTreeMap<String, Value>> {
    serde_json::from_slice::<StrictObject>(body)
        .ok()
        .map(|o| o.0)
}

/// CLI input uses the same strict flat JSON parser as the local consent API.
pub fn consent_input(action: &str, body: &[u8]) -> Result<Value, Error> {
    if !matches!(
        action,
        "list" | "inspect" | "approve" | "deny" | "revoke" | "mode"
    ) || body.len() > 8192
    {
        return Err(Error::InvalidRequest);
    }
    let mut fields = object(body).ok_or(Error::InvalidRequest)?;
    if fields.insert("action".into(), json!(action)).is_some() {
        return Err(Error::InvalidRequest);
    }
    Ok(json!(fields))
}
fn strings<'a>(values: &'a BTreeMap<String, Value>, key: &str) -> Option<Vec<&'a str>> {
    values
        .get(key)?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect()
}
fn register(state: &mut State, body: &[u8]) -> Reply {
    let Some(values) = object(body) else {
        return error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    };
    if !values.keys().all(|k| {
        [
            "client_name",
            "redirect_uris",
            "token_endpoint_auth_method",
            "grant_types",
            "response_types",
            "scope",
        ]
        .contains(&k.as_str())
    }) {
        return error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }
    let (Some(redirects), Some(grants), Some(responses), Some(auth)) = (
        strings(&values, "redirect_uris"),
        strings(&values, "grant_types"),
        strings(&values, "response_types"),
        values
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str),
    ) else {
        return error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    };
    let name = match values.get("client_name") {
        Some(v) => v.as_str(),
        None => Some("Unnamed client"),
    };
    let scope = match values.get("scope") {
        Some(v) => v.as_str(),
        None => Some(SCOPE),
    };
    let (Some(name), Some(scope)) = (name, scope) else {
        return error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    };
    match state
        .registry
        .register(name, &redirects, auth, &grants, &responses, scope)
    {
        Ok(registration) => {
            let response = registration.response();
            if let Err(e) = state.persist() {
                return oauth_error(e);
            }
            audit("registration");
            json_reply(StatusCode::CREATED, response)
        }
        Err(Error::InvalidRequest) => error(StatusCode::BAD_REQUEST, "invalid_client_metadata"),
        Err(e) => oauth_error(e),
    }
}

fn authorize(state: &mut State, query: &str, now: Instant) -> Reply {
    let Some(fields) = form(query.as_bytes()) else {
        return oauth_error(Error::InvalidRequest);
    };
    state.prune_deliveries(now);
    if fields.len() == 1
        && let Some(handle) = field(&fields, "request")
    {
        let Some(digest) = token_digest(handle) else {
            return oauth_error(Error::InvalidRequest);
        };
        if let Some(delivery) = state.deliveries.remove(&digest) {
            return delivery.decision.callback();
        }
        return if state.grants.pending(handle, now).is_ok() {
            waiting(handle)
        } else {
            error(StatusCode::BAD_REQUEST, "invalid_or_expired_request")
        };
    }
    if !allowed(
        &fields,
        &[
            "response_type",
            "client_id",
            "redirect_uri",
            "resource",
            "scope",
            "code_challenge",
            "code_challenge_method",
            "state",
        ],
    ) || field(&fields, "response_type") != Some("code")
    {
        return oauth_error(Error::InvalidRequest);
    }
    let (Some(client_id), Some(redirect), Some(resource), Some(challenge), Some(method)) = (
        field(&fields, "client_id"),
        field(&fields, "redirect_uri"),
        field(&fields, "resource"),
        field(&fields, "code_challenge"),
        field(&fields, "code_challenge_method"),
    ) else {
        return oauth_error(Error::InvalidRequest);
    };
    let request = state.registry.authorization(AuthorizationParameters {
        client_id,
        redirect,
        resource,
        scope: field(&fields, "scope").unwrap_or(SCOPE),
        challenge,
        method,
        state: field(&fields, "state"),
    });
    match request.and_then(|r| state.grants.begin(r, now)) {
        Ok(handle) => {
            audit("pending");
            waiting(&handle)
        }
        Err(e) => oauth_error(e),
    }
}

fn token(state: &mut State, body: &[u8], now: Instant) -> Reply {
    let Some(fields) = form(body) else {
        return oauth_error(Error::InvalidRequest);
    };
    let (Some(client), Some(resource)) = (field(&fields, "client_id"), field(&fields, "resource"))
    else {
        return oauth_error(Error::InvalidRequest);
    };
    if state.registry.get(client).is_none() || resource != state.registry.resource().resource() {
        return oauth_error(Error::InvalidGrant);
    }
    let result = match field(&fields, "grant_type") {
        Some("authorization_code")
            if allowed(
                &fields,
                &[
                    "grant_type",
                    "client_id",
                    "resource",
                    "code",
                    "redirect_uri",
                    "code_verifier",
                ],
            ) =>
        {
            let (Some(code), Some(redirect), Some(verifier)) = (
                field(&fields, "code"),
                field(&fields, "redirect_uri"),
                field(&fields, "code_verifier"),
            ) else {
                return oauth_error(Error::InvalidRequest);
            };
            state
                .registry
                .binding(client, redirect, resource)
                .map_err(|_| Error::InvalidGrant)
                .and_then(|binding| state.grants.exchange(code, &binding, verifier, now))
        }
        Some("refresh_token")
            if allowed(
                &fields,
                &[
                    "grant_type",
                    "client_id",
                    "resource",
                    "refresh_token",
                    "scope",
                ],
            ) =>
        {
            if field(&fields, "scope").is_some_and(|scope| scope != SCOPE) {
                return oauth_error(Error::InvalidRequest);
            }
            let Some(refresh) = field(&fields, "refresh_token") else {
                return oauth_error(Error::InvalidRequest);
            };
            state.grants.refresh(refresh, client, resource, now)
        }
        _ => return error(StatusCode::BAD_REQUEST, "unsupported_or_invalid_grant_type"),
    };
    match result {
        Ok(t) => {
            audit("token_issued");
            tokens(t)
        }
        Err(e) => {
            audit("token_denied");
            oauth_error(e)
        }
    }
}

fn scope_digest(scope: &Value) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(scope.to_string().as_bytes()))
}

// The new operator surface requires an exact reviewed binding. Legacy
// fixture-only /approve etc. remain for existing isolated regression tests.
fn consent(
    state: &mut State,
    body: &[u8],
    eligible: bool,
    native_scope: Value,
    yolo_scope: Option<&Value>,
    default_mode: ConnectionMode,
) -> Reply {
    let supports_yolo = yolo_scope.is_some();
    let Some(values) = object(body) else {
        return oauth_error(Error::InvalidRequest);
    };
    let Some(action) = values.get("action").and_then(Value::as_str) else {
        return oauth_error(Error::InvalidRequest);
    };
    let now = Instant::now();
    if action == "list" && values.len() == 1 {
        let registrations: Vec<Value> = state
            .registry
            .clients()
            .iter()
            .map(|client| {
                let modes = state.grants.client_family_modes(client.client_id(), now);
                let active_families = modes.len();
                let active_yolo_families = modes
                    .iter()
                    .filter(|mode| **mode == ConnectionMode::Yolo)
                    .count();
                json!({
                    "client_id": client.client_id(),
                    "client_name": client.client_name(),
                    "redirect_uris": client.redirects(),
                    "mode": client.mode().as_str(),
                    "active_families": active_families,
                    "active_yolo_families": active_yolo_families,
                })
            })
            .collect();
        return json_reply(
            StatusCode::OK,
            json!({
                "local_client": state.local_client,
                "eligible": eligible,
                "supports_yolo": supports_yolo,
                "default_mode": default_mode.as_str(),
                "registrations": registrations,
            }),
        );
    }
    if action == "mode_all"
        && values.len() == 3
        && values.get("confirm") == Some(&json!(true))
        && values
            .keys()
            .all(|k| matches!(k.as_str(), "action" | "mode" | "confirm"))
    {
        let Some(target_mode) = values
            .get("mode")
            .and_then(Value::as_str)
            .and_then(ConnectionMode::parse)
        else {
            return oauth_error(Error::InvalidRequest);
        };
        if target_mode == ConnectionMode::Yolo && (!supports_yolo || !eligible) {
            return error(StatusCode::FORBIDDEN, "yolo_authorization_unavailable");
        }
        return state.transaction("mode", None, |s, _now| {
            let previous = s.registry.set_all_modes(target_mode);
            let mut results = Vec::with_capacity(previous.len());
            for (client, prev) in previous {
                let mut reauth_required = false;
                match target_mode {
                    ConnectionMode::Yolo => {
                        if prev != ConnectionMode::Yolo {
                            s.grants.revoke_oauth_client(&client);
                            s.deliveries.retain(|_, v| v.decision.client_id() != client);
                            reauth_required = true;
                        }
                    }
                    ConnectionMode::Standard => {
                        s.grants.downgrade_oauth_client(&client);
                    }
                }
                results.push(json!({
                    "client_id": client,
                    "previous_mode": prev.as_str(),
                    "mode": target_mode.as_str(),
                    "reauthorization_required": reauth_required,
                }));
            }
            if let Err(e) = s.persist() {
                return oauth_error(e);
            }
            audit(if target_mode == ConnectionMode::Yolo {
                "mode_yolo"
            } else {
                "mode_standard"
            });
            json_reply(
                StatusCode::OK,
                json!({
                    "ok": true,
                    "mode": target_mode.as_str(),
                    "updated": results,
                }),
            )
        });
    }
    if action == "mode"
        && values.len() == 4
        && values.get("confirm") == Some(&json!(true))
        && values
            .keys()
            .all(|k| matches!(k.as_str(), "action" | "client_id" | "mode" | "confirm"))
    {
        let Some(client) = values
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|id| state.registry.get(id).is_some())
            .map(str::to_owned)
        else {
            return error(StatusCode::NOT_FOUND, "unknown_client");
        };
        let Some(target_mode) = values
            .get("mode")
            .and_then(Value::as_str)
            .and_then(ConnectionMode::parse)
        else {
            return oauth_error(Error::InvalidRequest);
        };
        if target_mode == ConnectionMode::Yolo && (!supports_yolo || !eligible) {
            return error(StatusCode::FORBIDDEN, "yolo_authorization_unavailable");
        }
        return state.transaction("mode", Some(client.clone()), |s, _now| {
            let Some(previous) = s.registry.set_mode(&client, target_mode) else {
                return oauth_error(Error::InvalidRequest);
            };
            let mut reauth_required = false;
            match target_mode {
                ConnectionMode::Yolo => {
                    if previous != ConnectionMode::Yolo {
                        s.grants.revoke_oauth_client(&client);
                        s.deliveries.retain(|_, v| v.decision.client_id() != client);
                        reauth_required = true;
                    }
                }
                ConnectionMode::Standard => {
                    s.grants.downgrade_oauth_client(&client);
                }
            }
            if let Err(e) = s.persist() {
                return oauth_error(e);
            }
            audit(if target_mode == ConnectionMode::Yolo {
                "mode_yolo"
            } else {
                "mode_standard"
            });
            json_reply(
                StatusCode::OK,
                json!({
                    "ok": true,
                    "client_id": client,
                    "previous_mode": previous.as_str(),
                    "mode": target_mode.as_str(),
                    "reauthorization_required": reauth_required,
                    "downgraded_active_grants": target_mode == ConnectionMode::Standard,
                }),
            )
        });
    }
    if action == "revoke" && values.len() == 3 && values.get("confirm") == Some(&json!(true)) {
        let Some(client) = values
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|id| state.registry.get(id).is_some())
            .map(str::to_owned)
        else {
            return oauth_error(Error::InvalidRequest);
        };
        let args = json!({"client_id":client}).to_string();
        return state.transaction("revoke", Some(client), |s, t| {
            operator(s, "/revoke", args.as_bytes(), t)
        });
    }
    let Some(handle) = values.get("request").and_then(Value::as_str) else {
        return oauth_error(Error::InvalidRequest);
    };
    let Ok(pending) = state.grants.pending(handle, now) else {
        return oauth_error(Error::InvalidGrant);
    };
    let binding = pending.binding();
    let Some(registration) = state.registry.get(binding.client_id()) else {
        return oauth_error(Error::InvalidGrant);
    };
    if action == "inspect"
        && (values.len() == 2 || (values.len() == 3 && values.contains_key("mode")))
    {
        let selected_mode = match values.get("mode") {
            None => {
                if supports_yolo && eligible {
                    if registration.has_explicit_mode() {
                        registration.mode()
                    } else {
                        default_mode
                    }
                } else {
                    ConnectionMode::Standard
                }
            }
            Some(raw) => match raw.as_str().and_then(ConnectionMode::parse) {
                Some(m) => m,
                None => return oauth_error(Error::InvalidRequest),
            },
        };
        let effective_scope = match selected_mode {
            ConnectionMode::Standard => &native_scope,
            ConnectionMode::Yolo => match yolo_scope {
                Some(scope) if eligible => scope,
                _ => return error(StatusCode::FORBIDDEN, "yolo_authorization_unavailable"),
            },
        };
        let scope_fingerprint = scope_digest(effective_scope);
        return json_reply(
            StatusCode::OK,
            json!({
                "client_id": binding.client_id(),
                "unverified_client_name": registration.client_name(),
                "redirect_uri": binding.redirect_uri(),
                "resource": binding.resource(),
                "local_client": state.local_client,
                "scope": SCOPE,
                "mode": selected_mode.as_str(),
                "default_mode": default_mode.as_str(),
                "registered_mode": registration.mode().as_str(),
                "supports_yolo": supports_yolo,
                "eligible": eligible,
                "native_scope": effective_scope,
                "scope_fingerprint": scope_fingerprint,
            }),
        );
    }
    if !matches!(action, "approve" | "deny")
        || !values.keys().all(|k| {
            matches!(
                k.as_str(),
                "action"
                    | "request"
                    | "confirm"
                    | "client_id"
                    | "redirect_uri"
                    | "resource"
                    | "local_client"
                    | "scope_fingerprint"
                    | "mode"
            )
        })
        || values.get("confirm") != Some(&json!(true))
        || values.get("client_id").and_then(Value::as_str) != Some(binding.client_id())
        || values.get("redirect_uri").and_then(Value::as_str) != Some(binding.redirect_uri())
        || values.get("resource").and_then(Value::as_str) != Some(binding.resource())
        || values.get("local_client").and_then(Value::as_str) != Some(state.local_client.as_str())
    {
        return oauth_error(Error::InvalidRequest);
    }
    let selected_mode = match values.get("mode") {
        None => ConnectionMode::Standard,
        Some(raw) => {
            if action != "approve" {
                return oauth_error(Error::InvalidRequest);
            }
            match raw.as_str().and_then(ConnectionMode::parse) {
                Some(m) => m,
                None => return oauth_error(Error::InvalidRequest),
            }
        }
    };
    if action == "approve" && selected_mode == ConnectionMode::Yolo && !supports_yolo {
        return error(StatusCode::FORBIDDEN, "yolo_authorization_unavailable");
    }
    if action == "approve" && !eligible {
        return error(StatusCode::FORBIDDEN, "native_authorization_unavailable");
    }
    let effective_scope = match selected_mode {
        ConnectionMode::Standard => &native_scope,
        ConnectionMode::Yolo => match yolo_scope {
            Some(scope) => scope,
            None => return error(StatusCode::FORBIDDEN, "yolo_authorization_unavailable"),
        },
    };
    let scope_fingerprint = scope_digest(effective_scope);
    if action == "approve"
        && (selected_mode == ConnectionMode::Yolo
            || effective_scope["workspace_edit"] == true
            || effective_scope["workspace_jobs"] == true
            || effective_scope["workspace_interactive"] == true
            || effective_scope["workspace_upstreams"] == true
            || values.contains_key("scope_fingerprint"))
        && values.get("scope_fingerprint").and_then(Value::as_str)
            != Some(scope_fingerprint.as_str())
    {
        return oauth_error(Error::InvalidRequest);
    }
    let client = binding.client_id().to_owned();
    let (path, args) = if action == "approve" {
        (
            "/approve",
            json!({"request": handle, "local_client": state.local_client, "mode": selected_mode.as_str()}),
        )
    } else {
        ("/deny", json!({"request":handle}))
    };
    let args = args.to_string();
    state.transaction(action, Some(client), |s, t| {
        operator(s, path, args.as_bytes(), t)
    })
}

fn operator(state: &mut State, path: &str, body: &[u8], now: Instant) -> Reply {
    let Some(values) = object(body) else {
        return oauth_error(Error::InvalidRequest);
    };
    state.prune_deliveries(now);
    if path == "/revoke" {
        let Some(client) = values.get("client_id").and_then(Value::as_str) else {
            return oauth_error(Error::InvalidRequest);
        };
        if values.len() != 1 || state.registry.get(client).is_none() {
            return oauth_error(Error::InvalidRequest);
        }
        state.registry.revoke_local(client, &mut state.grants);
        state
            .deliveries
            .retain(|_, v| v.decision.client_id() != client);
        if let Err(e) = state.persist() {
            return oauth_error(e);
        }
        audit("revoked");
        return json_reply(StatusCode::OK, json!({"revoked":true}));
    }
    let Some(handle) = values.get("request").and_then(Value::as_str) else {
        return oauth_error(Error::InvalidRequest);
    };
    let Some(digest) = token_digest(handle) else {
        return oauth_error(Error::InvalidRequest);
    };
    match path {
        "/inspect" if values.len() == 1 => {
            let Ok(pending) = state.grants.pending(handle, now) else {
                return oauth_error(Error::InvalidGrant);
            };
            let b = pending.binding();
            let Some(c) = state.registry.get(b.client_id()) else {
                return oauth_error(Error::InvalidGrant);
            };
            json_reply(
                StatusCode::OK,
                json!({"client_id":b.client_id(),"unverified_client_name":c.client_name(),
                "redirect_uri":b.redirect_uri(),"resource":b.resource(),"local_fixture_client":state.local_client}),
            )
        }
        "/approve"
            if (values.len() == 2 || (values.len() == 3 && values.contains_key("mode")))
                && values.get("local_client").and_then(Value::as_str)
                    == Some(state.local_client.as_str()) =>
        {
            if state.deliveries.contains_key(&digest) {
                return oauth_error(Error::InvalidGrant);
            }
            if state.deliveries.len() >= 128 {
                return oauth_error(Error::Capacity);
            }
            let approved_mode = match values.get("mode") {
                None => ConnectionMode::Standard,
                Some(raw) => match raw.as_str().and_then(ConnectionMode::parse) {
                    Some(m) => m,
                    None => return oauth_error(Error::InvalidRequest),
                },
            };
            let Ok(pending) = state.grants.pending(handle, now) else {
                return oauth_error(Error::InvalidGrant);
            };
            let oauth_client_id = pending.binding().client_id().to_owned();
            if state.registry.get(&oauth_client_id).is_none() {
                return oauth_error(Error::InvalidGrant);
            }
            match state.grants.approve_local_with_mode(
                handle,
                &state.local_client,
                approved_mode,
                now,
            ) {
                Ok(code) => {
                    state.registry.set_mode(&oauth_client_id, approved_mode);
                    if approved_mode == ConnectionMode::Standard {
                        state.grants.downgrade_oauth_client(&oauth_client_id);
                    }
                    if let Err(e) = state.persist() {
                        return oauth_error(e);
                    }
                    state.deliveries.insert(
                        digest,
                        Delivery {
                            decision: Decision::Approved(code),
                            until: now + DELIVERY_TTL,
                        },
                    );
                    audit("approved");
                    json_reply(
                        StatusCode::OK,
                        json!({"approved":true,"mode":approved_mode.as_str()}),
                    )
                }
                Err(e) => oauth_error(e),
            }
        }
        "/deny" if values.len() == 1 => {
            if state.deliveries.contains_key(&digest) {
                return oauth_error(Error::InvalidGrant);
            }
            if state.deliveries.len() >= 128 {
                return oauth_error(Error::Capacity);
            }
            match state.grants.deny_local(handle, now) {
                Ok(request) => {
                    state.deliveries.insert(
                        digest,
                        Delivery {
                            decision: Decision::Denied(request),
                            until: now + DELIVERY_TTL,
                        },
                    );
                    audit("denied");
                    json_reply(StatusCode::OK, json!({"denied":true}))
                }
                Err(e) => oauth_error(e),
            }
        }
        _ => oauth_error(Error::InvalidRequest),
    }
}

async fn handle<F, Fut>(
    req: Request<Incoming>,
    shared: Arc<Shared>,
    authority: &str,
    admin: bool,
    ingress: IngressKind,
    native: F,
) -> Reply
where
    F: FnOnce(Request<Incoming>) -> Fut,
    Fut: std::future::Future<Output = Reply>,
{
    let headers = req.headers();
    // A dedicated Funnel/Tunnel backend accepts the known proxy envelope but
    // never uses source IP or tunnel identity as execution authority.
    let forwarding = match ingress {
        IngressKind::TailscaleFunnel => {
            // A browser inside the tailnet may resolve this same HTTPS name
            // privately. Neither kind of proxy envelope authenticates a user.
            let marked = headers.contains_key("tailscale-funnel-request");
            (!marked || one(headers, "tailscale-funnel-request") == Some("?1"))
                && one(headers, "x-forwarded-host") == Some(authority)
                && one(headers, "x-forwarded-proto") == Some("https")
                && one(headers, "x-forwarded-for")
                    .is_some_and(|v| v.parse::<std::net::IpAddr>().is_ok())
                && !headers.contains_key("forwarded")
                && ![
                    "tailscale-user-login",
                    "tailscale-user-name",
                    "tailscale-user-profile-pic",
                    "tailscale-app-capabilities",
                ]
                .iter()
                .any(|h| {
                    marked && headers.contains_key(*h) || headers.get_all(*h).iter().count() > 1
                })
        }
        IngressKind::CloudflareTunnel => {
            !headers.contains_key("tailscale-funnel-request")
                && !headers.contains_key("forwarded")
                && one(headers, "x-forwarded-host").is_none_or(|h| h == authority)
                && one(headers, "x-forwarded-proto") == Some("https")
                && (one(headers, "cf-connecting-ip")
                    .is_some_and(|v| v.parse::<std::net::IpAddr>().is_ok())
                    || one(headers, "x-forwarded-for")
                        .and_then(|v| v.split(',').next())
                        .is_some_and(|v| v.trim().parse::<std::net::IpAddr>().is_ok()))
        }
        IngressKind::Direct => ![
            "tailscale-funnel-request",
            "forwarded",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-for",
        ]
        .iter()
        .any(|h| headers.contains_key(*h)),
    };
    if req.uri().authority().is_some()
        || one(headers, "host") != Some(authority)
        || headers.contains_key(header::ORIGIN)
        || !forwarding
    {
        return error(StatusCode::FORBIDDEN, "invalid_origin_or_host");
    }
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    let method = req.method().clone();
    let auth = one(headers, "authorization").map(str::to_owned);
    let admission_auth = auth.clone();
    let admitted = shared
        .work(admin, move |state| {
            let budget = if admin {
                &mut state.admin_budget
            } else {
                &mut state.public_budget
            };
            if !budget.take(if admin { 30 } else { 60 }) {
                return Some(oauth_error(Error::Capacity));
            }
            if admin
                && !admission_auth
                    .as_deref()
                    .and_then(bearer_text)
                    .is_some_and(|v| bool::from(v.ct_eq(&state.operator)))
            {
                return Some(error(StatusCode::UNAUTHORIZED, "unauthorized"));
            }
            None
        })
        .await;
    match admitted {
        Ok(None) => {}
        Ok(Some(response)) => return response,
        Err(e) => return oauth_error(e),
    }
    if admin {
        if !matches!(path.as_str(), "/inspect" | "/approve" | "/deny" | "/revoke")
            || query.is_some()
        {
            return error(StatusCode::NOT_FOUND, "not_found");
        }
    } else {
        let Some(route) = public_route(&path) else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        if route != Route::Mcp && req.headers().contains_key(header::AUTHORIZATION) {
            return oauth_error(Error::InvalidRequest);
        }
        if route != Route::Authorize && query.is_some() {
            return oauth_error(Error::InvalidRequest);
        }
        if route == Route::Mcp {
            match shared
                .work(false, move |state| {
                    if identity(state, auth.as_deref()).is_none() {
                        return Some(unauthorized(state));
                    }
                    None
                })
                .await
            {
                Ok(None) => {}
                Ok(Some(response)) => return response,
                Err(e) => return oauth_error(e),
            }
            let mut response = native(req).await;
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            response.headers_mut().insert(
                "referrer-policy",
                header::HeaderValue::from_static("no-referrer"),
            );
            if response.status() == StatusCode::UNAUTHORIZED
                && let Ok(Some(challenge)) = shared
                    .work(false, |state| {
                        unauthorized(state)
                            .headers()
                            .get(header::WWW_AUTHENTICATE)
                            .cloned()
                    })
                    .await
            {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, challenge);
            }
            return response;
        }
        if matches!(
            route,
            Route::ProtectedResource | Route::AuthorizationServer | Route::Authorize
        ) {
            if method != Method::GET || !req.body().is_end_stream() {
                return error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
            }
            return shared
                .work(false, move |state| match route {
                    Route::ProtectedResource => json_reply(
                        StatusCode::OK,
                        state.registry.resource().protected_metadata(),
                    ),
                    Route::AuthorizationServer => json_reply(
                        StatusCode::OK,
                        state.registry.resource().authorization_metadata(),
                    ),
                    Route::Authorize => {
                        let query = query.as_deref().unwrap_or("");
                        let client = form(query.as_bytes()).and_then(|f| {
                            field(&f, "client_id")
                                .filter(|id| state.registry.get(id).is_some())
                                .map(str::to_owned)
                        });
                        state.transaction("authorize", client, |state, now| {
                            authorize(state, query, now)
                        })
                    }
                    _ => unreachable!(),
                })
                .await
                .unwrap_or_else(oauth_error);
        }
    }
    if method != Method::POST {
        return error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    }
    let content = if path == "/oauth/token" {
        "application/x-www-form-urlencoded"
    } else {
        "application/json"
    };
    if one(req.headers(), "content-type") != Some(content) {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_content_type");
    }
    let body = match tokio::time::timeout(
        REQUEST_TIMEOUT,
        Limited::new(req.into_body(), BODY_LIMIT).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes(),
        _ => return error(StatusCode::BAD_REQUEST, "invalid_or_oversized_body"),
    };
    shared
        .work(admin, move |state| {
            if admin {
                if path == "/inspect" {
                    return operator(state, &path, &body, Instant::now());
                }
                let client = object(&body).and_then(|v| {
                    if path == "/revoke" {
                        v.get("client_id")
                            .and_then(Value::as_str)
                            .filter(|id| state.registry.get(id).is_some())
                            .map(str::to_owned)
                    } else {
                        v.get("request")
                            .and_then(Value::as_str)
                            .and_then(|h| state.grants.pending(h, Instant::now()).ok())
                            .map(|r| r.binding().client_id().to_owned())
                    }
                });
                state.transaction(path.trim_start_matches('/'), client, |state, now| {
                    operator(state, &path, &body, now)
                })
            } else if path == "/oauth/register" {
                state.transaction("register", None, |state, _| register(state, &body))
            } else {
                let fields = form(&body);
                let client = fields
                    .as_ref()
                    .and_then(|f| field(f, "client_id"))
                    .filter(|id| state.registry.get(id).is_some())
                    .map(str::to_owned);
                let operation = match fields.as_ref().and_then(|f| field(f, "grant_type")) {
                    Some("authorization_code") => "exchange",
                    Some("refresh_token") => "refresh",
                    _ => "token",
                };
                state.transaction(operation, client, |state, now| token(state, &body, now))
            }
        })
        .await
        .unwrap_or_else(oauth_error)
}

async fn listener(
    socket: TcpListener,
    state: Arc<Shared>,
    authority: String,
    admin: bool,
) -> Result<(), String> {
    let permits = Arc::new(Semaphore::new(if admin { 4 } else { 16 }));
    loop {
        let (stream, peer) = socket.accept().await.map_err(|_| "Accept failed")?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let shared = state.clone();
        let host = authority.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let shared = shared.clone();
                let host = host.clone();
                async move {
                    Ok::<_, Infallible>(
                        handle(req, shared, &host, admin, IngressKind::Direct, |_| async {
                            error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "native_admission_not_enabled",
                            )
                        })
                        .await,
                    )
                }
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

pub fn init_state(dir: &Path, origin: &str) -> Result<(), String> {
    let resource = Resource::new(origin).map_err(|_| "Invalid HTTPS resource origin")?;
    Store::open_oauth(dir)?.write(&ClientRegistry::new(resource).snapshot(), true)?;
    println!("OAUTH_REGISTRY_INITIALIZED");
    Ok(())
}

pub fn open(origin: &str, config: Value, dir: Option<&Path>) -> Result<Server, String> {
    open_inner(origin, config, dir, None)
}

pub fn open_durable(
    origin: &str,
    config: Value,
    dir: &Path,
    binding: &str,
    initialize: bool,
) -> Result<Server, String> {
    open_inner(origin, config, None, Some((dir, binding, None, initialize)))
}

pub fn open_durable_with_legacy(
    origin: &str,
    config: Value,
    dir: &Path,
    binding: &str,
    legacy_binding: Option<&str>,
    initialize: bool,
) -> Result<Server, String> {
    open_inner(
        origin,
        config,
        None,
        Some((dir, binding, legacy_binding, initialize)),
    )
}

pub fn revoke_stopped_profile(dir: &Path, local: &str) -> Result<(), String> {
    durable::revoke_stopped_profile(dir, local)
}

pub fn inspect_stopped_state(dir: &Path) -> Result<Value, String> {
    durable::inspect_stopped_state(dir)
}

pub fn revoke_stopped_client(dir: &Path, local: &str, client_id: &str) -> Result<bool, String> {
    durable::revoke_stopped_client(dir, local, client_id)
}

pub fn switch_stopped_client_mode(
    dir: &Path,
    local: &str,
    client_id: &str,
    mode: ConnectionMode,
) -> Result<(ConnectionMode, bool), String> {
    durable::switch_stopped_client_mode(dir, local, client_id, mode)
}

pub fn switch_all_stopped_clients_mode(
    dir: &Path,
    local: &str,
    mode: ConnectionMode,
) -> Result<Vec<(String, ConnectionMode, bool)>, String> {
    durable::switch_all_stopped_clients_mode(dir, local, mode)
}

pub fn rebind_migrated_state(
    source_dir: &Path,
    dest_dir: &Path,
    local: &str,
    expected_old_bindings: &[&str],
    new_binding: &str,
) -> Result<String, String> {
    durable::rebind_migrated_state(source_dir, dest_dir, local, expected_old_bindings, new_binding)
}

pub fn persisted_origin(dir: &Path) -> Result<String, String> {
    durable::persisted_origin(dir)
}

fn open_inner(
    origin: &str,
    config: Value,
    dir: Option<&Path>,
    recovery: Option<(&Path, &str, Option<&str>, bool)>,
) -> Result<Server, String> {
    if config.as_object().is_none_or(|v| v.len() != 2) {
        return Err("Expected operator_token and local_fixture_client".into());
    }
    let operator = config["operator_token"]
        .as_str()
        .and_then(token_digest)
        .ok_or("Invalid operator credential")?;
    let local_client = config["local_fixture_client"]
        .as_str()
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 64
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
        .ok_or("Invalid fixture client")?
        .to_owned();
    let resource = Resource::new(origin).map_err(|_| "Invalid HTTPS resource origin")?;
    let (registry, persistence, durable, grants) =
        if let Some((dir, binding, legacy_binding, initialize)) = recovery {
            let (durable, registry, grants) = Durable::open_with_legacy(
                dir,
                resource,
                &local_client,
                binding,
                legacy_binding,
                initialize,
            )?;
            (registry, None, Some(durable), grants)
        } else if let Some(dir) = dir {
            let store = Store::open_oauth(dir)?;
            let snapshot = store.read()?;
            let registry = ClientRegistry::restore(resource, &snapshot)
                .map_err(|_| "Invalid OAuth registration state")?;
            (
                registry,
                Some((store, snapshot)),
                None,
                GrantStore::default(),
            )
        } else {
            (
                ClientRegistry::new(resource),
                None,
                None,
                GrantStore::default(),
            )
        };
    let authority = origin
        .strip_prefix("https://")
        .ok_or("Invalid origin")?
        .to_owned();
    let shared = Arc::new(Shared {
        public: Arc::new(Semaphore::new(8)),
        admin: Arc::new(Semaphore::new(4)),
        state: Mutex::new(State {
            registry,
            grants,
            deliveries: BTreeMap::new(),
            operator,
            local_client: local_client.clone(),
            public_budget: Budget::new(),
            admin_budget: Budget::new(),
            persistence,
            durable,
            failed: false,
        }),
    });
    Ok(Server {
        shared,
        authority,
        local_client,
        operator_digest: operator,
        ingress: IngressKind::Direct,
    })
}

pub async fn serve(
    port: u16,
    admin_port: u16,
    origin: &str,
    config: Value,
    dir: Option<&Path>,
) -> Result<(), String> {
    let Server {
        shared: state,
        authority,
        ..
    } = open(origin, config, dir)?;
    let public = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|_| "Cannot bind preview")?;
    let admin = TcpListener::bind(("127.0.0.1", admin_port))
        .await
        .map_err(|_| "Cannot bind operator preview")?;
    let public_addr: SocketAddr = public.local_addr().map_err(|_| "Cannot inspect preview")?;
    let admin_addr = admin
        .local_addr()
        .map_err(|_| "Cannot inspect operator preview")?;
    println!("OAUTH_PREVIEW {public_addr} {admin_addr}");
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(listener(public, state.clone(), authority, false));
    tasks.spawn(listener(admin, state, admin_addr.to_string(), true));
    match tasks.join_next().await {
        Some(Ok(result)) => result,
        _ => Err("Preview listener failed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocking_slots_survive_request_cancellation_and_leave_operator_capacity() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = open(
                "https://node.example",
                json!({"operator_token":"a".repeat(64),"local_fixture_client":"fixture"}),
                None,
            )
            .unwrap();
            let shared = server.shared.clone();
            let mut release = Vec::new();
            let mut requests = Vec::new();
            for _ in 0..8 {
                let (entered, ready) = tokio::sync::oneshot::channel();
                let (tx, rx) = std::sync::mpsc::channel();
                let worker = shared.clone();
                let task = tokio::spawn(async move {
                    worker
                        .blocking(false, move || {
                            let _ = entered.send(());
                            rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        })
                        .await
                });
                tokio::time::timeout(Duration::from_secs(5), ready)
                    .await
                    .unwrap()
                    .unwrap();
                release.push(tx);
                requests.push(task);
            }
            assert_eq!(shared.blocking(false, || ()).await, Err(Error::Capacity));
            requests[0].abort();
            assert!(requests.remove(0).await.unwrap_err().is_cancelled());
            assert_eq!(shared.blocking(false, || ()).await, Err(Error::Capacity));
            assert_eq!(shared.blocking(true, || 42).await, Ok(42));
            for tx in release {
                tx.send(()).unwrap();
            }
            for task in requests {
                task.await.unwrap().unwrap();
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if shared.public.available_permits() == 8 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(shared.blocking(false, || 7).await, Ok(7));
        });
    }
    #[test]
    fn strict_form_and_json_reject_ambiguity() {
        assert_eq!(form(b"x=a%2Bb+c").unwrap()["x"], "a+b c");
        for invalid in [
            b"x=1&%78=2".as_slice(),
            b"x=%FF",
            b"x=%00",
            b"x=%",
            b"x=%0",
            b"x=%zz",
            b"=a",
            b"x=1&",
            b"x",
        ] {
            assert!(form(invalid).is_none());
        }
        assert!(object(br#"{"client_id":"x","client_id":"y"}"#).is_none());
        assert!(object(br#"{"client_id":"x","client_\u0069d":"y"}"#).is_none());
        assert!(object(br#"{"client_id":"x"}"#).is_some());
        assert_eq!(
            consent_input("inspect", br#"{"request":"test"}"#).unwrap(),
            json!({"action":"inspect","request":"test"})
        );
        assert!(consent_input("approve", br#"{"confirm":true,"confirm":false}"#).is_err());
        assert!(consent_input("inspect", br#"{"action":"approve"}"#).is_err());
        assert!(consent_input("unknown", b"{}").is_err());
        assert!(consent_input("inspect", &vec![b' '; 8193]).is_err());
        assert_eq!(encode("a&b=+ %/é"), "a%26b%3D%2B%20%25%2F%C3%A9");
    }
}
