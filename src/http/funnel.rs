//! Credential verification for public MCP ingress.

use hyper::header::{self, HeaderMap, HeaderValue};
use mcp_gateway::security::policy::ExecutionMode;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::admission::Configuration;

pub(crate) const MARKER: &str = "Tailscale-Funnel-Request";
const ALLOW_HEADERS: &str =
    "Accept, Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version";
const MAX_PREFLIGHT_HEADER_BYTES: usize = 256;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub client: String,
    #[serde(default)]
    pub allow_secret_path: bool,
    #[serde(rename = "token_sha256", deserialize_with = "verifier")]
    digest: [u8; 32],
}

fn verifier<'de, D: serde::Deserializer<'de>>(input: D) -> Result<[u8; 32], D::Error> {
    let hex = String::deserialize(input)?;
    super::admission::decode_sha256(&hex).map_err(serde::de::Error::custom)
}

impl Settings {
    pub(crate) fn accepts_token(&self, token: &str) -> bool {
        self.allow_secret_path
            && super::admission::token_digest(token)
                .is_some_and(|digest| bool::from(self.digest.ct_eq(&digest)))
    }

    pub(crate) fn validate(&self, config: &Configuration) -> Result<(), String> {
        if config.audit_log.is_none()
            || !config.managed
            || !config.clients.iter().any(|client| client.id == self.client)
            || config
                .clients
                .iter()
                .any(|client| client.has_digest(&self.digest))
        {
            return Err(
                "Funnel needs a managed client, a separate verifier and a private audit ledger"
                    .into(),
            );
        }
        Ok(())
    }
}

pub(super) fn marked(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(MARKER).iter();
    values.next().is_some_and(|value| value == "?1") && values.next().is_none()
}

#[derive(Clone, Copy)]
pub(super) enum Origin {
    Absent,
    Same,
    ChatGpt,
    OpenAi,
    Rejected,
}

impl Origin {
    pub(super) fn parse(headers: &HeaderMap, same_origin: &str) -> Self {
        let mut origins = headers.get_all(header::ORIGIN).iter();
        let Some(origin) = origins.next() else {
            return Self::Absent;
        };
        if origins.next().is_some() {
            return Self::Rejected;
        }
        match origin.as_bytes() {
            b"https://chatgpt.com" => Self::ChatGpt,
            b"https://chat.openai.com" => Self::OpenAi,
            value if value == same_origin.as_bytes() => Self::Same,
            _ => Self::Rejected,
        }
    }

    pub(super) fn value(self) -> Option<HeaderValue> {
        match self {
            Self::ChatGpt => Some(HeaderValue::from_static("https://chatgpt.com")),
            Self::OpenAi => Some(HeaderValue::from_static("https://chat.openai.com")),
            _ => None,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Same => "same",
            Self::ChatGpt => "chatgpt",
            Self::OpenAi => "chat_openai",
            Self::Rejected => "rejected",
        }
    }
}

pub(super) fn route_matches(path: &str, allow_secret_path: bool) -> bool {
    let path = path.strip_prefix("/veyl").unwrap_or(path);
    // Browser preflight must see the same result for any well-formed
    // secret path, regardless of whether the credential is valid.
    path == "/mcp"
        || (allow_secret_path
            && path
                .strip_prefix("/mcp/")
                .is_some_and(super::admission::token_shape))
}

pub(super) fn options_allowed(headers: &HeaderMap) -> bool {
    let mut methods = headers
        .get_all(header::ACCESS_CONTROL_REQUEST_METHOD)
        .iter();
    if !methods.next().is_some_and(|method| method == "POST") || methods.next().is_some() {
        return false;
    }
    let mut requested = headers
        .get_all(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .iter();
    let Some(value) = requested.next() else {
        return true;
    };
    requested.next().is_none()
        && value.len() <= MAX_PREFLIGHT_HEADER_BYTES
        && value.to_str().is_ok_and(|names| {
            names.split(',').all(|name| {
                ALLOW_HEADERS
                    .split(", ")
                    .any(|allowed| name.trim().eq_ignore_ascii_case(allowed))
            })
        })
}

pub(super) fn cors_headers(headers: &mut HeaderMap, origin: Origin, preflight: bool) {
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    if preflight {
        headers.append(
            header::VARY,
            HeaderValue::from_static("Access-Control-Request-Method"),
        );
        headers.append(
            header::VARY,
            HeaderValue::from_static("Access-Control-Request-Headers"),
        );
    }
    if let Some(value) = origin.value() {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("Mcp-Session-Id, Mcp-Protocol-Version"),
        );
    }
}

pub(super) fn preflight_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(ALLOW_HEADERS),
    );
}

pub(super) fn proof(path: &str, headers: &HeaderMap, allow_secret_path: bool) -> Option<[u8; 32]> {
    let path = path.strip_prefix("/veyl").unwrap_or(path);
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let first = values.next();
    let token = if path == "/mcp" && values.next().is_none() {
        first.and_then(bearer)?
    } else if allow_secret_path && first.is_none() {
        path.strip_prefix("/mcp/")?
    } else {
        return None;
    };
    super::admission::token_digest(token)
}

fn bearer(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok()?.strip_prefix("Bearer ")
}

pub(super) fn authenticate(
    settings: &Configuration,
    proof: Option<&[u8; 32]>,
    now: u64,
) -> Option<usize> {
    let public = settings.tailnet.as_ref()?.funnel.as_ref()?;
    if !bool::from(public.digest.ct_eq(proof?)) {
        return None;
    }
    settings.clients.iter().position(|client| {
        client.id == public.client
            && !client.disabled
            && client.mode == ExecutionMode::BroadYolo
            && now < client.expires_at
    })
}
