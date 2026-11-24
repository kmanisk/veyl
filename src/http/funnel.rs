//! Credential verification for public MCP ingress.

use hyper::header::{self, HeaderMap, HeaderValue};
use mcp_gateway::security::policy::ExecutionMode;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::admission::Configuration;

pub(crate) const MARKER: &str = "Tailscale-Funnel-Request";

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

pub(super) fn proof(path: &str, headers: &HeaderMap, allow_secret_path: bool) -> Option<[u8; 32]> {
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
            && client.mode == ExecutionMode::BroadYolo
            && now < client.expires_at
    })
}
