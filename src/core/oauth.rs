//! Bounded OAuth authorization-code/PKCE grant lifecycle.
//! Transport, local approval UI, persistence, and live native policy
//! checks are deliberately outside this component.
//! Nothing in this module enables an HTTP route or authorizes an MCP tool.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

use super::{credential::token_digest, session::random_id};

#[cfg(target_os = "linux")]
pub(crate) mod persistence;

const PENDING_TTL: Duration = Duration::from_secs(300);
const CODE_TTL: Duration = Duration::from_secs(60);
const ACCESS_TTL: Duration = Duration::from_secs(900);
const FAMILY_TTL: Duration = Duration::from_secs(86_400);
const MAX_GRANTS: usize = 128;
const MAX_ROTATIONS: usize = 256;

type Digest32 = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRequest,
    InvalidGrant,
    Capacity,
    Unavailable,
}

/// Constructed only by the registered-client validation layer. No URL
/// matching by prefix or trust in a request-supplied Host belongs here.
#[derive(Clone, PartialEq, Eq)]
pub struct Binding {
    client_id: String,
    redirect_uri: String,
    resource: String,
}

pub(crate) fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

impl Binding {
    pub(crate) fn new(client_id: &str, redirect_uri: &str, resource: &str) -> Result<Self, Error> {
        if !bounded(client_id, 256) || !bounded(redirect_uri, 2048) || !bounded(resource, 2048) {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            resource: resource.into(),
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }
}

fn verifier_digest(verifier: &str) -> Option<Digest32> {
    let valid = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'));
    valid.then(|| Sha256::digest(verifier.as_bytes()).into())
}

/// RFC 7636 S256 only; reject padded, non-canonical and wrong-sized challenges.
pub(crate) fn challenge_digest(challenge: &str) -> Option<Digest32> {
    if challenge.len() != 43 {
        return None;
    }
    let digest: Digest32 = URL_SAFE_NO_PAD.decode(challenge).ok()?.try_into().ok()?;
    (URL_SAFE_NO_PAD.encode(digest) == challenge).then_some(digest)
}

fn same(a: &Digest32, b: &Digest32) -> bool {
    bool::from(a.ct_eq(b))
}

pub struct AuthorizationRequest {
    binding: Binding,
    challenge: Digest32,
    state: Option<String>,
}

impl AuthorizationRequest {
    pub fn new(
        binding: Binding,
        challenge: &str,
        method: &str,
        state: Option<&str>,
    ) -> Result<Self, Error> {
        if method != "S256" || state.is_some_and(|s| !bounded(s, 1024)) {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            binding,
            challenge: challenge_digest(challenge).ok_or(Error::InvalidRequest)?,
            state: state.map(str::to_owned),
        })
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }
}

/// Returned only after approval by the future authenticated local operator UI.
/// No Debug implementation: codes/tokens must not be printed in diagnostics.
pub struct ApprovedCode {
    pub code: String,
    pub binding: Binding,
    pub state: Option<String>,
}

pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// Per-OAuth-connection effective execution mode. Registrations and new approvals
/// default to Standard; YOLO requires explicit local approval or escalation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    #[default]
    #[serde(alias = "yolo")]
    Standard,
    #[serde(rename = "native_yolo")]
    Yolo,
}

impl ConnectionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Yolo => "yolo",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "standard" => Some(Self::Standard),
            "yolo" => Some(Self::Yolo),
            _ => None,
        }
    }
}

#[cfg(test)]
#[test]
fn persisted_old_oauth_yolo_has_only_standard_authority() {
    assert_eq!(
        serde_json::from_str::<ConnectionMode>(r#""yolo""#).unwrap(),
        ConnectionMode::Standard
    );
    let native = serde_json::to_string(&ConnectionMode::Yolo).unwrap();
    assert_eq!(native, r#""native_yolo""#);
    assert_eq!(
        serde_json::from_str::<ConnectionMode>(&native).unwrap(),
        ConnectionMode::Yolo
    );
}

/// Identity, not execution permission. Native policy must revalidate this
/// local client (activation, grants, mode and protected paths) on every call.
pub struct AccessIdentity<'a> {
    pub local_client: &'a str,
    pub oauth_client: &'a str,
    pub resource: &'a str,
    /// Stable within one grant family, including refresh. Not a bearer.
    pub family: [u8; 32],
    pub mode: ConnectionMode,
    pub access_remaining: Duration,
}

enum Stage {
    Pending {
        handle: Digest32,
        until: Instant,
    },
    Approved {
        code: Digest32,
        local_client: String,
        mode: ConnectionMode,
        until: Instant,
    },
    Active {
        code: Digest32,
        local_client: String,
        mode: ConnectionMode,
        access: Digest32,
        refresh: Digest32,
        spent_refresh: Vec<Digest32>,
        access_until: Instant,
        family_until: Instant,
    },
}

struct Entry {
    request: AuthorizationRequest,
    stage: Stage,
}

impl Entry {
    fn expires(&self) -> Instant {
        match &self.stage {
            Stage::Pending { until, .. } | Stage::Approved { until, .. } => *until,
            Stage::Active { family_until, .. } => *family_until,
        }
    }

    fn contains_digest(&self, digest: &Digest32) -> bool {
        match &self.stage {
            Stage::Pending { handle, .. } => same(handle, digest),
            Stage::Approved { code, .. } => same(code, digest),
            Stage::Active {
                code,
                access,
                refresh,
                spent_refresh,
                ..
            } => {
                same(code, digest)
                    || same(access, digest)
                    || same(refresh, digest)
                    || spent_refresh.iter().any(|old| same(old, digest))
            }
        }
    }
}

/// In-memory preview. Restart invalidates all pending requests and tokens.
/// The HTTP adapter must serialize transitions and add durable owner-private
/// state, audit and abuse controls before exposure. Time is server-supplied.
#[derive(Default)]
pub struct GrantStore {
    entries: Vec<Entry>,
}

impl GrantStore {
    fn prune(&mut self, now: Instant) {
        self.entries.retain(|entry| now < entry.expires());
    }

    fn fresh(&self) -> Result<(String, Digest32), Error> {
        let raw = random_id::<32>().map_err(|_| Error::Unavailable)?;
        let digest = token_digest(&raw).ok_or(Error::Unavailable)?;
        if self
            .entries
            .iter()
            .any(|entry| entry.contains_digest(&digest))
        {
            return Err(Error::Unavailable);
        }
        Ok((raw, digest))
    }

    fn pending_index(&self, handle: &str) -> Result<usize, Error> {
        let digest = token_digest(handle).ok_or(Error::InvalidGrant)?;
        self.entries.iter().position(|entry| {
            matches!(&entry.stage, Stage::Pending { handle, .. } if same(handle, &digest))
        }).ok_or(Error::InvalidGrant)
    }

    pub fn begin(&mut self, request: AuthorizationRequest, now: Instant) -> Result<String, Error> {
        self.prune(now);
        if self.entries.len() >= MAX_GRANTS {
            return Err(Error::Capacity);
        }
        let (raw, handle) = self.fresh()?;
        self.entries.push(Entry {
            request,
            stage: Stage::Pending {
                handle,
                until: now + PENDING_TTL,
            },
        });
        Ok(raw)
    }

    /// For the authenticated local approval UI, not an unauthenticated route.
    pub fn pending(&self, handle: &str, now: Instant) -> Result<&AuthorizationRequest, Error> {
        let entry = &self.entries[self.pending_index(handle)?];
        if now >= entry.expires() {
            return Err(Error::InvalidGrant);
        }
        Ok(&entry.request)
    }

    /// The caller must already be a trusted local operator and resolve the
    /// exact existing local client ID. Defaults to Standard connection mode.
    pub fn approve_local(
        &mut self,
        handle: &str,
        local_client: &str,
        now: Instant,
    ) -> Result<ApprovedCode, Error> {
        self.approve_local_with_mode(handle, local_client, ConnectionMode::Standard, now)
    }

    pub fn approve_local_with_mode(
        &mut self,
        handle: &str,
        local_client: &str,
        mode: ConnectionMode,
        now: Instant,
    ) -> Result<ApprovedCode, Error> {
        self.prune(now);
        if !bounded(local_client, 128) {
            return Err(Error::InvalidRequest);
        }
        let index = self.pending_index(handle)?;
        let (raw, code) = self.fresh()?;
        let entry = &mut self.entries[index];
        entry.stage = Stage::Approved {
            code,
            local_client: local_client.into(),
            mode,
            until: now + CODE_TTL,
        };
        Ok(ApprovedCode {
            code: raw,
            binding: entry.request.binding.clone(),
            state: entry.request.state.take(),
        })
    }

    pub fn deny_local(
        &mut self,
        handle: &str,
        now: Instant,
    ) -> Result<AuthorizationRequest, Error> {
        self.prune(now);
        let index = self.pending_index(handle)?;
        Ok(self.entries.swap_remove(index).request)
    }

    fn issue(
        &self,
        now: Instant,
        family_until: Instant,
    ) -> Result<(Tokens, Digest32, Digest32, Instant), Error> {
        let (access_token, access) = self.fresh()?;
        let (refresh_token, refresh) = self.fresh()?;
        if same(&access, &refresh) {
            return Err(Error::Unavailable);
        }
        let access_until = (now + ACCESS_TTL).min(family_until);
        Ok((
            Tokens {
                access_token,
                refresh_token,
                expires_in: access_until.duration_since(now).as_secs(),
            },
            access,
            refresh,
            access_until,
        ))
    }

    pub fn exchange(
        &mut self,
        code: &str,
        binding: &Binding,
        verifier: &str,
        now: Instant,
    ) -> Result<Tokens, Error> {
        self.prune(now);
        let digest = token_digest(code).ok_or(Error::InvalidGrant)?;
        let verifier = verifier_digest(verifier).ok_or(Error::InvalidGrant)?;
        let index = self
            .entries
            .iter()
            .position(|entry| {
                entry.request.binding == *binding
                    && same(&entry.request.challenge, &verifier)
                    && matches!(&entry.stage,
                    Stage::Approved { code, .. } | Stage::Active { code, .. }
                    if same(code, &digest))
            })
            .ok_or(Error::InvalidGrant)?;
        if matches!(self.entries[index].stage, Stage::Active { .. }) {
            // A correctly bound code replay invalidates the issued family.
            self.entries.swap_remove(index);
            return Err(Error::InvalidGrant);
        }
        let Stage::Approved {
            code,
            local_client,
            mode,
            ..
        } = &self.entries[index].stage
        else {
            return Err(Error::InvalidGrant);
        };
        let code = *code;
        let local_client = local_client.clone();
        let mode = *mode;
        let family_until = now + FAMILY_TTL;
        let (tokens, access, refresh, access_until) = self.issue(now, family_until)?;
        self.entries[index].stage = Stage::Active {
            code,
            local_client,
            mode,
            access,
            refresh,
            spent_refresh: Vec::new(),
            access_until,
            family_until,
        };
        Ok(tokens)
    }

    pub fn refresh(
        &mut self,
        token: &str,
        client_id: &str,
        resource: &str,
        now: Instant,
    ) -> Result<Tokens, Error> {
        self.prune(now);
        let digest = token_digest(token).ok_or(Error::InvalidGrant)?;
        let index = self
            .entries
            .iter()
            .position(|entry| {
                entry.request.binding.client_id == client_id
                    && entry.request.binding.resource == resource
                    && matches!(&entry.stage, Stage::Active { refresh, spent_refresh, .. }
                    if same(refresh, &digest) || spent_refresh.iter().any(|old| same(old, &digest)))
            })
            .ok_or(Error::InvalidGrant)?;
        let Stage::Active {
            refresh,
            spent_refresh,
            family_until,
            ..
        } = &self.entries[index].stage
        else {
            return Err(Error::InvalidGrant);
        };
        if !same(refresh, &digest) || spent_refresh.len() >= MAX_ROTATIONS {
            // A replay or excessive rotations forces fresh local approval.
            self.entries.swap_remove(index);
            return Err(Error::InvalidGrant);
        }
        let (tokens, new_access, new_refresh, new_until) = self.issue(now, *family_until)?;
        let Stage::Active {
            access,
            refresh,
            spent_refresh,
            access_until,
            ..
        } = &mut self.entries[index].stage
        else {
            return Err(Error::InvalidGrant);
        };
        spent_refresh.push(*refresh);
        *access = new_access;
        *refresh = new_refresh;
        *access_until = new_until;
        Ok(tokens)
    }

    pub fn authenticate(
        &self,
        token: &str,
        resource: &str,
        now: Instant,
    ) -> Option<AccessIdentity<'_>> {
        let digest = token_digest(token)?;
        self.entries.iter().find_map(|entry| {
            if resource != entry.request.binding.resource {
                return None;
            }
            let Stage::Active {
                code,
                access,
                local_client,
                mode,
                access_until,
                family_until,
                ..
            } = &entry.stage
            else {
                return None;
            };
            (now < *access_until && now < *family_until && same(access, &digest)).then_some(
                AccessIdentity {
                    local_client,
                    oauth_client: &entry.request.binding.client_id,
                    resource: &entry.request.binding.resource,
                    family: *code,
                    mode: *mode,
                    access_remaining: (*access_until)
                        .min(*family_until)
                        .saturating_duration_since(now),
                },
            )
        })
    }

    /// Local operator revocation applies to pending issued codes and all
    /// active families of this native client. Unapproved requests cannot
    /// acquire this client without a subsequent explicit local approval.
    pub fn revoke_local_client(&mut self, local_client: &str) {
        self.entries.retain(|entry| {
            !matches!(&entry.stage, Stage::Approved { local_client: id, .. }
                | Stage::Active { local_client: id, .. } if id == local_client)
        });
    }

    pub(crate) fn revoke_oauth_client(&mut self, client_id: &str) {
        self.entries
            .retain(|entry| entry.request.binding.client_id != client_id);
    }

    /// Immediately downgrade any approved or active grant families for `client_id`
    /// back to Standard so existing tokens can never re-elevate without fresh auth.
    pub fn downgrade_oauth_client(&mut self, client_id: &str) -> bool {
        let mut changed = false;
        for entry in &mut self.entries {
            if entry.request.binding.client_id != client_id {
                continue;
            }
            match &mut entry.stage {
                Stage::Approved { mode, .. } | Stage::Active { mode, .. }
                    if *mode != ConnectionMode::Standard =>
                {
                    *mode = ConnectionMode::Standard;
                    changed = true;
                }
                _ => {}
            }
        }
        changed
    }

    pub fn client_family_modes(&self, client_id: &str, now: Instant) -> Vec<ConnectionMode> {
        self.entries
            .iter()
            .filter_map(|entry| {
                if entry.request.binding.client_id != client_id {
                    return None;
                }
                match &entry.stage {
                    Stage::Active {
                        mode, family_until, ..
                    } if now < *family_until => Some(*mode),
                    _ => None,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const RESOURCE: &str = "https://veyl.example/mcp";

    fn binding(client: &str, redirect: &str, resource: &str) -> Binding {
        Binding::new(client, redirect, resource).unwrap()
    }

    fn registered() -> Binding {
        binding("chat", "https://client.example/callback", RESOURCE)
    }

    fn request() -> AuthorizationRequest {
        AuthorizationRequest::new(registered(), CHALLENGE, "S256", Some("opaque-state")).unwrap()
    }

    fn approved(store: &mut GrantStore, now: Instant, local: &str) -> ApprovedCode {
        let pending = store.begin(request(), now).unwrap();
        assert!(store.pending(&pending, now).is_ok());
        store.approve_local(&pending, local, now).unwrap()
    }

    #[test]
    fn rfc7636_known_vector_and_strict_challenge() {
        assert_eq!(
            URL_SAFE_NO_PAD.encode(verifier_digest(VERIFIER).unwrap()),
            CHALLENGE
        );
        for invalid in [
            "",
            "plain",
            &"x".repeat(42),
            &"x".repeat(44),
            &format!("{CHALLENGE}="),
        ] {
            assert!(AuthorizationRequest::new(registered(), invalid, "S256", None).is_err());
        }
        assert!(AuthorizationRequest::new(registered(), CHALLENGE, "plain", None).is_err());
        assert!(verifier_digest(&"a".repeat(42)).is_none());
        assert!(verifier_digest(&"a".repeat(129)).is_none());
        assert!(verifier_digest(&format!("{}+", "a".repeat(42))).is_none());
        assert!(verifier_digest(&"a".repeat(128)).is_some());
    }

    #[test]
    fn approval_is_required_one_use_and_state_bound() {
        let now = Instant::now();
        let mut store = GrantStore::default();
        let pending = store.begin(request(), now).unwrap();
        assert!(
            store
                .exchange(&pending, &registered(), VERIFIER, now)
                .is_err()
        );
        let code = store.approve_local(&pending, "local-a", now).unwrap();
        assert!(store.approve_local(&pending, "local-b", now).is_err());
        assert_eq!(code.state.as_deref(), Some("opaque-state"));
        assert_eq!(
            code.binding.redirect_uri(),
            "https://client.example/callback"
        );
        let tokens = store
            .exchange(&code.code, &registered(), VERIFIER, now)
            .unwrap();
        let identity = store
            .authenticate(&tokens.access_token, RESOURCE, now)
            .unwrap();
        assert_eq!(identity.local_client, "local-a");
        assert_eq!(identity.oauth_client, "chat");
        assert_eq!(tokens.expires_in, ACCESS_TTL.as_secs());
        assert!(
            store
                .exchange(&code.code, &registered(), VERIFIER, now)
                .is_err()
        );
        assert!(
            store
                .authenticate(&tokens.access_token, RESOURCE, now)
                .is_none()
        );
        assert!(
            store
                .refresh(&tokens.refresh_token, "chat", RESOURCE, now)
                .is_err()
        );
    }

    #[test]
    fn exact_binding_and_pkce_no_token_on_mismatch() {
        let now = Instant::now();
        let mut store = GrantStore::default();
        let code = approved(&mut store, now, "local-a");
        for other in [
            binding("other", "https://client.example/callback", RESOURCE),
            binding("chat", "https://client.example/callback/evil", RESOURCE),
            binding(
                "chat",
                "https://client.example/callback",
                "https://other.example/mcp",
            ),
        ] {
            assert!(store.exchange(&code.code, &other, VERIFIER, now).is_err());
        }
        assert!(
            store
                .exchange(&code.code, &registered(), &"a".repeat(43), now)
                .is_err()
        );
        let tokens = store
            .exchange(&code.code, &registered(), VERIFIER, now)
            .unwrap();
        assert!(
            store
                .authenticate(&tokens.access_token, "https://other.example/mcp", now)
                .is_none()
        );
        assert!(
            store
                .authenticate(&tokens.refresh_token, RESOURCE, now)
                .is_none()
        );
        assert!(
            store
                .authenticate(&tokens.access_token, RESOURCE, now)
                .is_some()
        );
    }

    #[test]
    fn expiry_and_denial_are_fail_closed() {
        let now = Instant::now();
        let mut store = GrantStore::default();
        let pending = store.begin(request(), now).unwrap();
        assert!(store.pending(&pending, now + PENDING_TTL).is_err());
        assert!(
            store
                .approve_local(&pending, "local-a", now + PENDING_TTL)
                .is_err()
        );
        let t = now + PENDING_TTL;
        let pending = store.begin(request(), t).unwrap();
        store.deny_local(&pending, t).unwrap();
        assert!(store.approve_local(&pending, "local-a", t).is_err());
        let code = approved(&mut store, t, "local-a");
        assert!(
            store
                .exchange(&code.code, &registered(), VERIFIER, t + CODE_TTL)
                .is_err()
        );
        let t = t + CODE_TTL;
        let code = approved(&mut store, t, "local-a");
        let tokens = store
            .exchange(&code.code, &registered(), VERIFIER, t)
            .unwrap();
        assert!(
            store
                .authenticate(&tokens.access_token, RESOURCE, t + ACCESS_TTL)
                .is_none()
        );
        assert!(
            store
                .refresh(&tokens.refresh_token, "chat", RESOURCE, t + FAMILY_TTL)
                .is_err()
        );
    }

    #[test]
    fn refresh_rotates_both_tokens_and_replay_revokes_family() {
        let now = Instant::now();
        let mut store = GrantStore::default();
        let code = approved(&mut store, now, "local-a");
        let first = store
            .exchange(&code.code, &registered(), VERIFIER, now)
            .unwrap();
        let t = now + ACCESS_TTL;
        assert!(
            store
                .refresh(&first.refresh_token, "other", RESOURCE, t)
                .is_err()
        );
        assert!(
            store
                .refresh(&first.refresh_token, "chat", "https://other.example/mcp", t)
                .is_err()
        );
        assert!(
            store
                .refresh(&first.access_token, "chat", RESOURCE, t)
                .is_err()
        );
        let second = store
            .refresh(&first.refresh_token, "chat", RESOURCE, t)
            .unwrap();
        assert_ne!(first.access_token, second.access_token);
        assert_ne!(first.refresh_token, second.refresh_token);
        assert!(
            store
                .authenticate(&first.access_token, RESOURCE, t)
                .is_none()
        );
        assert!(
            store
                .authenticate(&second.access_token, RESOURCE, t)
                .is_some()
        );
        assert!(
            store
                .refresh(&first.refresh_token, "chat", RESOURCE, t)
                .is_err()
        );
        assert!(
            store
                .authenticate(&second.access_token, RESOURCE, t)
                .is_none()
        );
        assert!(
            store
                .refresh(&second.refresh_token, "chat", RESOURCE, t)
                .is_err()
        );
    }

    #[test]
    fn revoke_scoped_to_native_client_and_restart_invalidates() {
        let now = Instant::now();
        let mut store = GrantStore::default();
        let a = approved(&mut store, now, "local-a");
        let b = approved(&mut store, now, "local-b");
        let still_pending_code = approved(&mut store, now, "local-a");
        let a = store
            .exchange(&a.code, &registered(), VERIFIER, now)
            .unwrap();
        let b = store
            .exchange(&b.code, &registered(), VERIFIER, now)
            .unwrap();
        store.revoke_local_client("local-a");
        assert!(store.authenticate(&a.access_token, RESOURCE, now).is_none());
        assert!(
            store
                .refresh(&a.refresh_token, "chat", RESOURCE, now)
                .is_err()
        );
        assert!(
            store
                .exchange(&still_pending_code.code, &registered(), VERIFIER, now)
                .is_err()
        );
        assert_eq!(
            store
                .authenticate(&b.access_token, RESOURCE, now)
                .unwrap()
                .local_client,
            "local-b"
        );
        assert!(
            GrantStore::default()
                .authenticate(&b.access_token, RESOURCE, now)
                .is_none()
        );
    }

    #[test]
    fn capacity_and_family_lifetime_are_bounded() {
        let now = Instant::now();
        let mut store = GrantStore::default();
        for _ in 0..MAX_GRANTS {
            store.begin(request(), now).unwrap();
        }
        assert_eq!(store.begin(request(), now), Err(Error::Capacity));
        let t = now + PENDING_TTL;
        let code = approved(&mut store, t, "local-a");
        let tokens = store
            .exchange(&code.code, &registered(), VERIFIER, t)
            .unwrap();
        let near_end = t + FAMILY_TTL - Duration::from_secs(1);
        let renewed = store
            .refresh(&tokens.refresh_token, "chat", RESOURCE, near_end)
            .unwrap();
        assert_eq!(renewed.expires_in, 1);
        assert!(
            store
                .authenticate(&renewed.access_token, RESOURCE, t + FAMILY_TTL)
                .is_none()
        );
    }

    #[test]
    fn rotation_budget_requires_new_approval() {
        let now = Instant::now();
        let mut store = GrantStore::default();
        let code = approved(&mut store, now, "local-a");
        let mut tokens = store
            .exchange(&code.code, &registered(), VERIFIER, now)
            .unwrap();
        for _ in 0..MAX_ROTATIONS {
            tokens = store
                .refresh(&tokens.refresh_token, "chat", RESOURCE, now)
                .unwrap();
        }
        assert!(
            store
                .refresh(&tokens.refresh_token, "chat", RESOURCE, now)
                .is_err()
        );
        assert!(
            store
                .authenticate(&tokens.access_token, RESOURCE, now)
                .is_none()
        );
    }

    #[test]
    fn connection_mode_defaults_to_standard_and_downgrades_immediately() {
        let now = Instant::now();
        let mut store = GrantStore::default();
        let std_req = store.begin(request(), now).unwrap();
        let std_code = store.approve_local(&std_req, "local-a", now).unwrap();
        let std_tokens = store
            .exchange(&std_code.code, &registered(), VERIFIER, now)
            .unwrap();
        assert_eq!(
            store
                .authenticate(&std_tokens.access_token, RESOURCE, now)
                .unwrap()
                .mode,
            ConnectionMode::Standard
        );

        let yolo_req = store.begin(request(), now).unwrap();
        let yolo_code = store
            .approve_local_with_mode(&yolo_req, "local-a", ConnectionMode::Yolo, now)
            .unwrap();
        let yolo_tokens = store
            .exchange(&yolo_code.code, &registered(), VERIFIER, now)
            .unwrap();
        assert_eq!(
            store
                .authenticate(&yolo_tokens.access_token, RESOURCE, now)
                .unwrap()
                .mode,
            ConnectionMode::Yolo
        );
        let refreshed = store
            .refresh(&yolo_tokens.refresh_token, "chat", RESOURCE, now)
            .unwrap();
        assert_eq!(
            store
                .authenticate(&refreshed.access_token, RESOURCE, now)
                .unwrap()
                .mode,
            ConnectionMode::Yolo
        );

        assert!(store.downgrade_oauth_client("chat"));
        assert_eq!(
            store
                .authenticate(&refreshed.access_token, RESOURCE, now)
                .unwrap()
                .mode,
            ConnectionMode::Standard
        );
        assert_eq!(
            store.client_family_modes("chat", now),
            vec![ConnectionMode::Standard, ConnectionMode::Standard]
        );
    }

    #[test]
    fn reconsent_to_standard_clamps_old_yolo_families_across_later_yolo_grant() {
        let now = Instant::now();
        let mut store = GrantStore::default();
        let old_req = store.begin(request(), now).unwrap();
        let old_code = store
            .approve_local_with_mode(&old_req, "local-a", ConnectionMode::Yolo, now)
            .unwrap();
        let old_tokens = store
            .exchange(&old_code.code, &registered(), VERIFIER, now)
            .unwrap();
        assert_eq!(
            store
                .authenticate(&old_tokens.access_token, RESOURCE, now)
                .unwrap()
                .mode,
            ConnectionMode::Yolo
        );

        let std_req = store.begin(request(), now).unwrap();
        let std_code = store
            .approve_local_with_mode(&std_req, "local-a", ConnectionMode::Standard, now)
            .unwrap();
        assert!(store.downgrade_oauth_client("chat"));
        let _std_tokens = store
            .exchange(&std_code.code, &registered(), VERIFIER, now)
            .unwrap();

        let new_req = store.begin(request(), now).unwrap();
        let new_code = store
            .approve_local_with_mode(&new_req, "local-a", ConnectionMode::Yolo, now)
            .unwrap();
        let new_tokens = store
            .exchange(&new_code.code, &registered(), VERIFIER, now)
            .unwrap();
        assert_eq!(
            store
                .authenticate(&new_tokens.access_token, RESOURCE, now)
                .unwrap()
                .mode,
            ConnectionMode::Yolo
        );
        // Old family stays permanently Standard even after fresh YOLO grant.
        assert_eq!(
            store
                .authenticate(&old_tokens.access_token, RESOURCE, now)
                .unwrap()
                .mode,
            ConnectionMode::Standard
        );
    }
}
