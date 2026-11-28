//! Atomic OAuth lifecycle checkpoint. The same private file contains
//! registrations, active hashed families, and bounded lifecycle receipts.
//! A durable intent precedes transitions. Interrupted intent is a startup
//! blocker, not an invitation to resurrect a possibly revoked family.
use super::*;
use crate::core::oauth::{ConnectionMode, persistence::Family};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AUDIT_LIMIT: usize = 2048;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    sequence: u64,
    unix_ms: u64,
    operation: String,
    status: u16,
    client: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    binding: String,
    saved_ms: u64,
    interrupted: Option<String>,
    registry: Value,
    families: Vec<Family>,
    audit: Vec<Receipt>,
}

fn operation_valid(operation: &str) -> bool {
    matches!(
        operation,
        "register"
            | "authorize"
            | "approve"
            | "deny"
            | "revoke"
            | "mode"
            | "exchange"
            | "refresh"
            | "token"
    )
}

fn wall_ms() -> Result<u64, Error> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Unavailable)?
        .as_millis();
    u64::try_from(ms).map_err(|_| Error::Unavailable)
}

fn checked_clock(projected: u64, saved: u64, wall: u64) -> Result<u64, Error> {
    if wall < saved || wall.abs_diff(projected) > 2000 {
        return Err(Error::Unavailable);
    }
    Ok(projected.max(saved))
}

fn seal(snapshot: &Snapshot) -> Result<Value, Error> {
    let payload = serde_json::to_value(snapshot).map_err(|_| Error::Unavailable)?;
    // Integrity check for accidental corruption, not a MAC or a defense
    // against an arbitrary process with the same host UID.
    let checksum = format!("{:x}", Sha256::digest(payload.to_string().as_bytes()));
    Ok(json!({"payload":payload,"sha256":checksum}))
}

fn unseal(value: &Value) -> Result<Snapshot, Error> {
    if value.as_object().is_none_or(|v| v.len() != 2) {
        return Err(Error::InvalidRequest);
    }
    let checksum = format!(
        "{:x}",
        Sha256::digest(value["payload"].to_string().as_bytes())
    );
    if value["sha256"].as_str() != Some(checksum.as_str()) {
        return Err(Error::InvalidRequest);
    }
    serde_json::from_value(value["payload"].clone()).map_err(|_| Error::InvalidRequest)
}

/// Routing hint only; open independently validates full state/policy binding.
pub(super) fn persisted_origin(dir: &Path) -> Result<String, String> {
    let store = Store::open_oauth_state(dir)?;
    let snapshot = unseal(&store.read()?).map_err(|_| "Invalid OAuth state")?;
    if snapshot.version != 1 || snapshot.interrupted.is_some() {
        return Err("Interrupted or unsupported OAuth state".into());
    }
    let origin = snapshot.registry["resource"]
        .as_str()
        .and_then(|s| s.strip_suffix("/mcp"))
        .ok_or("Invalid saved OAuth resource")?;
    let resource = Resource::new(origin).map_err(|_| "Invalid saved OAuth origin")?;
    ClientRegistry::restore(resource, &snapshot.registry)
        .map_err(|_| "Invalid saved OAuth registrations")?;
    Ok(origin.to_owned())
}

/// Verify from sealed durable OAuth state that `family_code` remains active,
/// registered, unrevoked, and unexpired for both its grant family and current
/// access token. Fails closed on missing, corrupted, or interrupted state.
pub fn verify_active_family(
    dir: &Path,
    oauth_client: &str,
    local_client: &str,
    family_code: &str,
) -> Result<(), Error> {
    active_family_guard(dir, oauth_client, local_client, family_code).map(drop)
}

pub fn verify_active_family_with_mode(
    dir: &Path,
    oauth_client: &str,
    local_client: &str,
    family_code: &str,
    required_yolo: bool,
) -> Result<(), Error> {
    active_family_guard_with_mode(dir, oauth_client, local_client, family_code, required_yolo)
        .map(drop)
}

/// Retain the shared lock through the actual admitted action. Writers publish
/// the durable interrupted intent exclusively before changing grant state.
pub fn active_family_guard(
    dir: &Path,
    oauth_client: &str,
    local_client: &str,
    family_code: &str,
) -> Result<rustix::fd::OwnedFd, Error> {
    active_family_guard_with_mode(dir, oauth_client, local_client, family_code, false)
}

pub fn active_family_guard_with_mode(
    dir: &Path,
    oauth_client: &str,
    local_client: &str,
    family_code: &str,
    required_yolo: bool,
) -> Result<rustix::fd::OwnedFd, Error> {
    let store = Store::open_oauth_state_readonly(dir).map_err(|_| Error::Unavailable)?;
    let mut admitted = None;
    for attempt in 0..4 {
        if let Ok(guard) = store.oauth_admission_lock(false, false) {
            let parsed = unseal(&store.read().map_err(|_| Error::Unavailable)?)?;
            if parsed.interrupted.is_none() {
                admitted = Some((parsed, guard));
                break;
            }
            // Release the lock before allowing a writer to finish.
            drop(guard);
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let (snapshot, guard) = admitted.ok_or(Error::Unavailable)?;
    let now_ms = wall_ms()?;
    if snapshot.version != 1 || snapshot.saved_ms > now_ms {
        return Err(Error::Unavailable);
    }
    let origin = snapshot.registry["resource"]
        .as_str()
        .and_then(|s| s.strip_suffix("/mcp"))
        .ok_or(Error::InvalidRequest)?;
    let resource = Resource::new(origin).map_err(|_| Error::InvalidRequest)?;
    let registry =
        ClientRegistry::restore(resource, &snapshot.registry).map_err(|_| Error::InvalidRequest)?;
    let Some(registration) = registry.get(oauth_client) else {
        return Err(Error::InvalidGrant);
    };
    if required_yolo && registration.mode() != ConnectionMode::Yolo {
        return Err(Error::InvalidGrant);
    }
    let expected_code =
        crate::core::oauth::challenge_digest(family_code).ok_or(Error::InvalidRequest)?;
    let active = snapshot.families.iter().any(|family| {
        family.matches_active(oauth_client, local_client, &expected_code, now_ms)
            && family.matches_mode(required_yolo)
    });
    if active {
        Ok(guard)
    } else {
        Err(Error::InvalidGrant)
    }
}

/// Read non-secret connection summary from a stopped managed OAuth state directory.
pub(super) fn inspect_stopped_state(dir: &Path) -> Result<Value, String> {
    let store = Store::open_oauth_state_readonly(dir)?;
    let snapshot = unseal(&store.read()?).map_err(|_| "Invalid OAuth state")?;
    if snapshot.version != 1 || snapshot.interrupted.is_some() {
        return Err("Interrupted or unsupported OAuth state".into());
    }
    let now_ms = wall_ms().map_err(|_| "OAuth clock unavailable")?;
    let origin = snapshot.registry["resource"]
        .as_str()
        .and_then(|s| s.strip_suffix("/mcp"))
        .ok_or("Invalid saved OAuth origin")?;
    let resource = Resource::new(origin).map_err(|_| "Invalid saved OAuth origin")?;
    let registry = ClientRegistry::restore(resource, &snapshot.registry)
        .map_err(|_| "Invalid saved OAuth registrations")?;
    let registrations: Vec<Value> = registry
        .clients()
        .iter()
        .map(|client| {
            let mut active = 0usize;
            let mut active_yolo = 0usize;
            for family in snapshot
                .families
                .iter()
                .filter(|f| f.client() == client.client_id() && f.is_unexpired(now_ms))
            {
                active += 1;
                if family.mode() == ConnectionMode::Yolo {
                    active_yolo += 1;
                }
            }
            json!({
                "client_id": client.client_id(),
                "client_name": client.client_name(),
                "redirect_uris": client.redirects(),
                "mode": client.mode().as_str(),
                "active_families": active,
                "active_yolo_families": active_yolo,
            })
        })
        .collect();
    Ok(json!({
        "origin": origin,
        "registrations": registrations,
    }))
}

/// Revoke a single OAuth client from a stopped managed profile cleanly.
pub(super) fn revoke_stopped_client(
    dir: &Path,
    local: &str,
    oauth_client: &str,
) -> Result<bool, String> {
    let store = Store::open_oauth_state(dir)?;
    let snapshot = unseal(&store.read()?).map_err(|_| "Invalid OAuth state")?;
    let origin = snapshot.registry["resource"]
        .as_str()
        .and_then(|s| s.strip_suffix("/mcp"))
        .ok_or("Invalid saved OAuth origin")?;
    let resource = Resource::new(origin).map_err(|_| "Invalid saved OAuth origin")?;
    let (mut durable, mut registry, mut grants) = Durable::open_locked(
        store,
        resource,
        local,
        &snapshot.binding,
        None,
        false,
        false,
    )?;
    if registry.get(oauth_client).is_none() {
        return Ok(false);
    }
    let now = Instant::now();
    let epoch = durable
        .begin("revoke", now)
        .map_err(|_| "Cannot publish client logout intent")?;
    registry.revoke_local(oauth_client, &mut grants);
    durable
        .finish(
            Transition {
                operation: "revoke",
                status: 200,
                client: Some(oauth_client.to_owned()),
                now,
                epoch,
            },
            &registry,
            &grants,
        )
        .map_err(|_| "Cannot confirm durable client logout".to_owned())?;
    Ok(true)
}

/// Persistently switch one stopped OAuth client between Standard and YOLO.
/// Escalation revokes existing Standard grants so the client must re-authorize.
/// Downgrade immediately clamps existing grant families to Standard.
pub(super) fn switch_stopped_client_mode(
    dir: &Path,
    local: &str,
    oauth_client: &str,
    target_mode: ConnectionMode,
) -> Result<(ConnectionMode, bool), String> {
    let store = Store::open_oauth_state(dir)?;
    let snapshot = unseal(&store.read()?).map_err(|_| "Invalid OAuth state")?;
    let origin = snapshot.registry["resource"]
        .as_str()
        .and_then(|s| s.strip_suffix("/mcp"))
        .ok_or("Invalid saved OAuth origin")?;
    let resource = Resource::new(origin).map_err(|_| "Invalid saved OAuth origin")?;
    let (mut durable, mut registry, mut grants) = Durable::open_locked(
        store,
        resource,
        local,
        &snapshot.binding,
        None,
        false,
        false,
    )?;
    let Some(previous) = registry.set_mode(oauth_client, target_mode) else {
        return Err("Unknown OAuth client".into());
    };
    let mut reauth_required = false;
    match target_mode {
        ConnectionMode::Yolo => {
            if previous != ConnectionMode::Yolo {
                grants.revoke_oauth_client(oauth_client);
                reauth_required = true;
            }
        }
        ConnectionMode::Standard => {
            grants.downgrade_oauth_client(oauth_client);
        }
    }
    let now = Instant::now();
    let epoch = durable
        .begin("mode", now)
        .map_err(|_| "Cannot publish mode switch intent")?;
    durable
        .finish(
            Transition {
                operation: "mode",
                status: 200,
                client: Some(oauth_client.to_owned()),
                now,
                epoch,
            },
            &registry,
            &grants,
        )
        .map_err(|_| "Cannot confirm durable mode switch".to_owned())?;
    Ok((previous, reauth_required))
}

/// Persistently switch every stopped OAuth registration between Standard and
/// YOLO in a single durable transaction.
pub(super) fn switch_all_stopped_clients_mode(
    dir: &Path,
    local: &str,
    target_mode: ConnectionMode,
) -> Result<Vec<(String, ConnectionMode, bool)>, String> {
    let store = Store::open_oauth_state(dir)?;
    let snapshot = unseal(&store.read()?).map_err(|_| "Invalid OAuth state")?;
    let origin = snapshot.registry["resource"]
        .as_str()
        .and_then(|s| s.strip_suffix("/mcp"))
        .ok_or("Invalid saved OAuth origin")?;
    let resource = Resource::new(origin).map_err(|_| "Invalid saved OAuth origin")?;
    let (mut durable, mut registry, mut grants) = Durable::open_locked(
        store,
        resource,
        local,
        &snapshot.binding,
        None,
        false,
        false,
    )?;
    let previous = registry.set_all_modes(target_mode);
    let mut results = Vec::with_capacity(previous.len());
    for (id, prev) in previous {
        let mut reauth_required = false;
        match target_mode {
            ConnectionMode::Yolo => {
                if prev != ConnectionMode::Yolo {
                    grants.revoke_oauth_client(&id);
                    reauth_required = true;
                }
            }
            ConnectionMode::Standard => {
                grants.downgrade_oauth_client(&id);
            }
        }
        results.push((id, prev, reauth_required));
    }
    let now = Instant::now();
    let epoch = durable
        .begin("mode", now)
        .map_err(|_| "Cannot publish bulk mode switch intent")?;
    durable
        .finish(
            Transition {
                operation: "mode",
                status: 200,
                client: None,
                now,
                epoch,
            },
            &registry,
            &grants,
        )
        .map_err(|_| "Cannot confirm durable bulk mode switch".to_owned())?;
    Ok(results)
}

/// Copy and re-bind a verified stopped OAuth durable state directory into a
/// unified destination directory without modifying the original files or
/// weakening issuer/family/revocation integrity.
pub(super) fn rebind_migrated_state(
    source_dir: &Path,
    dest_dir: &Path,
    local: &str,
    expected_old_bindings: &[&str],
    new_binding: &str,
) -> Result<String, String> {
    let source_store = Store::open_oauth_state_readonly(source_dir)?;
    let raw_sealed = source_store.read()?;
    let snapshot = unseal(&raw_sealed).map_err(|_| "Invalid OAuth state checksum or schema")?;
    if snapshot.version != 1 || snapshot.interrupted.is_some() {
        return Err("Interrupted or unsupported OAuth state cannot be migrated".into());
    }
    if !expected_old_bindings
        .iter()
        .any(|expected| snapshot.binding == *expected)
    {
        return Err("OAuth durable binding mismatch on source profile".into());
    }
    let now_ms = wall_ms().map_err(|_| "OAuth clock unavailable")?;
    if snapshot.saved_ms > now_ms {
        return Err("OAuth clock rollback detected on source state".into());
    }
    let origin = snapshot.registry["resource"]
        .as_str()
        .and_then(|s| s.strip_suffix("/mcp"))
        .ok_or("Invalid saved OAuth resource")?;
    let resource = Resource::new(origin).map_err(|_| "Invalid saved OAuth origin")?;
    let registry = ClientRegistry::restore(resource, &snapshot.registry)
        .map_err(|_| "Invalid OAuth registrations in source state")?;
    let _grants = GrantStore::restore(
        snapshot.families,
        snapshot.saved_ms,
        now_ms,
        Instant::now(),
        local,
        |c, d, r| registry.binding(c, d, r).is_ok(),
    )
    .map_err(|_| "Invalid OAuth grant families in source state")?;

    let mut rebound = unseal(&raw_sealed).map_err(|_| "Invalid OAuth state checksum or schema")?;
    rebound.binding = new_binding.to_owned();
    let sealed = seal(&rebound).map_err(|_| "Cannot seal migrated OAuth state")?;
    let dest_store = Store::open_oauth_state(dest_dir)?;
    dest_store.write(&sealed, true)?;
    Ok(origin.to_owned())
}

/// Revoke a stopped managed profile while holding its exclusive lifetime
/// lock. Uses the normal audited durable intent/finish protocol.
pub(super) fn revoke_stopped_profile(dir: &Path, local: &str) -> Result<(), String> {
    let store = Store::open_oauth_state(dir)?;
    let snapshot = unseal(&store.read()?).map_err(|_| "Invalid OAuth state")?;
    let origin = snapshot.registry["resource"]
        .as_str()
        .and_then(|s| s.strip_suffix("/mcp"))
        .ok_or("Invalid saved OAuth origin")?;
    let resource = Resource::new(origin).map_err(|_| "Invalid saved OAuth origin")?;
    let empty =
        ClientRegistry::new(Resource::new(origin).map_err(|_| "Invalid saved OAuth origin")?);
    let (mut durable, _registry, _grants) =
        Durable::open_locked(store, resource, local, &snapshot.binding, None, false, true)?;
    let now = Instant::now();
    let epoch = durable
        .begin("revoke", now)
        .map_err(|_| "Cannot publish logout intent")?;
    durable
        .finish(
            Transition {
                operation: "revoke",
                status: 200,
                client: None,
                now,
                epoch,
            },
            &empty,
            &GrantStore::default(),
        )
        .map_err(|_| "Cannot confirm durable logout".to_owned())
}

pub(super) struct Durable {
    store: Store,
    previous: Value,
    binding: String,
    saved_ms: u64,
    anchor: (Instant, u64),
    audit: Vec<Receipt>,
}

impl Durable {
    #[cfg(test)]
    pub(super) fn open(
        dir: &Path,
        resource: Resource,
        local: &str,
        binding: &str,
        initialize: bool,
    ) -> Result<(Self, ClientRegistry, GrantStore), String> {
        Self::open_with_legacy(dir, resource, local, binding, None, initialize)
    }

    pub(super) fn open_with_legacy(
        dir: &Path,
        resource: Resource,
        local: &str,
        binding: &str,
        legacy_binding: Option<&str>,
        initialize: bool,
    ) -> Result<(Self, ClientRegistry, GrantStore), String> {
        let store = Store::open_oauth_state(dir)?;
        Self::open_locked(
            store,
            resource,
            local,
            binding,
            legacy_binding,
            initialize,
            false,
        )
    }

    fn open_locked(
        store: Store,
        resource: Resource,
        local: &str,
        binding: &str,
        legacy_binding: Option<&str>,
        initialize: bool,
        recover_logout: bool,
    ) -> Result<(Self, ClientRegistry, GrantStore), String> {
        let now = Instant::now();
        let epoch = wall_ms().map_err(|_| "OAuth clock unavailable")?;
        if initialize {
            let snapshot = Snapshot {
                version: 1,
                binding: binding.into(),
                saved_ms: epoch,
                interrupted: None,
                registry: ClientRegistry::new(
                    Resource::new(
                        resource
                            .resource()
                            .strip_suffix("/mcp")
                            .ok_or("Invalid resource")?,
                    )
                    .map_err(|_| "Invalid resource")?,
                )
                .snapshot(),
                families: Vec::new(),
                audit: Vec::new(),
            };
            let sealed = seal(&snapshot).map_err(|_| "OAuth state serialization failed")?;
            store.write(&sealed, true)?;
        }
        let mut previous = store.read()?;
        let snapshot = unseal(&previous).map_err(|_| "Invalid OAuth state checksum or schema")?;
        let legacy_match = snapshot.binding != binding
            && snapshot.interrupted.is_none()
            && legacy_binding.is_some_and(|old| snapshot.binding == old);
        if snapshot.version != 1
            || (snapshot.binding != binding && !legacy_match)
            || snapshot.saved_ms > epoch
            // Only an explicit stopped-profile logout may complete an interrupted
            // revoke. Normal startup must never recover an authorized family.
            || (snapshot.interrupted.is_some() && !(recover_logout && snapshot.interrupted.as_deref() == Some("revoke")))
            || snapshot.audit.len() > AUDIT_LIMIT
            || !valid_audit(&snapshot.audit, snapshot.saved_ms)
        {
            return Err(
                "OAuth state binding, clock, audit or interrupted transition invalid".into(),
            );
        }
        let migrated_payload = if legacy_match {
            let mut next: Snapshot = serde_json::from_value(previous["payload"].clone())
                .map_err(|_| "Invalid OAuth state checksum or schema")?;
            next.binding = binding.to_owned();
            Some(seal(&next).map_err(|_| "OAuth state serialization failed")?)
        } else {
            None
        };
        let registry = ClientRegistry::restore(resource, &snapshot.registry)
            .map_err(|_| "Invalid OAuth registrations")?;
        let grants = GrantStore::restore(
            snapshot.families,
            snapshot.saved_ms,
            epoch,
            now,
            local,
            |c, d, r| registry.binding(c, d, r).is_ok(),
        )
        .map_err(|_| "Invalid OAuth grant families")?;
        if let Some(sealed) = migrated_payload {
            store.write(&sealed, false)?;
            previous = sealed;
        }
        Ok((
            Self {
                store,
                previous,
                binding: binding.into(),
                saved_ms: snapshot.saved_ms,
                anchor: (now, epoch),
                audit: snapshot.audit,
            },
            registry,
            grants,
        ))
    }

    // Fail closed on large clock steps in either direction (including
    // suspend on clocks that do not count suspended time). Restart uses
    // absolute persisted deadlines rather than granting fresh lifetimes.
    pub(super) fn clock(&self, now: Instant) -> Result<u64, Error> {
        let elapsed = u64::try_from(now.saturating_duration_since(self.anchor.0).as_millis())
            .map_err(|_| Error::Unavailable)?;
        let projected = self
            .anchor
            .1
            .checked_add(elapsed)
            .ok_or(Error::Unavailable)?;
        checked_clock(projected, self.saved_ms, wall_ms()?)
    }

    pub(super) fn begin(&mut self, operation: &str, now: Instant) -> Result<u64, Error> {
        let epoch = self.clock(now)?;
        if !operation_valid(operation)
            || self.store.read().map_err(|_| Error::Unavailable)? != self.previous
        {
            return Err(Error::Unavailable);
        }
        let mut snapshot = unseal(&self.previous)?;
        snapshot.interrupted = Some(operation.into());
        let marked = seal(&snapshot)?;
        self.store
            .write(&marked, false)
            .map_err(|_| Error::Unavailable)?;
        if self.store.read().map_err(|_| Error::Unavailable)? != marked {
            return Err(Error::Unavailable);
        }
        self.previous = marked;
        Ok(epoch)
    }

    pub(super) fn finish(
        &mut self,
        transition: Transition<'_>,
        registry: &ClientRegistry,
        grants: &GrantStore,
    ) -> Result<(), Error> {
        self.clock(Instant::now())?;
        let Transition {
            operation,
            status,
            client,
            now,
            epoch,
        } = transition;
        let sequence = self
            .audit
            .last()
            .map_or(Some(1), |r| r.sequence.checked_add(1))
            .ok_or(Error::Unavailable)?;
        let mut audit = self.audit.clone();
        if audit.len() == AUDIT_LIMIT {
            audit.remove(0);
        }
        audit.push(Receipt {
            sequence,
            unix_ms: epoch,
            operation: operation.into(),
            status,
            client,
        });
        let snapshot = Snapshot {
            version: 1,
            binding: self.binding.clone(),
            saved_ms: epoch,
            interrupted: None,
            registry: registry.snapshot(),
            families: grants.snapshot(now, epoch)?,
            audit,
        };
        let sealed = seal(&snapshot)?;
        if self.store.read().map_err(|_| Error::Unavailable)? != self.previous {
            return Err(Error::Unavailable);
        }
        self.store
            .write(&sealed, false)
            .map_err(|_| Error::Unavailable)?;
        if self.store.read().map_err(|_| Error::Unavailable)? != sealed {
            return Err(Error::Unavailable);
        }
        self.previous = sealed;
        self.audit = snapshot.audit;
        self.saved_ms = epoch;
        Ok(())
    }
}

pub(super) struct Transition<'a> {
    pub operation: &'a str,
    pub status: u16,
    pub client: Option<String>,
    pub now: Instant,
    pub epoch: u64,
}

fn valid_audit(audit: &[Receipt], saved_ms: u64) -> bool {
    audit.iter().all(|r| {
        r.sequence > 0
            && r.unix_ms <= saved_ms
            && operation_valid(&r.operation)
            && (200..=599).contains(&r.status)
            && r.client
                .as_ref()
                .is_none_or(|c| crate::core::credential::token_shape(c))
    }) && audit.windows(2).all(|w| {
        w[0].sequence.checked_add(1) == Some(w[1].sequence) && w[0].unix_ms <= w[1].unix_ms
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_rejects_large_steps_and_saved_time_rollback() {
        assert_eq!(checked_clock(10_000, 9_000, 10_001), Ok(10_000));
        assert!(checked_clock(10_000, 9_000, 8_999).is_err());
        assert!(checked_clock(10_000, 0, 7_999).is_err());
        assert!(checked_clock(10_000, 9_000, 12_001).is_err());
    }

    #[test]
    fn verify_active_family_enforces_sealed_state_expiry_and_revocation() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!(
            "veyl-durable-test-{}-{}",
            std::process::id(),
            crate::core::session::random_id::<8>().unwrap()
        ));
        let state_dir = base.join("oauth");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let origin = "https://veyl.example";
        let resource = Resource::new(origin).unwrap();
        let local = "oauth-preview";
        let binding = "test-binding";

        let (durable, mut registry, mut grants) =
            Durable::open(&state_dir, resource, local, binding, true).unwrap();
        let now = Instant::now();
        let registered = registry
            .register(
                "TestClient",
                &["https://client.example/cb"],
                "none",
                &["authorization_code", "refresh_token"],
                &["code"],
                SCOPE,
            )
            .unwrap();
        let client_id = registered.client_id().to_owned();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let auth_req = crate::core::oauth::AuthorizationRequest::new(
            registry
                .binding(
                    &client_id,
                    "https://client.example/cb",
                    "https://veyl.example/mcp",
                )
                .unwrap(),
            challenge,
            "S256",
            None,
        )
        .unwrap();
        let pending = grants.begin(auth_req, now).unwrap();
        let approved = grants.approve_local(&pending, local, now).unwrap();
        let issued = grants
            .exchange(
                &approved.code,
                &registry
                    .binding(
                        &client_id,
                        "https://client.example/cb",
                        "https://veyl.example/mcp",
                    )
                    .unwrap(),
                verifier,
                now,
            )
            .unwrap();
        let id = grants
            .authenticate(&issued.access_token, "https://veyl.example/mcp", now)
            .unwrap();
        let family_code = URL_SAFE_NO_PAD.encode(id.family);

        let epoch = durable.clock(now).unwrap();
        let mut durable = durable;
        durable
            .finish(
                Transition {
                    operation: "exchange",
                    status: 200,
                    client: Some(client_id.clone()),
                    now,
                    epoch,
                },
                &registry,
                &grants,
            )
            .unwrap();
        drop(durable);

        assert!(verify_active_family(&state_dir, &client_id, local, &family_code).is_ok());
        assert!(matches!(
            verify_active_family(&state_dir, "wrong-client", local, &family_code),
            Err(Error::InvalidGrant)
        ));
        assert!(matches!(
            verify_active_family(&state_dir, &client_id, "wrong-local", &family_code),
            Err(Error::InvalidGrant)
        ));
        assert!(matches!(
            verify_active_family(
                &state_dir,
                &client_id,
                local,
                &URL_SAFE_NO_PAD.encode([7u8; 32])
            ),
            Err(Error::InvalidGrant)
        ));

        let (mut reopened, _, _) = Durable::open(
            &state_dir,
            Resource::new(origin).unwrap(),
            local,
            binding,
            false,
        )
        .unwrap();
        // Deterministically inspect both lock directions, then exercise the
        // real durable intent writer while an admitted action holds its guard.
        let admission = active_family_guard(&state_dir, &client_id, local, &family_code)
            .expect("active admission");
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(state_dir.join(".oauth-admission-lock"))
            .unwrap();
        assert_eq!(
            rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        let begin_epoch = std::thread::scope(|scope| {
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let state = &mut reopened;
            let writer = scope.spawn(move || {
                started_tx.send(()).unwrap();
                done_tx
                    .send(state.begin("refresh", Instant::now()))
                    .unwrap();
            });
            started_rx.recv().unwrap();
            let blocked = done_rx.recv_timeout(Duration::from_millis(30));
            drop(admission);
            assert!(matches!(
                blocked,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            let epoch = done_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            writer.join().unwrap();
            epoch
        });
        {
            let exclusive = reopened.store.oauth_admission_lock(true, false).unwrap();
            assert!(matches!(
                active_family_guard(&state_dir, &client_id, local, &family_code),
                Err(Error::Unavailable)
            ));
            drop(exclusive);
        }
        assert!(matches!(
            verify_active_family(&state_dir, &client_id, local, &family_code),
            Err(Error::Unavailable)
        ));
        reopened
            .finish(
                Transition {
                    operation: "refresh",
                    status: 400,
                    client: Some(client_id.clone()),
                    now: Instant::now() + Duration::from_secs(1000),
                    epoch: begin_epoch,
                },
                &registry,
                &grants,
            )
            .unwrap();
        assert!(matches!(
            verify_active_family(&state_dir, &client_id, local, &family_code),
            Err(Error::InvalidGrant)
        ));

        let state_file = state_dir.join("oauth-state.json");
        let mut raw: Value = serde_json::from_slice(&std::fs::read(&state_file).unwrap()).unwrap();
        raw["sha256"] = json!("0".repeat(64));
        std::fs::write(&state_file, raw.to_string()).unwrap();
        assert!(verify_active_family(&state_dir, &client_id, local, &family_code).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn stopped_mode_switch_and_family_mode_enforcement() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!(
            "veyl-durable-mode-test-{}-{}",
            std::process::id(),
            crate::core::session::random_id::<8>().unwrap()
        ));
        let state_dir = base.join("oauth");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let origin = "https://veyl.example";
        let local = "oauth-preview";
        let binding = "test-binding";
        let (mut durable, mut registry, mut grants) = Durable::open(
            &state_dir,
            Resource::new(origin).unwrap(),
            local,
            binding,
            true,
        )
        .unwrap();
        let now = Instant::now();
        let client_id = registry
            .register(
                "ModeClient",
                &["https://client.example/cb"],
                "none",
                &["authorization_code", "refresh_token"],
                &["code"],
                SCOPE,
            )
            .unwrap()
            .client_id()
            .to_owned();
        let binding_obj = registry
            .binding(
                &client_id,
                "https://client.example/cb",
                "https://veyl.example/mcp",
            )
            .unwrap();
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let req = crate::core::oauth::AuthorizationRequest::new(
            binding_obj.clone(),
            challenge,
            "S256",
            None,
        )
        .unwrap();
        let handle = grants.begin(req, now).unwrap();
        let approved = grants
            .approve_local_with_mode(&handle, local, ConnectionMode::Yolo, now)
            .unwrap();
        registry.set_mode(&client_id, ConnectionMode::Yolo);
        let issued = grants
            .exchange(&approved.code, &binding_obj, verifier, now)
            .unwrap();
        let id = grants
            .authenticate(&issued.access_token, "https://veyl.example/mcp", now)
            .unwrap();
        let family_code = URL_SAFE_NO_PAD.encode(id.family);
        let epoch = durable.clock(now).unwrap();
        durable
            .finish(
                Transition {
                    operation: "exchange",
                    status: 200,
                    client: Some(client_id.clone()),
                    now,
                    epoch,
                },
                &registry,
                &grants,
            )
            .unwrap();
        drop(durable);

        assert!(
            verify_active_family_with_mode(&state_dir, &client_id, local, &family_code, true)
                .is_ok()
        );
        // Downgrade immediately rejects required_yolo=true while allowing standard checks.
        let (prev, reauth) =
            switch_stopped_client_mode(&state_dir, local, &client_id, ConnectionMode::Standard)
                .unwrap();
        assert_eq!(prev, ConnectionMode::Yolo);
        assert!(!reauth);
        assert!(matches!(
            verify_active_family_with_mode(&state_dir, &client_id, local, &family_code, true),
            Err(Error::InvalidGrant)
        ));
        assert!(
            verify_active_family_with_mode(&state_dir, &client_id, local, &family_code, false)
                .is_ok()
        );

        // Escalation revokes existing Standard family so fresh OAuth auth is required.
        let (prev, reauth) =
            switch_stopped_client_mode(&state_dir, local, &client_id, ConnectionMode::Yolo)
                .unwrap();
        assert_eq!(prev, ConnectionMode::Standard);
        assert!(reauth);
        assert!(matches!(
            verify_active_family_with_mode(&state_dir, &client_id, local, &family_code, false),
            Err(Error::InvalidGrant)
        ));

        let _ = std::fs::remove_dir_all(&base);
    }
}
