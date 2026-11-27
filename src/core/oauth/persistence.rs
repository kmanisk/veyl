//! Active grant snapshots only. Pending consent and unredeemed codes never
//! survive restart. All bearer material is represented by SHA-256 digests.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Family {
    client: String,
    redirect: String,
    resource: String,
    local_client: String,
    #[serde(default)]
    mode: ConnectionMode,
    challenge: String,
    code: String,
    access: String,
    refresh: String,
    spent: Vec<String>,
    access_until_ms: u64,
    family_until_ms: u64,
}

impl Family {
    pub(crate) fn matches_active(
        &self,
        oauth_client: &str,
        local_client: &str,
        expected_code: &Digest32,
        now_ms: u64,
    ) -> bool {
        self.client == oauth_client
            && self.local_client == local_client
            && self.access_until_ms > now_ms
            && self.family_until_ms > now_ms
            && decode(&self.code).is_ok_and(|code| same(&code, expected_code))
    }

    pub(crate) fn matches_mode(&self, required_yolo: bool) -> bool {
        !required_yolo || self.mode == ConnectionMode::Yolo
    }

    pub(crate) fn client(&self) -> &str {
        &self.client
    }

    pub(crate) fn mode(&self) -> ConnectionMode {
        self.mode
    }

    pub(crate) fn is_unexpired(&self, now_ms: u64) -> bool {
        self.family_until_ms > now_ms && self.access_until_ms > now_ms
    }
}

fn encode(digest: &Digest32) -> String {
    URL_SAFE_NO_PAD.encode(digest)
}
fn decode(value: &str) -> Result<Digest32, Error> {
    challenge_digest(value).ok_or(Error::InvalidRequest)
}
fn deadline(until: Instant, now: Instant, epoch_ms: u64) -> Result<u64, Error> {
    epoch_ms
        .checked_add(
            u64::try_from(until.saturating_duration_since(now).as_millis())
                .map_err(|_| Error::Unavailable)?,
        )
        .ok_or(Error::Unavailable)
}

impl GrantStore {
    pub(crate) fn snapshot(&self, now: Instant, epoch_ms: u64) -> Result<Vec<Family>, Error> {
        self.entries
            .iter()
            .filter_map(|entry| {
                let Stage::Active {
                    code,
                    local_client,
                    mode,
                    access,
                    refresh,
                    spent_refresh,
                    access_until,
                    family_until,
                } = &entry.stage
                else {
                    return None;
                };
                if *family_until <= now {
                    return None;
                }
                Some((|| {
                    Ok(Family {
                        client: entry.request.binding.client_id.clone(),
                        redirect: entry.request.binding.redirect_uri.clone(),
                        resource: entry.request.binding.resource.clone(),
                        local_client: local_client.clone(),
                        mode: *mode,
                        challenge: encode(&entry.request.challenge),
                        code: encode(code),
                        access: encode(access),
                        refresh: encode(refresh),
                        spent: spent_refresh.iter().map(encode).collect(),
                        access_until_ms: deadline(*access_until, now, epoch_ms)?,
                        family_until_ms: deadline(*family_until, now, epoch_ms)?,
                    })
                })())
            })
            .collect()
    }

    pub(crate) fn restore(
        families: Vec<Family>,
        saved_ms: u64,
        epoch_ms: u64,
        now: Instant,
        local: &str,
        validate: impl Fn(&str, &str, &str) -> bool,
    ) -> Result<Self, Error> {
        if saved_ms > epoch_ms || families.len() > MAX_GRANTS {
            return Err(Error::InvalidRequest);
        }
        let mut store = Self::default();
        let mut digests = BTreeSet::new();
        for family in families {
            if family.local_client != local
                || !bounded(local, 128)
                || !validate(&family.client, &family.redirect, &family.resource)
                || family.spent.len() > MAX_ROTATIONS
                || family.family_until_ms < saved_ms
                || family.family_until_ms - saved_ms > FAMILY_TTL.as_millis() as u64
                || family.access_until_ms > family.family_until_ms
                || family.access_until_ms.saturating_sub(saved_ms) > ACCESS_TTL.as_millis() as u64
            {
                return Err(Error::InvalidRequest);
            }
            let code = decode(&family.code)?;
            let access = decode(&family.access)?;
            let refresh = decode(&family.refresh)?;
            let spent: Vec<_> = family
                .spent
                .iter()
                .map(|v| decode(v))
                .collect::<Result<_, _>>()?;
            let challenge = decode(&family.challenge)?;
            for digest in [code, access, refresh]
                .into_iter()
                .chain(spent.iter().copied())
            {
                if !digests.insert(digest) {
                    return Err(Error::InvalidRequest);
                }
            }
            let binding = Binding::new(&family.client, &family.redirect, &family.resource)?;
            if family.family_until_ms <= epoch_ms {
                continue;
            }
            let family_until = now
                .checked_add(Duration::from_millis(family.family_until_ms - epoch_ms))
                .ok_or(Error::InvalidRequest)?;
            let access_until = now
                .checked_add(Duration::from_millis(
                    family.access_until_ms.saturating_sub(epoch_ms),
                ))
                .ok_or(Error::InvalidRequest)?;
            store.entries.push(Entry {
                request: AuthorizationRequest {
                    binding,
                    challenge,
                    state: None,
                },
                stage: Stage::Active {
                    code,
                    local_client: family.local_client,
                    mode: family.mode,
                    access,
                    refresh,
                    spent_refresh: spent,
                    access_until,
                    family_until,
                },
            });
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const V: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const C: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const R: &str = "https://node.example/mcp";
    const D: &str = "https://client.example/callback";
    fn binding() -> Binding {
        Binding::new("client", D, R).unwrap()
    }
    fn valid(c: &str, d: &str, r: &str) -> bool {
        c == "client" && d == D && r == R
    }
    fn issue(s: &mut GrantStore, t: Instant) -> (String, Tokens) {
        let h = s
            .begin(
                AuthorizationRequest::new(binding(), C, "S256", None).unwrap(),
                t,
            )
            .unwrap();
        let c = s.approve_local(&h, "local", t).unwrap().code;
        let tokens = s.exchange(&c, &binding(), V, t).unwrap();
        (c, tokens)
    }
    #[test]
    fn restart_preserves_replay_history_and_family_identity() {
        let t = Instant::now();
        let mut s = GrantStore::default();
        let (code, a) = issue(&mut s, t);
        let b = s.refresh(&a.refresh_token, "client", R, t).unwrap();
        let family = s.authenticate(&b.access_token, R, t).unwrap().family;
        let snapshot = s.snapshot(t, 1_000_000).unwrap();
        let raw = serde_json::to_string(&snapshot).unwrap();
        for secret in [
            &code,
            &a.access_token,
            &a.refresh_token,
            &b.access_token,
            &b.refresh_token,
            V,
        ] {
            assert!(!raw.contains(secret));
        }
        let mut resumed =
            GrantStore::restore(snapshot, 1_000_000, 1_001_000, t, "local", valid).unwrap();
        assert_eq!(
            resumed.authenticate(&b.access_token, R, t).unwrap().family,
            family
        );
        assert!(resumed.authenticate(&a.access_token, R, t).is_none());
        assert!(resumed.refresh(&a.refresh_token, "client", R, t).is_err());
        assert!(resumed.authenticate(&b.access_token, R, t).is_none());
        assert!(resumed.snapshot(t, 1_001_000).unwrap().is_empty());
    }
    #[test]
    fn restore_checks_expiry_clock_binding_and_duplicate_digests() {
        let t = Instant::now();
        let mut s = GrantStore::default();
        let (code, a) = issue(&mut s, t);
        let snap = || s.snapshot(t, 1_000_000).unwrap();
        assert!(GrantStore::restore(snap(), 1_000_000, 999_999, t, "local", valid).is_err());
        assert!(GrantStore::restore(snap(), 1_000_000, 1_000_000, t, "other", valid).is_err());
        assert!(
            GrantStore::restore(snap(), 1_000_000, 1_000_000, t, "local", |_, _, _| false).is_err()
        );
        let mut malformed = snap();
        malformed[0].refresh = malformed[0].access.clone();
        assert!(GrantStore::restore(malformed, 1_000_000, 1_000_000, t, "local", valid).is_err());
        let mut malformed = snap();
        malformed[0].family_until_ms += 1;
        assert!(GrantStore::restore(malformed, 1_000_000, 1_000_000, t, "local", valid).is_err());
        let mut expired =
            GrantStore::restore(snap(), 1_000_000, 1_900_000, t, "local", valid).unwrap();
        assert!(expired.authenticate(&a.access_token, R, t).is_none());
        let b = expired.refresh(&a.refresh_token, "client", R, t).unwrap();
        assert!(expired.exchange(&code, &binding(), V, t).is_err());
        assert!(expired.authenticate(&b.access_token, R, t).is_none());
        let expired =
            GrantStore::restore(snap(), 1_000_000, 87_400_000, t, "local", valid).unwrap();
        assert!(expired.snapshot(t, 87_400_000).unwrap().is_empty());
    }
}
