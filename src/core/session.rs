//! Shared session identity and lifetime; admission is adapter-owned.
use std::time::{Duration, Instant};

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(1800);

pub struct OwnedSession<O, S, P> {
    owner: O,
    scope: S,
    last_used: Instant,
    pub protocol: P,
}

impl<O: PartialEq, S: PartialEq, P> OwnedSession<O, S, P> {
    pub fn new(owner: O, scope: S, protocol: P) -> Self {
        Self {
            owner,
            scope,
            last_used: Instant::now(),
            protocol,
        }
    }
    pub fn belongs_to(&self, owner: &O, scope: &S) -> bool {
        &self.owner == owner && &self.scope == scope
    }
    pub fn owner(&self) -> &O {
        &self.owner
    }
    pub fn scope(&self) -> &S {
        &self.scope
    }
    pub fn is_live(&self) -> bool {
        self.last_used.elapsed() < IDLE_TIMEOUT
    }
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}

pub fn random_id<const N: usize>() -> Result<String, getrandom::Error> {
    use std::fmt::Write;
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)?;
    let mut id = String::with_capacity(N * 2);
    for byte in bytes {
        let _ = write!(id, "{byte:02x}");
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_scope_and_expiry() {
        let mut session = OwnedSession::new("alice", false, 42);
        assert!(session.belongs_to(&"alice", &false));
        assert!(!session.belongs_to(&"bob", &false));
        assert!(!session.belongs_to(&"alice", &true));
        assert!(session.is_live());
        session.last_used = Instant::now() - IDLE_TIMEOUT;
        assert!(!session.is_live());
        session.touch();
        assert!(session.is_live());
        assert_eq!(session.protocol, 42);
    }
    #[test]
    fn wire_lengths() {
        let a = random_id::<24>().unwrap();
        let b = random_id::<32>().unwrap();
        assert_eq!(a.len(), 48);
        assert_eq!(b.len(), 64);
        assert!(
            a.bytes()
                .chain(b.bytes())
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
}
