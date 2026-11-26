//! Existing Veyl bearer wire format, shared by platform adapters.
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn token_shape(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

pub fn token_digest(token: &str) -> Option<[u8; 32]> {
    token_shape(token).then(|| Sha256::digest(token.as_bytes()).into())
}

pub fn decode_sha256(value: &str) -> Result<[u8; 32], String> {
    if !token_shape(value) {
        return Err("invalid token verifier encoding".into());
    }
    let mut digest = [0_u8; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
            .map_err(|_| "invalid token verifier encoding")?;
    }
    Ok(digest)
}

/// Evaluate all verifiers; adapter supplies eligibility (revocation, expiry).
/// Reject duplicate active matches rather than selecting an ambiguous identity.
pub fn select_client(
    candidate: &[u8; 32],
    clients: impl IntoIterator<Item = ([u8; 32], bool)>,
) -> Option<usize> {
    let mut found = None;
    let mut ambiguous = false;
    for (index, (digest, enabled)) in clients.into_iter().enumerate() {
        let matched = bool::from(digest.ct_eq(candidate));
        if matched && enabled {
            ambiguous |= found.is_some();
            found = Some(index);
        }
    }
    if ambiguous { None } else { found }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_compatibility_and_malformed_values() {
        let token = "a".repeat(64);
        let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        assert_eq!(token_digest(&token), Some(decode_sha256(&hash).unwrap()));
        for bad in ["", "abc", &"A".repeat(64), &"g".repeat(64), &"é".repeat(32)] {
            assert!(token_digest(bad).is_none());
            assert!(decode_sha256(bad).is_err());
        }
    }
    #[test]
    fn selection_checks_eligibility_and_ambiguity() {
        let a = [1; 32];
        let b = [2; 32];
        assert_eq!(select_client(&a, [(b, true), (a, true)]), Some(1));
        assert_eq!(select_client(&a, [(a, false), (b, true)]), None);
        assert_eq!(select_client(&a, [(a, true), (a, true)]), None);
        assert_eq!(select_client(&a, [(a, false), (a, true)]), Some(1));
        let mut visits = 0;
        assert_eq!(
            select_client(
                &a,
                [(a, true), (b, false)].into_iter().inspect(|_| visits += 1)
            ),
            Some(0)
        );
        assert_eq!(visits, 2);
    }
}
