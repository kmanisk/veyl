//! Shared HTTP parsing; endpoint-specific admission stays in adapters.
use crate::core::credential::token_digest;
use hyper::header::{HeaderMap, HeaderValue};

pub fn one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    one_value(headers, name)?.to_str().ok()
}

/// Preserve the original header bytes while rejecting ambiguous cardinality.
pub fn one_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

pub fn bearer(value: &HeaderValue) -> Option<[u8; 32]> {
    bearer_text(value.to_str().ok()?)
}

pub fn bearer_text(value: &str) -> Option<[u8; 32]> {
    token_digest(value.strip_prefix("Bearer ")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::AUTHORIZATION;
    #[test]
    fn duplicate_and_invalid_bearers() {
        let mut headers = HeaderMap::new();
        let token = format!("Bearer {}", "a".repeat(64));
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&token).unwrap());
        assert_eq!(
            bearer_text(one(&headers, "authorization").unwrap()),
            token_digest(&"a".repeat(64))
        );
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer invalid"));
        assert!(one(&headers, "authorization").is_none());
        assert!(bearer_text("Bearer invalid").is_none());
        assert!(bearer_text(&format!("bearer {}", "a".repeat(64))).is_none());
    }
}
