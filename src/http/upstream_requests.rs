use std::collections::{HashMap, hash_map::Entry};
use std::sync::{Arc, Mutex, Weak};

use hyper::StatusCode;
use serde_json::Value;

use crate::upstream::Cancellation;

// Every live entry is bound by a tool worker permit. Weak entries let the next
// caller prune stale request IDs without acquiring a lock from a destructor.
#[derive(Default)]
pub(super) struct Requests(Mutex<HashMap<(String, String), Weak<Cancellation>>>);

pub(super) struct RequestGuard(Arc<Cancellation>);

impl Requests {
    pub(super) fn start(
        &self,
        session: &str,
        request_id: String,
    ) -> Result<RequestGuard, (StatusCode, &'static str)> {
        let mut requests = self.0.lock().map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Upstream requests unavailable",
            )
        })?;
        requests.retain(|_, token| token.strong_count() != 0);
        let Entry::Vacant(entry) = requests.entry((session.to_owned(), request_id)) else {
            return Err((StatusCode::CONFLICT, "Upstream request ID already in use"));
        };
        let token = Arc::new(Cancellation::new().map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Upstream requests unavailable",
            )
        })?);
        entry.insert(Arc::downgrade(&token));
        Ok(RequestGuard(token))
    }

    pub(super) fn cancel(&self, session: &str, id: &Value) {
        let Some(id) = request_key(id) else {
            return;
        };
        if let Some(token) = self
            .0
            .lock()
            .ok()
            .and_then(|requests| requests.get(&(session.to_owned(), id))?.upgrade())
        {
            token.cancel();
        }
    }
}

pub(super) fn request_key(id: &Value) -> Option<String> {
    (id.is_string() || id.is_i64() || id.is_u64()).then(|| id.to_string())
}

impl RequestGuard {
    pub(super) fn token(&self) -> Arc<Cancellation> {
        Arc::clone(&self.0)
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if Arc::strong_count(&self.0) > 1 {
            self.0.cancel();
        }
    }
}
