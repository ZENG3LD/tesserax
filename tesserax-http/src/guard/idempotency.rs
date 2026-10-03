//! `Idempotency-Key` replay cache for state-changing requests.
//!
//! A `POST` / `PUT` / `PATCH` / `DELETE` carrying `Idempotency-Key: <k>`
//! is keyed by `(caller, method, path, k)`, where the caller is the
//! `tesserax::Principal` the auth gate admitted (door + key id) or, for a
//! request admitted without one (a `Public` route), the honest client
//! address ([`tesserax::honest_client_ip`] with the configured trusted
//! proxies). Two different keys that send the same `Idempotency-Key`
//! therefore never share a stored response, and a key is never shared
//! with anonymous callers from the same address.
//!
//! The middleware runs at `LayerStage::Idempotency`, a route-scoped stage
//! inside `TierGate` and `TierRateLimit` (installed with
//! `Router::route_layer`), so the Principal is already in the request
//! extensions and a rate-limited (429) request never claims a slot.
//! Routes added with `merge_router` are not covered.
//!
//! - first time: the handler runs; its response (status, headers, body) is
//!   stored for `ttl` when the status is not 5xx and the body length is
//!   known and at most `max_body_bytes` (otherwise it is passed through
//!   and not stored);
//! - while that first request is still running, the same key is refused
//!   with `409 {"ok":false,"error":"idempotency_in_flight"}` (two
//!   concurrent retries never both execute);
//! - afterwards, the stored response is replayed with
//!   `x-idempotent-replayed: true`.
//!
//! A key longer than 255 bytes is refused with
//! `400 {"ok":false,"error":"idempotency_key_invalid"}`. The cache is
//! bounded by `max_entries` (oldest evicted first) and expired entries are
//! dropped on access.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes, HttpBody, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tesserax::{CidrList, Principal};

use super::{client_ip, refuse};

/// Request header.
pub const IDEMPOTENCY_KEY: &str = "idempotency-key";
/// Response header set on a replay.
pub const IDEMPOTENT_REPLAYED: &str = "x-idempotent-replayed";

const MAX_KEY_LEN: usize = 255;

/// Cache limits.
#[derive(Clone, Debug)]
pub struct IdempotencyConfig {
    /// How long a stored response is replayed.
    pub ttl: Duration,
    /// Larger responses are not stored.
    pub max_body_bytes: usize,
    /// Entries kept at most.
    pub max_entries: usize,
    /// Proxies whose forwarding headers are believed.
    pub trusted_proxies: CidrList,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(86_400),
            max_body_bytes: 256 * 1024,
            max_entries: 4096,
            trusted_proxies: CidrList::new(),
        }
    }
}

#[derive(Clone)]
struct Stored {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

enum Slot {
    InFlight(u64),
    Done(Stored),
}

struct Entry {
    id: String,
    expires_at: Instant,
    slot: Slot,
}

/// The cache. Share by `Arc`.
pub struct IdempotencyStore {
    cfg: IdempotencyConfig,
    entries: Mutex<VecDeque<Entry>>,
    next_ticket: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for IdempotencyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdempotencyStore")
            .field("ttl", &self.cfg.ttl)
            .field("max_body_bytes", &self.cfg.max_body_bytes)
            .field("len", &self.len())
            .finish()
    }
}

enum Lookup {
    Replay(Stored),
    InFlight,
    Claimed(u64),
}

impl IdempotencyStore {
    /// An empty cache.
    pub fn new(cfg: IdempotencyConfig) -> Self {
        Self {
            cfg,
            entries: Mutex::new(VecDeque::new()),
            next_ticket: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Entries held (in flight or stored).
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// True iff nothing is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn claim(&self, id: &str, now: Instant) -> Lookup {
        let mut q = self.lock();
        q.retain(|e| e.expires_at > now);
        if let Some(e) = q.iter().find(|e| e.id == id) {
            return match &e.slot {
                Slot::Done(s) => Lookup::Replay(s.clone()),
                Slot::InFlight(_) => Lookup::InFlight,
            };
        }
        while q.len() >= self.cfg.max_entries.max(1) {
            q.pop_front();
        }
        let ticket = self
            .next_ticket
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        q.push_back(Entry {
            id: id.to_owned(),
            expires_at: now + self.cfg.ttl,
            slot: Slot::InFlight(ticket),
        });
        Lookup::Claimed(ticket)
    }

    fn complete(&self, id: &str, ticket: u64, stored: Option<Stored>) {
        let mut q = self.lock();
        let pos = q
            .iter()
            .position(|e| e.id == id && matches!(e.slot, Slot::InFlight(t) if t == ticket));
        if let Some(i) = pos {
            match stored {
                Some(s) => {
                    if let Some(e) = q.get_mut(i) {
                        e.slot = Slot::Done(s);
                        e.expires_at = Instant::now() + self.cfg.ttl;
                    }
                }
                None => {
                    q.remove(i);
                }
            }
        }
    }
}

/// Releases an in-flight claim if the handler never completes (panic,
/// cancelled request).
struct Claim<'a> {
    store: &'a IdempotencyStore,
    id: String,
    ticket: u64,
    done: bool,
}

impl Claim<'_> {
    fn finish(mut self, stored: Option<Stored>) {
        self.store.complete(&self.id, self.ticket, stored);
        self.done = true;
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.store.complete(&self.id, self.ticket, None);
        }
    }
}

fn is_state_changing(m: &Method) -> bool {
    matches!(
        *m,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// The caller part of the cache key: `p:<door>/<key id>` for an admitted
/// Principal, `ip:<address>` otherwise. The prefixes keep the two spaces
/// apart, and door / key-id names (`[A-Za-z0-9._:-]`) contain neither `/`
/// nor `|`, so no two callers map to one key.
fn caller_id(req: &Request, trusted: &CidrList) -> String {
    match req.extensions().get::<Principal>() {
        Some(p) => format!("p:{}/{}", p.door, p.key_id),
        None => format!("ip:{}", client_ip(req, trusted)),
    }
}

/// The middleware (`Router::route_layer(from_fn_with_state(Arc<IdempotencyStore>, idempotency_mw))`
/// at `LayerStage::Idempotency`).
pub async fn idempotency_mw(
    State(store): State<Arc<IdempotencyStore>>,
    req: Request,
    next: Next,
) -> Response {
    if !is_state_changing(req.method()) {
        return next.run(req).await;
    }
    let key = match req.headers().get(IDEMPOTENCY_KEY).map(|v| v.to_str()) {
        None => return next.run(req).await,
        Some(Ok(k)) if !k.is_empty() && k.len() <= MAX_KEY_LEN => k.to_owned(),
        Some(_) => return refuse(StatusCode::BAD_REQUEST, "idempotency_key_invalid"),
    };
    let caller = caller_id(&req, &store.cfg.trusted_proxies);
    let composite = format!("{caller}|{}|{}|{key}", req.method(), req.uri().path());

    let ticket = match store.claim(&composite, Instant::now()) {
        Lookup::Replay(s) => {
            tracing::debug!(%caller, "idempotency replay");
            let mut resp = Response::new(Body::from(s.body));
            *resp.status_mut() = s.status;
            *resp.headers_mut() = s.headers;
            resp.headers_mut()
                .insert(IDEMPOTENT_REPLAYED, HeaderValue::from_static("true"));
            return resp;
        }
        Lookup::InFlight => return refuse(StatusCode::CONFLICT, "idempotency_in_flight"),
        Lookup::Claimed(t) => t,
    };
    let claim = Claim {
        store: &store,
        id: composite,
        ticket,
        done: false,
    };

    let resp = next.run(req).await;
    let cacheable_len = resp
        .body()
        .size_hint()
        .exact()
        .filter(|n| *n <= store.cfg.max_body_bytes as u64);
    if resp.status().is_server_error() || cacheable_len.is_none() {
        claim.finish(None);
        return resp;
    }
    let (parts, body) = resp.into_parts();
    match to_bytes(body, store.cfg.max_body_bytes).await {
        Ok(bytes) => {
            claim.finish(Some(Stored {
                status: parts.status,
                headers: parts.headers.clone(),
                body: bytes.clone(),
            }));
            Response::from_parts(parts, Body::from(bytes))
        }
        Err(e) => {
            claim.finish(None);
            tracing::warn!(error = %e, "idempotency: response body failed");
            refuse(StatusCode::INTERNAL_SERVER_ERROR, "response_body_failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::middleware::from_fn_with_state;
    use axum::routing::post;
    use tower::ServiceExt;

    fn cfg(max_entries: usize) -> IdempotencyConfig {
        IdempotencyConfig {
            max_entries,
            ..IdempotencyConfig::default()
        }
    }

    #[test]
    fn claim_then_replay_then_expire() {
        let s = IdempotencyStore::new(cfg(8));
        let t0 = Instant::now();
        let Lookup::Claimed(t) = s.claim("k", t0) else {
            panic!()
        };
        assert!(matches!(s.claim("k", t0), Lookup::InFlight));
        s.complete(
            "k",
            t,
            Some(Stored {
                status: StatusCode::CREATED,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"{\"id\":42}"),
            }),
        );
        match s.claim("k", Instant::now()) {
            Lookup::Replay(st) => assert_eq!(st.status, StatusCode::CREATED),
            _ => panic!("expected replay"),
        }
        assert!(matches!(
            s.claim("k", Instant::now() + Duration::from_secs(90_000)),
            Lookup::Claimed(_)
        ));
    }

    #[test]
    fn bounded_fifo() {
        let s = IdempotencyStore::new(cfg(3));
        for i in 0..5 {
            let _ = s.claim(&format!("k{i}"), Instant::now());
        }
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn dropped_claim_is_released() {
        let s = IdempotencyStore::new(cfg(8));
        let Lookup::Claimed(t) = s.claim("k", Instant::now()) else {
            panic!()
        };
        drop(Claim {
            store: &s,
            id: "k".into(),
            ticket: t,
            done: false,
        });
        assert!(s.is_empty());
    }

    #[tokio::test]
    async fn replays_through_the_middleware() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        let store = Arc::new(IdempotencyStore::new(IdempotencyConfig::default()));
        let app = Router::new()
            .route(
                "/pay",
                post(move || {
                    let n = h.fetch_add(1, Ordering::SeqCst) + 1;
                    async move { (StatusCode::CREATED, format!("charge {n}")) }
                }),
            )
            .layer(from_fn_with_state(store, idempotency_mw));
        let call = |key: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut b = axum::http::Request::post("/pay");
                if let Some(k) = key {
                    b = b.header(IDEMPOTENCY_KEY, k);
                }
                let resp = app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
                let replayed = resp.headers().contains_key(IDEMPOTENT_REPLAYED);
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap();
                (status, String::from_utf8(body.to_vec()).unwrap(), replayed)
            }
        };
        assert_eq!(
            call(Some("a")).await,
            (StatusCode::CREATED, "charge 1".into(), false)
        );
        assert_eq!(
            call(Some("a")).await,
            (StatusCode::CREATED, "charge 1".into(), true)
        );
        assert_eq!(call(Some("b")).await.1, "charge 2");
        assert_eq!(call(None).await.1, "charge 3");
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        let long: &'static str = Box::leak("x".repeat(300).into_boxed_str());
        assert_eq!(call(Some(long)).await.0, StatusCode::BAD_REQUEST);
    }
}
