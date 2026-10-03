//! [`AuthGate`]: the per-request decision.
//!
//! Decision for a request whose route is `(method, template)` in the
//! server's final [`RouteTable`] (read from the request's
//! `Extension<Arc<RouteTable>>`, so routes added by any plugin are covered):
//!
//! 1. *(PeerGuard stage, before anything is parsed)* the client address
//!    (`honest_client_ip` over the trusted proxies) is banned → `403 ip_banned`.
//! 2. The route is not in the table, or the table / matched path is missing
//!    → refuse (`401 unauthorized`, or `500 gate_misconfigured` when the
//!    server did not inject the table): fail closed.
//! 3. The route is `Public` with no scope → admitted anonymously.
//! 4. Candidate doors = doors whose policy admits `(method, template)`
//!    (restricted to one door with [`AuthGate::layer_for`]).
//! 5. Credential: `Authorization: Bearer <key>` (scheme case-insensitive,
//!    exactly one space, no trimming); `?api_key=` only if a candidate door
//!    allows it.
//! 6. Identity: the key's SHA-256 is compared with **every** ring record in
//!    constant time, expired records ignored; if none matches, the
//!    [`AuthChain`] layers are asked. A layer `Reject` refuses.
//! 7. Nothing presented and no layer identified the caller: a loopback
//!    caller (loopback peer, no forwarding headers) gets the loopback grant
//!    of a candidate door that has one; otherwise `401 missing_credential`.
//! 8. Authorize: some grant of the identity names a candidate door, its
//!    tier satisfies the route's tier and its scopes contain the route's
//!    scope → admitted; the [`Principal`] goes into request extensions and
//!    mutating verbs are recorded to the [`AuditSink`] with the final status.
//! 9. Otherwise → `401 unauthorized`, byte-identical for an unknown key, an
//!    expired key, a key for another door, a too-low tier and a missing
//!    scope; the failure is recorded in the [`AuthBan`] ledger.
//!
//! An empty key ring therefore refuses every credential.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tesserax::audit::{AuditEvent, AuditSink, NullAuditSink};
use tesserax::{
    CidrList, DoorName, HttpMethod, KeyId, Principal, Published, RouteEntry, RouteTable,
    honest_client_ip,
};

use crate::ban::AuthBan;
use crate::door::Door;
use crate::key::{Grant, KeyHash, KeyRing};
use crate::layer::{AuthChain, AuthOutcome};

const BODY_MISSING: &str = r#"{"ok":false,"error":"missing_credential"}"#;
const BODY_UNAUTHORIZED: &str = r#"{"ok":false,"error":"unauthorized"}"#;
const BODY_BANNED: &str = r#"{"ok":false,"error":"ip_banned"}"#;
const BODY_MISCONFIGURED: &str = r#"{"ok":false,"error":"gate_misconfigured"}"#;

/// Why a request was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denial {
    /// No credential was presented (401 `missing_credential`).
    MissingCredential,
    /// A credential was presented but does not admit this route (401
    /// `unauthorized`), or the route is unknown.
    Unauthorized,
    /// The server did not provide what the gate needs (500).
    Misconfigured,
}

impl Denial {
    /// The HTTP answer. Identical bytes for every cause of one kind.
    pub fn into_response(self) -> Response {
        let (status, body, challenge) = match self {
            Denial::MissingCredential => (StatusCode::UNAUTHORIZED, BODY_MISSING, true),
            Denial::Unauthorized => (StatusCode::UNAUTHORIZED, BODY_UNAUTHORIZED, true),
            Denial::Misconfigured => (StatusCode::INTERNAL_SERVER_ERROR, BODY_MISCONFIGURED, false),
        };
        json_response(status, body, challenge)
    }
}

fn json_response(status: StatusCode, body: &'static str, challenge: bool) -> Response {
    let mut resp = (status, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if challenge {
        h.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    resp
}

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Doors, key ring, optional credential layers, ban ledger and audit sink
/// of one server. Cheap to clone (shared parts are behind `Arc`).
#[derive(Clone)]
pub struct AuthGate {
    doors: Vec<Door>,
    ring: Arc<Published<KeyRing>>,
    chain: AuthChain,
    ban: Option<Arc<AuthBan>>,
    audit: Arc<dyn AuditSink>,
    trusted_proxies: CidrList,
    clock: Clock,
}

impl AuthGate {
    /// Gate over `ring` with no doors yet (which admits nothing but public
    /// routes).
    pub fn new(ring: KeyRing) -> Self {
        Self::with_shared_ring(Arc::new(Published::new(ring)))
    }

    /// Gate over a ring the caller keeps a handle to (for rotation).
    pub fn with_shared_ring(ring: Arc<Published<KeyRing>>) -> Self {
        Self {
            doors: Vec::new(),
            ring,
            chain: AuthChain::new(),
            ban: None,
            audit: Arc::new(NullAuditSink),
            trusted_proxies: CidrList::new(),
            clock: Arc::new(system_clock_ms),
        }
    }

    /// Adds a door.
    pub fn door(mut self, door: Door) -> Self {
        self.doors.push(door);
        self
    }

    /// Credential layers consulted when no ring key matched.
    pub fn chain(mut self, chain: AuthChain) -> Self {
        self.chain = chain;
        self
    }

    /// Records failures and refuses banned addresses.
    pub fn with_ban(mut self, ban: Arc<AuthBan>) -> Self {
        self.ban = Some(ban);
        self
    }

    /// Where admitted mutating requests are recorded.
    pub fn with_audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = sink;
        self
    }

    /// Proxies whose `X-Forwarded-For` / `X-Real-IP` are believed.
    pub fn trusted_proxies(mut self, list: CidrList) -> Self {
        self.trusted_proxies = list;
        self
    }

    /// Clock in Unix milliseconds (key expiry, audit timestamps).
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// The ring; store a new [`KeyRing`] into it to rotate keys.
    pub fn key_ring(&self) -> &Arc<Published<KeyRing>> {
        &self.ring
    }

    /// The ban ledger, if any.
    pub fn ban(&self) -> Option<&Arc<AuthBan>> {
        self.ban.as_ref()
    }

    /// Layer function for `LayerStage::TierGate` evaluating every door.
    pub fn tier_gate_layer(&self) -> impl FnOnce(Router) -> Router + Send + 'static {
        self.make_layer(None)
    }

    /// Layer function restricted to one door (for a sub-router that is
    /// only reachable through that door).
    pub fn layer_for(&self, door: &DoorName) -> impl FnOnce(Router) -> Router + Send + 'static {
        self.make_layer(Some(door.clone()))
    }

    fn make_layer(&self, only: Option<DoorName>) -> impl FnOnce(Router) -> Router + Send + 'static {
        let state = Arc::new((self.clone(), only));
        move |r: Router| r.route_layer(middleware::from_fn_with_state(state, gate_mw))
    }

    /// Layer function for `LayerStage::PeerGuard`: refuses banned client
    /// addresses before anything else runs. No-op without a ban ledger.
    pub fn peer_guard_layer(&self) -> impl FnOnce(Router) -> Router + Send + 'static {
        let gate = Arc::new(self.clone());
        move |r: Router| match gate.ban {
            Some(_) => r.layer(middleware::from_fn_with_state(gate, peer_guard_mw)),
            None => r,
        }
    }

    fn client_ip(&self, parts: &Parts) -> Option<IpAddr> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>()?.0.ip();
        let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
        Some(honest_client_ip(
            peer,
            &self.trusted_proxies,
            header("x-forwarded-for"),
            header("x-real-ip"),
        ))
    }

    fn record_failure(&self, parts: &Parts) {
        tracing::info!(target: "tesserax_auth", "credential refused");
        if let (Some(ban), Some(ip)) = (&self.ban, self.client_ip(parts))
            && ban.record_failure(ip)
        {
            tracing::warn!(target: "tesserax_auth", %ip, "address banned after repeated failures");
        }
    }

    /// Decides one request for route `entry` (steps 3-9 above). `Ok(None)`
    /// admits anonymously, `Ok(Some(p))` admits as `p`.
    pub async fn check(
        &self,
        parts: &Parts,
        entry: &RouteEntry,
        only: Option<&DoorName>,
    ) -> Result<Option<Principal>, Denial> {
        if entry.tier == tesserax::Tier::Public && entry.scope.is_none() {
            return Ok(None);
        }
        let doors: Vec<&Door> = self
            .doors
            .iter()
            .filter(|d| only.is_none_or(|o| o.as_str() == d.name.as_str()))
            .filter(|d| d.policy.admits(entry.method, &entry.path))
            .collect();

        let has_auth_header = parts.headers.contains_key(header::AUTHORIZATION);
        let mut credential = bearer_token(&parts.headers);
        if credential.is_none() && doors.iter().any(|d| d.allow_query_key) {
            credential = query_key(parts.uri.query());
        }
        let presented = has_auth_header || credential.is_some();

        let mut identity: Option<(KeyId, Vec<Grant>)> = None;
        if let Some(cred) = credential {
            let now = (self.clock)();
            let ring = self.ring.load();
            if let Some(r) = ring.find(&KeyHash::of_raw(cred)).filter(|r| r.is_live(now)) {
                identity = Some((r.id.clone(), r.grants.clone()));
            }
        }
        if identity.is_none() && !self.chain.is_empty() {
            match self.chain.resolve(parts).await {
                AuthOutcome::Grant { key_id, grants } => identity = Some((key_id, grants)),
                AuthOutcome::Reject { .. } => {
                    self.record_failure(parts);
                    return Err(Denial::Unauthorized);
                }
                AuthOutcome::Abstain => {}
            }
        }
        let (key_id, grants) = match identity {
            Some(i) => i,
            None if presented => {
                self.record_failure(parts);
                return Err(Denial::Unauthorized);
            }
            None => {
                let loopback = doors
                    .iter()
                    .find_map(|d| d.loopback_grant.as_ref().map(|(t, s)| (d, t, s)))
                    .filter(|_| is_plain_loopback(parts));
                match (loopback, KeyId::new("loopback")) {
                    (Some((d, tier, scopes)), Ok(id)) => (
                        id,
                        vec![Grant {
                            door: d.name.clone(),
                            tier: *tier,
                            scopes: scopes.clone(),
                        }],
                    ),
                    _ => return Err(Denial::MissingCredential),
                }
            }
        };

        let admitted = grants.into_iter().find(|g| {
            doors.iter().any(|d| d.name.as_str() == g.door.as_str())
                && g.tier.satisfies(entry.tier)
                && entry.scope.as_ref().is_none_or(|s| g.scopes.contains(s))
        });
        match admitted {
            Some(g) => Ok(Some(Principal {
                key_id,
                door: g.door,
                tier: g.tier,
                scopes: g.scopes,
            })),
            None => {
                self.record_failure(parts);
                Err(Denial::Unauthorized)
            }
        }
    }
}

impl std::fmt::Debug for AuthGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthGate")
            .field(
                "doors",
                &self
                    .doors
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("keys", &self.ring.load().len())
            .field("chain", &self.chain)
            .field("ban", &self.ban.is_some())
            .finish_non_exhaustive()
    }
}

/// `Authorization: Bearer <key>`: scheme case-insensitive, one space,
/// non-empty key, no surrounding whitespace accepted.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || rest.is_empty()
        || rest.contains(char::is_whitespace)
    {
        return None;
    }
    Some(rest)
}

fn query_key(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("api_key="))
        .filter(|v| !v.is_empty())
}

/// Loopback peer and no forwarding headers (a reverse proxy on the same
/// host would otherwise make every caller look local).
fn is_plain_loopback(parts: &Parts) -> bool {
    let peer_local = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|c| c.0.ip().is_loopback());
    peer_local
        && !["x-forwarded-for", "x-real-ip", "forwarded"]
            .iter()
            .any(|h| parts.headers.contains_key(*h))
}

fn route_method(m: &axum::http::Method) -> Option<HttpMethod> {
    HttpMethod::parse(m.as_str())
}

fn is_mutating(m: HttpMethod) -> bool {
    matches!(
        m,
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch | HttpMethod::Delete
    )
}

async fn gate_mw(
    State(state): State<Arc<(AuthGate, Option<DoorName>)>>,
    req: Request,
    next: Next,
) -> Response {
    let (gate, only) = (&state.0, state.1.as_ref());
    let (mut parts, body) = req.into_parts();
    let (Some(table), Some(matched)) = (
        parts.extensions.get::<Arc<RouteTable>>().cloned(),
        parts.extensions.get::<MatchedPath>().cloned(),
    ) else {
        tracing::error!(target: "tesserax_auth", "route table or matched path missing; refusing");
        return Denial::Misconfigured.into_response();
    };
    let entry = route_method(&parts.method).and_then(|m| {
        table.lookup(m, matched.as_str()).or_else(|| {
            (m == HttpMethod::Head)
                .then(|| table.lookup(HttpMethod::Get, matched.as_str()))
                .flatten()
        })
    });
    let Some(entry) = entry.cloned() else {
        return Denial::Unauthorized.into_response();
    };
    match gate.check(&parts, &entry, only).await {
        Err(denial) => denial.into_response(),
        Ok(None) => next.run(Request::from_parts(parts, body)).await,
        Ok(Some(principal)) => {
            let audit = is_mutating(entry.method).then(|| AuditEvent {
                ts_ms: (gate.clock)(),
                door: principal.door.to_string(),
                principal: Some(principal.key_id.to_string()),
                client: gate.client_ip(&parts).map(|ip| ip.to_string()),
                verb: entry.method.as_str().to_owned(),
                target: parts.uri.path().to_owned(),
                status: 0,
            });
            parts.extensions.insert(principal);
            let resp = next.run(Request::from_parts(parts, body)).await;
            if let Some(mut ev) = audit {
                ev.status = resp.status().as_u16();
                gate.audit.record(ev);
            }
            resp
        }
    }
}

async fn peer_guard_mw(State(gate): State<Arc<AuthGate>>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    if let (Some(ban), Some(ip)) = (&gate.ban, gate.client_ip(&parts))
        && ban.is_banned(ip)
    {
        tracing::info!(target: "tesserax_auth", %ip, "banned address refused");
        return json_response(StatusCode::FORBIDDEN, BODY_BANNED, false);
    }
    next.run(Request::from_parts(parts, body)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(
            bearer_token(&headers(&[("authorization", "Bearer abc")])),
            Some("abc")
        );
        assert_eq!(
            bearer_token(&headers(&[("authorization", "bEaReR abc")])),
            Some("abc")
        );
        assert_eq!(
            bearer_token(&headers(&[("authorization", "Bearer  abc")])),
            None
        );
        assert_eq!(
            bearer_token(&headers(&[("authorization", "Bearer abc ")])),
            None
        );
        assert_eq!(
            bearer_token(&headers(&[("authorization", "Bearer ")])),
            None
        );
        assert_eq!(
            bearer_token(&headers(&[("authorization", "Basic abc")])),
            None
        );
        assert_eq!(
            bearer_token(&headers(&[("authorization", "Bearerabc")])),
            None
        );
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn query_parsing() {
        assert_eq!(query_key(Some("a=1&api_key=k")), Some("k"));
        assert_eq!(query_key(Some("api_key=")), None);
        assert_eq!(query_key(None), None);
    }
}
