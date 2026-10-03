//! Security middleware. Each guard is a state object plus an axum
//! middleware function for `axum::middleware::from_fn_with_state`;
//! [`HttpExt`](crate::HttpExt) installs them at their
//! [`LayerStage`](tesserax::LayerStage).
//!
//! | guard | stage | refusal |
//! |---|---|---|
//! | [`cors_policy`] | `Decorate` | (CORS headers) |
//! | [`SecurityHeaders`] | `Decorate` | (response headers) |
//! | [`csrf_mw`] | `Csrf` | 403 `csrf_token_invalid` |
//! | [`ip_acl_mw`] | `PeerGuard` | 403 `ip_not_admitted` |
//! | [`conn_cap_mw`] | `PeerGuard` | 503 `too_many_concurrent` |
//! | [`rate_limit_mw`] | `PeerGuard` | 429 `rate_limited` |
//! | [`tier_rate_limit_mw`] | `TierRateLimit` | 429 `rate_limited` |
//! | [`idempotency_mw`] | `Idempotency` (inside the gate; keyed by Principal) | 409 `idempotency_in_flight` |
//! | [`WebhookVerifier`] | (handler step) | 401 |
//! | `response_signing_mw` (feature `signing`) | `ResponseSigning` | (response headers) |
//!
//! Every guard that keys on the caller's address uses
//! [`tesserax::honest_client_ip`] with its own trusted-proxy list, so a
//! forwarding header from an untrusted peer is ignored. HMAC and every
//! comparison of secret material go through [`tesserax::ct`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::Json;
use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tesserax::{CidrList, honest_client_ip};

mod conn_cap;
mod cors;
mod csrf;
mod headers;
mod idempotency;
mod ip_acl;
mod rate_limit;
#[cfg(feature = "signing")]
mod signing;
mod tier_rate_limit;
mod webhook;

pub use conn_cap::{ConnCap, ConnGuard, conn_cap_mw};
pub use cors::{CorsPolicy, cors_policy};
pub use csrf::{CSRF_COOKIE, CSRF_HEADER, CsrfState, csrf_mw};
pub use headers::SecurityHeaders;
pub use idempotency::{
    IDEMPOTENCY_KEY, IDEMPOTENT_REPLAYED, IdempotencyConfig, IdempotencyStore, idempotency_mw,
};
pub use ip_acl::{IpAcl, ip_acl_mw};
pub use rate_limit::{RateLimit, RateLimitState, rate_limit_mw};
#[cfg(feature = "signing")]
pub use signing::response_signing_mw;
pub use tier_rate_limit::{TierRateLimit, TierRateLimitPolicy, tier_rate_limit_mw};
pub use webhook::{WEBHOOK_SIGNATURE, WEBHOOK_TIMESTAMP, WebhookVerifier};

/// The caller's address: the transport peer (`ConnectInfo`, unspecified
/// when absent), with forwarding headers honoured only from `trusted`.
pub fn client_ip(req: &Request, trusted: &CidrList) -> IpAddr {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let h = req.headers();
    honest_client_ip(
        peer,
        trusted,
        h.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
        h.get("x-real-ip").and_then(|v| v.to_str().ok()),
    )
}

/// `{"ok":false,"error":<code>}` with `status`.
pub(crate) fn refuse(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({"ok": false, "error": code})),
    )
        .into_response()
}

/// Seconds since the Unix epoch (0 if the clock is before it).
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
