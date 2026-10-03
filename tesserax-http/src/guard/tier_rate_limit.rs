//! Rate limit by the tier of the admitted caller.
//!
//! Installed at `LayerStage::TierRateLimit`, inside the auth gate, so the
//! `tesserax::Principal` the gate admitted is in the request extensions;
//! a request without one (public route, no credential) is `anonymous`.
//! Buckets are keyed by `(address, class)` so an anonymous flood on one
//! address does not spend an administrator's budget. Refusal:
//! `429 {"ok":false,"error":"rate_limited"}`.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use tesserax::{CidrList, Principal, Tier};

use super::rate_limit::RateLimitState;
use super::{client_ip, refuse};

/// Rates per class (tokens per second, burst).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TierRateLimitPolicy {
    /// No principal.
    pub anonymous: (f64, f64),
    /// `Public` or `Authenticated` principal.
    pub authenticated: (f64, f64),
    /// `Admin` or `Root` principal.
    pub admin: (f64, f64),
}

impl Default for TierRateLimitPolicy {
    fn default() -> Self {
        Self {
            anonymous: (10.0, 30.0),
            authenticated: (100.0, 300.0),
            admin: (1000.0, 3000.0),
        }
    }
}

/// Policy + buckets. Cheap to clone.
#[derive(Clone, Debug)]
pub struct TierRateLimit {
    state: Arc<RateLimitState>,
    policy: TierRateLimitPolicy,
    trusted_proxies: Arc<CidrList>,
}

impl TierRateLimit {
    /// A limit over `state` with `policy`.
    pub fn new(state: Arc<RateLimitState>, policy: TierRateLimitPolicy) -> Self {
        Self {
            state,
            policy,
            trusted_proxies: Arc::new(CidrList::new()),
        }
    }

    /// Proxies whose forwarding headers are believed.
    pub fn trusted_proxies(mut self, list: CidrList) -> Self {
        self.trusted_proxies = Arc::new(list);
        self
    }

    /// Class name and `(rate, burst)` for a caller.
    pub fn classify(&self, principal: Option<&Principal>) -> (&'static str, (f64, f64)) {
        match principal.map(|p| p.tier) {
            None => ("anonymous", self.policy.anonymous),
            Some(t) if t >= Tier::Admin => ("admin", self.policy.admin),
            Some(_) => ("authenticated", self.policy.authenticated),
        }
    }
}

/// The middleware (`route_layer(from_fn_with_state(limit, tier_rate_limit_mw))`).
pub async fn tier_rate_limit_mw(
    State(limit): State<TierRateLimit>,
    req: Request,
    next: Next,
) -> Response {
    let (class, (rate, burst)) = limit.classify(req.extensions().get::<Principal>());
    let ip = client_ip(&req, &limit.trusted_proxies);
    if limit.state.allow(ip, class, rate, burst) {
        next.run(req).await
    } else {
        tracing::warn!(%ip, class, "tier rate limit exceeded");
        refuse(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tesserax::{DoorName, KeyId, ScopeSet};

    fn principal(tier: Tier) -> Principal {
        Principal {
            key_id: KeyId::new("k").unwrap(),
            door: DoorName::new("d").unwrap(),
            tier,
            scopes: ScopeSet::new(),
        }
    }

    #[test]
    fn classes() {
        let l = TierRateLimit::new(
            Arc::new(RateLimitState::new()),
            TierRateLimitPolicy::default(),
        );
        assert_eq!(l.classify(None).0, "anonymous");
        assert_eq!(
            l.classify(Some(&principal(Tier::Authenticated))).0,
            "authenticated"
        );
        assert_eq!(l.classify(Some(&principal(Tier::Admin))).0, "admin");
        assert_eq!(l.classify(Some(&principal(Tier::Root))).1, (1000.0, 3000.0));
    }
}
