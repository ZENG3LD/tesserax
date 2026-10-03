//! Token-bucket rate limit per `(caller address, class)`, in memory.
//!
//! A bucket holds up to `burst` tokens and refills at `rate_per_sec`; each
//! request takes one. The caller's address is the honest one (forwarding
//! headers only from trusted proxies), so a spoofed `X-Forwarded-For` does
//! not buy a fresh bucket. State is process-local; call
//! [`RateLimitState::sweep`] periodically to drop idle buckets. Refusal:
//! `429 {"ok":false,"error":"rate_limited"}`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use tesserax::CidrList;

use super::{client_ip, refuse};

struct Bucket {
    last_refill: Instant,
    tokens: f64,
}

/// The buckets. Share one between limits by `Arc`.
#[derive(Default)]
pub struct RateLimitState {
    buckets: Mutex<HashMap<(IpAddr, &'static str), Bucket>>,
}

impl std::fmt::Debug for RateLimitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitState")
            .field("buckets", &self.len())
            .finish()
    }
}

impl RateLimitState {
    /// No buckets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes one token from `(ip, class)`; false if none is left.
    pub fn allow(&self, ip: IpAddr, class: &'static str, rate_per_sec: f64, burst: f64) -> bool {
        self.allow_at(ip, class, rate_per_sec, burst, Instant::now())
    }

    fn allow_at(
        &self,
        ip: IpAddr,
        class: &'static str,
        rate: f64,
        burst: f64,
        now: Instant,
    ) -> bool {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let b = map.entry((ip, class)).or_insert(Bucket {
            last_refill: now,
            tokens: burst,
        });
        let elapsed = now.saturating_duration_since(b.last_refill).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rate).min(burst);
        b.last_refill = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drops buckets idle for `idle` or longer; returns how many.
    pub fn sweep(&self, idle: Duration) -> usize {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let before = map.len();
        map.retain(|_, b| now.saturating_duration_since(b.last_refill) < idle);
        before - map.len()
    }

    /// Buckets tracked.
    pub fn len(&self) -> usize {
        self.buckets.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// True iff no bucket is tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One limit: class, rate, burst, trusted proxies. Cheap to clone.
#[derive(Clone, Debug)]
pub struct RateLimit {
    state: Arc<RateLimitState>,
    class: &'static str,
    rate_per_sec: f64,
    burst: f64,
    trusted_proxies: Arc<CidrList>,
}

impl RateLimit {
    /// `rate_per_sec` refill, `burst` capacity, buckets named `class`.
    pub fn new(
        state: Arc<RateLimitState>,
        class: &'static str,
        rate_per_sec: f64,
        burst: f64,
    ) -> Self {
        Self {
            state,
            class,
            rate_per_sec,
            burst,
            trusted_proxies: Arc::new(CidrList::new()),
        }
    }

    /// Proxies whose forwarding headers are believed.
    pub fn trusted_proxies(mut self, list: CidrList) -> Self {
        self.trusted_proxies = Arc::new(list);
        self
    }

    /// The shared buckets.
    pub fn state(&self) -> &Arc<RateLimitState> {
        &self.state
    }
}

/// The middleware (`from_fn_with_state(limit, rate_limit_mw)`).
pub async fn rate_limit_mw(State(limit): State<RateLimit>, req: Request, next: Next) -> Response {
    let ip = client_ip(&req, &limit.trusted_proxies);
    if limit
        .state
        .allow(ip, limit.class, limit.rate_per_sec, limit.burst)
    {
        next.run(req).await
    } else {
        tracing::warn!(%ip, class = limit.class, "rate limit exceeded");
        refuse(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn drains_then_refills() {
        let st = RateLimitState::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(st.allow_at(ip, "t", 1.0, 3.0, t0));
        }
        assert!(!st.allow_at(ip, "t", 1.0, 3.0, t0));
        assert!(st.allow_at(ip, "t", 1.0, 3.0, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn buckets_are_independent() {
        let st = RateLimitState::new();
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        assert!(st.allow(a, "x", 0.0, 1.0));
        assert!(!st.allow(a, "x", 0.0, 1.0));
        assert!(st.allow(b, "x", 0.0, 1.0));
        assert!(st.allow(a, "y", 0.0, 1.0));
        assert_eq!(st.len(), 3);
        assert_eq!(st.sweep(Duration::ZERO), 3);
        assert!(st.is_empty());
    }

    /// 10k concurrent takes from one bucket of burst 100: exactly 100 pass.
    #[test]
    fn stress_exactly_burst_admitted() {
        let st = Arc::new(RateLimitState::new());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let started = Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let st = Arc::clone(&st);
                std::thread::spawn(move || {
                    (0..1250).filter(|_| st.allow(ip, "s", 0.0, 100.0)).count()
                })
            })
            .collect();
        let admitted: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(admitted, 100);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
