//! [`ConnCap`]: at most `max_per_ip` requests in flight per caller address
//! (slow-loris guard). The slot is taken with a compare-and-swap (never
//! above the cap, even transiently) and released when the response is
//! done. Refusal: `503 {"ok":false,"error":"too_many_concurrent"}`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use tesserax::CidrList;

use super::{client_ip, refuse};

/// Per-address in-flight counters.
pub struct ConnCap {
    counters: Mutex<HashMap<IpAddr, Arc<AtomicU32>>>,
    max_per_ip: u32,
    trusted_proxies: CidrList,
}

impl std::fmt::Debug for ConnCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnCap")
            .field("max_per_ip", &self.max_per_ip)
            .field("tracked_ips", &self.tracked_ips())
            .finish()
    }
}

/// A held slot; dropping it releases the slot.
#[derive(Debug)]
pub struct ConnGuard {
    counter: Arc<AtomicU32>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ConnCap {
    /// At most `max_per_ip` concurrent requests per address.
    pub fn new(max_per_ip: u32, trusted_proxies: CidrList) -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
            max_per_ip,
            trusted_proxies,
        }
    }

    /// Takes a slot for `ip`, or `None` at the cap.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnGuard> {
        let counter = {
            let mut map = self.counters.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(map.entry(ip).or_default())
        };
        let mut cur = counter.load(Ordering::SeqCst);
        loop {
            if cur >= self.max_per_ip {
                return None;
            }
            match counter.compare_exchange_weak(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(ConnGuard { counter }),
                Err(seen) => cur = seen,
            }
        }
    }

    /// Addresses tracked.
    pub fn tracked_ips(&self) -> usize {
        self.counters.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// In-flight requests of `ip`.
    pub fn current_for(&self, ip: IpAddr) -> u32 {
        self.counters
            .lock()
            .ok()
            .and_then(|m| m.get(&ip).map(|c| c.load(Ordering::SeqCst)))
            .unwrap_or(0)
    }

    /// Drops idle counters; returns how many.
    pub fn sweep(&self) -> usize {
        let mut map = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        let before = map.len();
        map.retain(|_, c| c.load(Ordering::SeqCst) > 0);
        before - map.len()
    }
}

/// The middleware (`from_fn_with_state(Arc<ConnCap>, conn_cap_mw)`).
pub async fn conn_cap_mw(State(cap): State<Arc<ConnCap>>, req: Request, next: Next) -> Response {
    let ip = client_ip(&req, &cap.trusted_proxies);
    let Some(_slot) = cap.try_acquire(ip) else {
        tracing::warn!(%ip, max = cap.max_per_ip, "concurrent request cap reached");
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "too_many_concurrent");
    };
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cap_release_sweep() {
        let st = ConnCap::new(2, CidrList::new());
        let a = st.try_acquire(ip("192.0.2.1")).unwrap();
        let _b = st.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(st.try_acquire(ip("192.0.2.1")).is_none());
        assert_eq!(st.current_for(ip("192.0.2.1")), 2);
        drop(a);
        assert!(st.try_acquire(ip("192.0.2.1")).is_some());
        let _v6 = st.try_acquire(ip("::1")).unwrap();
        assert_eq!(st.tracked_ips(), 2);
        drop(_v6);
        assert_eq!(st.sweep(), 1);
    }

    /// 16 threads hammering one address never observe more than the cap.
    #[test]
    fn stress_never_exceeds_cap() {
        const CAP: u32 = 10;
        let st = Arc::new(ConnCap::new(CAP, CidrList::new()));
        let target = ip("10.20.30.40");
        let max_seen = Arc::new(AtomicU32::new(0));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let st = Arc::clone(&st);
                let max_seen = Arc::clone(&max_seen);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        if let Some(_g) = st.try_acquire(target) {
                            max_seen.fetch_max(st.current_for(target), Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(max_seen.load(Ordering::SeqCst) <= CAP);
        assert_eq!(st.current_for(target), 0);
    }
}
