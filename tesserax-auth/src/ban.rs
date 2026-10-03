//! [`AuthBan`]: temporary ban of client addresses after repeated
//! authentication failures.
//!
//! Only failures count (a rate limit counts every request). After
//! `max_failures` failures inside `window` an address is banned for
//! `ban_duration`; banned addresses are refused before any credential is
//! parsed. Failures are not forgiven on success; they age out of the window.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Thresholds of an [`AuthBan`].
#[derive(Clone, Copy, Debug)]
pub struct AuthBanConfig {
    /// Failures inside `window` that trigger a ban.
    pub max_failures: u32,
    /// Sliding window for counting failures.
    pub window: Duration,
    /// Length of a ban.
    pub ban_duration: Duration,
    /// Addresses tracked at most; beyond it stale entries are swept and, if
    /// still full, new addresses are not tracked until space frees up.
    pub max_tracked: usize,
}

impl Default for AuthBanConfig {
    /// 5 failures in 5 minutes ban for 15 minutes; 100 000 addresses.
    fn default() -> Self {
        Self {
            max_failures: 5,
            window: Duration::from_secs(300),
            ban_duration: Duration::from_secs(900),
            max_tracked: 100_000,
        }
    }
}

#[derive(Default)]
struct Entry {
    failures: VecDeque<Instant>,
    banned_until: Option<Instant>,
}

/// Failure ledger and ban list, keyed by client address.
pub struct AuthBan {
    cfg: AuthBanConfig,
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

impl AuthBan {
    /// New ledger.
    pub fn new(cfg: AuthBanConfig) -> Self {
        Self {
            cfg,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, Entry>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Records one failure; returns true if this call started a ban.
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.lock();
        if !map.contains_key(&ip) && map.len() >= self.cfg.max_tracked {
            sweep_locked(&mut map, now, self.cfg.window);
            if map.len() >= self.cfg.max_tracked {
                return false;
            }
        }
        let e = map.entry(ip).or_default();
        while e
            .failures
            .front()
            .is_some_and(|t| now.duration_since(*t) > self.cfg.window)
        {
            e.failures.pop_front();
        }
        e.failures.push_back(now);
        if e.failures.len() as u64 >= u64::from(self.cfg.max_failures.max(1)) {
            let already = e.banned_until.is_some_and(|u| u > now);
            e.banned_until = Some(now + self.cfg.ban_duration);
            e.failures.clear();
            !already
        } else {
            false
        }
    }

    /// True while `ip` is banned.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.lock()
            .get(&ip)
            .and_then(|e| e.banned_until)
            .is_some_and(|u| u > now)
    }

    /// Bans `ip` for `duration` now.
    pub fn ban(&self, ip: IpAddr, duration: Duration) {
        self.lock().entry(ip).or_default().banned_until = Some(Instant::now() + duration);
    }

    /// Lifts a ban and forgets failures; returns true if `ip` was banned.
    pub fn unban(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        match self.lock().get_mut(&ip) {
            Some(e) => {
                let was = e.banned_until.is_some_and(|u| u > now);
                e.banned_until = None;
                e.failures.clear();
                was
            }
            None => false,
        }
    }

    /// Currently banned addresses with remaining seconds.
    pub fn banned_list(&self) -> Vec<(IpAddr, u64)> {
        let now = Instant::now();
        self.lock()
            .iter()
            .filter_map(|(ip, e)| {
                e.banned_until
                    .filter(|u| *u > now)
                    .map(|u| (*ip, u.duration_since(now).as_secs()))
            })
            .collect()
    }

    /// Drops entries with neither an active ban nor a recent failure;
    /// returns how many were dropped. Call periodically.
    pub fn sweep(&self) -> usize {
        sweep_locked(&mut self.lock(), Instant::now(), self.cfg.window)
    }
}

fn sweep_locked(map: &mut HashMap<IpAddr, Entry>, now: Instant, window: Duration) -> usize {
    let before = map.len();
    map.retain(|_, e| {
        e.banned_until.is_some_and(|u| u > now)
            || e.failures
                .back()
                .is_some_and(|t| now.duration_since(*t) <= window)
    });
    before - map.len()
}

impl std::fmt::Debug for AuthBan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBan")
            .field("cfg", &self.cfg)
            .field("tracked", &self.lock().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn tight() -> AuthBanConfig {
        AuthBanConfig {
            max_failures: 3,
            window: Duration::from_secs(60),
            ban_duration: Duration::from_secs(60),
            max_tracked: 1_000,
        }
    }

    #[test]
    fn threshold_bans_once() {
        let b = AuthBan::new(tight());
        let t = ip("192.0.2.1");
        assert!(!b.record_failure(t));
        assert!(!b.record_failure(t));
        assert!(!b.is_banned(t));
        assert!(b.record_failure(t));
        assert!(b.is_banned(t));
        for _ in 0..3 {
            assert!(!b.record_failure(t), "already banned: not newly banned");
        }
    }

    #[test]
    fn unban_and_manual_ban() {
        let b = AuthBan::new(tight());
        let t = ip("192.0.2.2");
        b.ban(t, Duration::from_secs(60));
        assert!(b.is_banned(t));
        assert_eq!(b.banned_list().len(), 1);
        assert!(b.unban(t));
        assert!(!b.is_banned(t));
        assert!(!b.unban(t));
    }

    #[test]
    fn old_failures_age_out_and_sweep() {
        let cfg = AuthBanConfig {
            window: Duration::from_millis(20),
            ..tight()
        };
        let b = AuthBan::new(cfg);
        let t = ip("192.0.2.3");
        b.record_failure(t);
        b.record_failure(t);
        std::thread::sleep(Duration::from_millis(40));
        assert!(!b.record_failure(t));
        assert!(!b.is_banned(t));
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(b.sweep(), 1);
        b.ban(ip("192.0.2.4"), Duration::from_nanos(1));
        std::thread::sleep(Duration::from_millis(2));
        assert!(b.banned_list().is_empty());
    }

    #[test]
    fn tracking_is_bounded() {
        let b = AuthBan::new(AuthBanConfig {
            max_tracked: 2,
            ..tight()
        });
        b.record_failure(ip("192.0.2.10"));
        b.record_failure(ip("192.0.2.11"));
        assert!(!b.record_failure(ip("192.0.2.12")));
        assert_eq!(b.lock().len(), 2);
    }

    #[test]
    fn stress_concurrent_failures_end_banned() {
        let b = Arc::new(AuthBan::new(AuthBanConfig {
            max_failures: 5,
            ..tight()
        }));
        let t = ip("198.51.100.1");
        let newly = Arc::new(AtomicUsize::new(0));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let (b, newly) = (Arc::clone(&b), Arc::clone(&newly));
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        if b.record_failure(t) {
                            newly.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(
            newly.load(Ordering::SeqCst),
            1,
            "a ban is reported once while it lasts"
        );
        assert!(b.is_banned(t));
    }
}
