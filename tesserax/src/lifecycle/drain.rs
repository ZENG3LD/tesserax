//! Drain flag behind `/readyz` and `POST /admin/drain`.
//!
//! `/livez` answers 200 while the process answers at all. `/readyz`
//! answers 503 once the server is draining, so a load balancer stops
//! sending new traffic while in-flight requests finish; the operator then
//! fires the shutdown broadcast.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Process-wide drain flag. Clones share it.
#[derive(Clone, Default)]
pub struct DrainState {
    flag: Arc<AtomicBool>,
}

impl DrainState {
    /// Not draining.
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts draining. Idempotent.
    pub fn drain(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Stops draining.
    pub fn resume(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }

    /// True while draining.
    pub fn is_draining(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for DrainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DrainState")
            .field("draining", &self.is_draining())
            .finish()
    }
}

/// `(ready, reason_if_not)`. Draining is reported before failed dependencies.
pub fn readiness(drain: &DrainState, deps_ok: bool) -> (bool, Option<&'static str>) {
    if drain.is_draining() {
        (false, Some("draining"))
    } else if !deps_ok {
        (false, Some("dependency_failed"))
    } else {
        (true, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_resume_and_clones_share_state() {
        let d = DrainState::new();
        let d2 = d.clone();
        assert!(!d.is_draining());
        d.drain();
        assert!(d2.is_draining());
        d.resume();
        assert!(!d2.is_draining());
    }

    #[test]
    fn readiness_reports_drain_first() {
        let d = DrainState::new();
        assert_eq!(readiness(&d, true), (true, None));
        assert_eq!(readiness(&d, false), (false, Some("dependency_failed")));
        d.drain();
        assert_eq!(readiness(&d, true), (false, Some("draining")));
        assert_eq!(readiness(&d, false), (false, Some("draining")));
    }
}
