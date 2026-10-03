//! Retention — drop chunks past the cutoff.
//!
//! A thin policy wrapper over [`Tsdb::evict_before`]. Scheduling (e.g.
//! hourly) is the caller's job — a background task of its runtime; this
//! module stays runtime-agnostic and exposes the one-shot sweep and the
//! cutoff computation.

use std::time::Duration;

use super::store::{Tsdb, TsdbError};

/// Retention policy: keep samples newer than `window`.
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    /// How far back samples are kept.
    pub window: Duration,
}

impl Retention {
    /// Common default: 30 days.
    pub fn days(d: u64) -> Self {
        Self {
            window: Duration::from_secs(d * 86_400),
        }
    }

    /// Cutoff timestamp (ms) for a given "now": samples with
    /// `t_end_ms < cutoff` are evictable.
    pub fn cutoff_ms(&self, now_ms: i64) -> i64 {
        now_ms.saturating_sub(self.window.as_millis() as i64)
    }

    /// Run one eviction sweep against `now_ms`. Returns
    /// (chunks_deleted, series_deleted). Run it on a periodic timer.
    pub fn sweep(&self, db: &Tsdb, now_ms: i64) -> Result<(usize, usize), TsdbError> {
        db.evict_before(self.cutoff_ms(now_ms))
    }
}

impl Default for Retention {
    fn default() -> Self {
        Self::days(30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tsdb::model::{LabelSet, Sample, SeriesKey};

    #[test]
    fn cutoff_subtracts_window() {
        let r = Retention::days(1);
        // now = 2 days in ms; cutoff = 1 day in ms.
        let now = 2 * 86_400_000i64;
        assert_eq!(r.cutoff_ms(now), 86_400_000);
    }

    #[test]
    fn sweep_drops_old_keeps_recent() {
        let db = Tsdb::open_in_memory().unwrap().with_chunk_cap(3);
        let k = SeriesKey::new("x", LabelSet::empty());
        let day = 86_400_000i64;
        // Old chunk: 3 samples around t=0 (flushes at cap 3).
        for i in 0..3 {
            db.record(
                &k,
                Sample {
                    ts_ms: i * 1000,
                    value: i as f64,
                },
            )
            .unwrap();
        }
        // Recent chunk: 3 samples around t=10 days (flushes).
        for i in 0..3 {
            db.record(
                &k,
                Sample {
                    ts_ms: 10 * day + i * 1000,
                    value: i as f64,
                },
            )
            .unwrap();
        }
        // Retain 1 day, now = 11 days → old chunk (t_end ~2s) evicted,
        // recent chunk (t_end ~10 days) kept.
        let r = Retention::days(1);
        let (chunks, _series) = r.sweep(&db, 11 * day).unwrap();
        assert_eq!(chunks, 1, "only the old chunk should go");
        // Recent data still queryable.
        let got = db.range(&k, 0, i64::MAX).unwrap();
        assert!(got.iter().all(|s| s.ts_ms >= 10 * day));
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn default_is_30_days() {
        assert_eq!(
            Retention::default().window,
            Duration::from_secs(30 * 86_400)
        );
    }
}
