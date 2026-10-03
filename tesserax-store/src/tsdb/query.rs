//! Query surface — the minimum that covers operational use, not PromQL.
//!
//! Range + window aggregate + `rate()` cover essentially all operational
//! metric queries. Instant-vector algebra, joins, `histogram_quantile` and
//! subqueries are deliberately out until a concrete consumer needs them.

use super::model::{Sample, SeriesKey};
use super::store::{Tsdb, TsdbError};

/// Window aggregation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agg {
    /// Arithmetic mean.
    Avg,
    /// Smallest value.
    Min,
    /// Largest value.
    Max,
    /// Sum of values.
    Sum,
    /// Most recent sample in the window.
    Last,
    /// Sample count in the window.
    Count,
}

impl Tsdb {
    /// Raw samples for a series in `[t0_ms, t1_ms]` (inclusive), sorted
    /// by timestamp. Decodes overlapping flushed chunks plus the live
    /// chunk.
    pub fn range(&self, key: &SeriesKey, t0_ms: i64, t1_ms: i64) -> Result<Vec<Sample>, TsdbError> {
        self.read_range(key.id(), t0_ms, t1_ms)
    }

    /// Series matching a metric name + partial label matcher. Empty
    /// matcher returns every series with that name.
    pub fn select(
        &self,
        name: &str,
        matchers: &[(String, String)],
    ) -> Result<Vec<SeriesKey>, TsdbError> {
        self.select_series(name, matchers)
    }

    /// Window aggregate over `[t0_ms, t1_ms]`. `None` when the window is
    /// empty (no samples).
    pub fn aggregate(
        &self,
        key: &SeriesKey,
        t0_ms: i64,
        t1_ms: i64,
        agg: Agg,
    ) -> Result<Option<f64>, TsdbError> {
        let samples = self.range(key, t0_ms, t1_ms)?;
        Ok(aggregate_samples(&samples, agg))
    }

    /// Per-second rate of a counter over `[t0_ms, t1_ms]`, with
    /// counter-reset correction.
    ///
    /// A counter only ever increases; a process restart resets it to 0.
    /// When `v[i] < v[i-1]` we treat it as a reset and fold the
    /// pre-reset value into a running correction so the cumulative
    /// increase stays monotonic — exactly Prometheus's `rate()` reset
    /// handling. Returns `None` when fewer than two samples exist or the
    /// time span is zero.
    pub fn rate(&self, key: &SeriesKey, t0_ms: i64, t1_ms: i64) -> Result<Option<f64>, TsdbError> {
        let samples = self.range(key, t0_ms, t1_ms)?;
        Ok(rate_over(&samples))
    }
}

/// Pure aggregate over an already-fetched slice (sorted by ts). Exposed
/// at crate level so query tests + the recorder path can reuse it.
pub(crate) fn aggregate_samples(samples: &[Sample], agg: Agg) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    Some(match agg {
        Agg::Avg => samples.iter().map(|s| s.value).sum::<f64>() / samples.len() as f64,
        Agg::Min => samples
            .iter()
            .map(|s| s.value)
            .fold(f64::INFINITY, f64::min),
        Agg::Max => samples
            .iter()
            .map(|s| s.value)
            .fold(f64::NEG_INFINITY, f64::max),
        Agg::Sum => samples.iter().map(|s| s.value).sum(),
        Agg::Last => samples.last().unwrap().value,
        Agg::Count => samples.len() as f64,
    })
}

/// Counter rate with reset correction. Returns per-second increase.
pub(crate) fn rate_over(samples: &[Sample]) -> Option<f64> {
    if samples.len() < 2 {
        return None;
    }
    let first = samples.first().unwrap();
    let last = samples.last().unwrap();
    let span_secs = (last.ts_ms - first.ts_ms) as f64 / 1000.0;
    if span_secs <= 0.0 {
        return None;
    }

    // Walk the series summing positive increments; on a reset
    // (value drop) the new value IS the increment from zero.
    let mut total_increase = 0.0;
    let mut prev = first.value;
    for s in &samples[1..] {
        if s.value >= prev {
            total_increase += s.value - prev;
        } else {
            // Counter reset: everything from the new floor counts.
            total_increase += s.value;
        }
        prev = s.value;
    }
    Some(total_increase / span_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tsdb::model::{LabelSet, SeriesKey};

    fn db_with(name: &str, samples: &[(i64, f64)]) -> (Tsdb, SeriesKey) {
        let db = Tsdb::open_in_memory().unwrap();
        let k = SeriesKey::new(name, LabelSet::empty());
        for (ts, v) in samples {
            db.record(
                &k,
                Sample {
                    ts_ms: *ts,
                    value: *v,
                },
            )
            .unwrap();
        }
        (db, k)
    }

    #[test]
    fn range_returns_window() {
        let (db, k) = db_with("x", &[(0, 1.0), (1000, 2.0), (2000, 3.0), (3000, 4.0)]);
        let got = db.range(&k, 1000, 2000).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].value, 2.0);
        assert_eq!(got[1].value, 3.0);
    }

    #[test]
    fn aggregates() {
        let (db, k) = db_with("x", &[(0, 2.0), (1000, 4.0), (2000, 6.0)]);
        assert_eq!(db.aggregate(&k, 0, 2000, Agg::Avg).unwrap(), Some(4.0));
        assert_eq!(db.aggregate(&k, 0, 2000, Agg::Min).unwrap(), Some(2.0));
        assert_eq!(db.aggregate(&k, 0, 2000, Agg::Max).unwrap(), Some(6.0));
        assert_eq!(db.aggregate(&k, 0, 2000, Agg::Sum).unwrap(), Some(12.0));
        assert_eq!(db.aggregate(&k, 0, 2000, Agg::Last).unwrap(), Some(6.0));
        assert_eq!(db.aggregate(&k, 0, 2000, Agg::Count).unwrap(), Some(3.0));
    }

    #[test]
    fn aggregate_empty_window_is_none() {
        let (db, k) = db_with("x", &[(0, 1.0)]);
        assert_eq!(db.aggregate(&k, 5000, 6000, Agg::Avg).unwrap(), None);
    }

    #[test]
    fn rate_simple_counter() {
        // Counter 0→10→20→30 over 30s → 1.0/s.
        let (db, k) = db_with(
            "c",
            &[(0, 0.0), (10_000, 10.0), (20_000, 20.0), (30_000, 30.0)],
        );
        let r = db.rate(&k, 0, 30_000).unwrap().unwrap();
        assert!((r - 1.0).abs() < 1e-9, "rate = {r}");
    }

    #[test]
    fn rate_with_counter_reset() {
        // 0→10→20→[reset]→5→15 over 40s.
        // Increases: 10 + 10 + 5(reset, new floor counts) + 10 = 35 over 40s.
        let (db, k) = db_with(
            "c",
            &[
                (0, 0.0),
                (10_000, 10.0),
                (20_000, 20.0),
                (30_000, 5.0),
                (40_000, 15.0),
            ],
        );
        let r = db.rate(&k, 0, 40_000).unwrap().unwrap();
        let expected = 35.0 / 40.0;
        assert!(
            (r - expected).abs() < 1e-9,
            "rate = {r}, expected {expected}"
        );
    }

    #[test]
    fn rate_needs_two_samples() {
        let (db, k) = db_with("c", &[(0, 5.0)]);
        assert_eq!(db.rate(&k, 0, 1000).unwrap(), None);
    }

    #[test]
    fn rate_zero_span_is_none() {
        let (db, k) = db_with("c", &[(1000, 1.0), (1000, 2.0)]);
        assert_eq!(db.rate(&k, 1000, 1000).unwrap(), None);
    }
}
