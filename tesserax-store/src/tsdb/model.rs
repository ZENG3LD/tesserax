//! Time-series data model — mirrors Prometheus so the mental model
//! (and any future PromQL-lite) maps 1:1.
//!
//! A series is identified by `metric_name + label_set`, hashed to a
//! stable [`SeriesId`]. A [`Sample`] is `(timestamp_ms, f64)`. Counter /
//! gauge / histogram are not distinguished at the storage layer — a
//! histogram is just N regular series with `le` buckets, exactly like
//! Prometheus.

use serde::{Deserialize, Serialize};

/// One observation: millisecond Unix timestamp + float value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// Unix time in milliseconds.
    pub ts_ms: i64,
    /// Observed value.
    pub value: f64,
}

/// A label set, kept sorted by key so the identity hash is independent
/// of insertion order. Construct via [`LabelSet::new`] which sorts +
/// dedups (last write wins on duplicate keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LabelSet(Vec<(String, String)>);

impl LabelSet {
    /// Sorted, de-duplicated label set.
    pub fn new(mut pairs: Vec<(String, String)>) -> Self {
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs.dedup_by(|a, b| a.0 == b.0); // dedup keeps the FIRST of equal keys
        Self(pairs)
    }

    /// No labels.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Pairs in key order.
    pub fn as_slice(&self) -> &[(String, String)] {
        &self.0
    }

    /// True if every (key, value) in `matchers` is present in this set.
    /// Used by `select` for partial-label queries.
    pub fn matches(&self, matchers: &[(String, String)]) -> bool {
        matchers
            .iter()
            .all(|(mk, mv)| self.0.iter().any(|(k, v)| k == mk && v == mv))
    }
}

/// Stable 128-bit series identity = `BLAKE3(name || 0x00 || k=v || 0x00 ...)`
/// truncated to 16 bytes. Collision probability is negligible at the
/// series counts this store targets (~thousands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeriesId(pub u128);

impl SeriesId {
    /// Big-endian bytes (the on-disk key).
    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
    /// From big-endian bytes.
    pub fn from_bytes(b: [u8; 16]) -> Self {
        SeriesId(u128::from_be_bytes(b))
    }
}

/// Name + labels. The thing a caller records against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeriesKey {
    /// Metric name.
    pub name: String,
    /// Labels.
    pub labels: LabelSet,
}

impl SeriesKey {
    /// Name + labels.
    pub fn new(name: impl Into<String>, labels: LabelSet) -> Self {
        Self {
            name: name.into(),
            labels,
        }
    }

    /// Bare metric, no labels.
    pub fn bare(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            labels: LabelSet::empty(),
        }
    }

    /// Derive the stable [`SeriesId`].
    pub fn id(&self) -> SeriesId {
        let mut h = blake3::Hasher::new();
        h.update(self.name.as_bytes());
        for (k, v) in self.labels.as_slice() {
            h.update(&[0u8]);
            h.update(k.as_bytes());
            h.update(b"=");
            h.update(v.as_bytes());
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&h.finalize().as_bytes()[..16]);
        SeriesId(u128::from_be_bytes(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_order_does_not_change_id() {
        let a = SeriesKey::new(
            "cpu",
            LabelSet::new(vec![
                ("host".into(), "a".into()),
                ("region".into(), "eu".into()),
            ]),
        );
        let b = SeriesKey::new(
            "cpu",
            LabelSet::new(vec![
                ("region".into(), "eu".into()),
                ("host".into(), "a".into()),
            ]),
        );
        assert_eq!(a.id(), b.id(), "id must be order-independent");
    }

    #[test]
    fn different_labels_different_id() {
        let a = SeriesKey::new("cpu", LabelSet::new(vec![("host".into(), "a".into())]));
        let b = SeriesKey::new("cpu", LabelSet::new(vec![("host".into(), "b".into())]));
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn name_participates_in_id() {
        let a = SeriesKey::bare("cpu");
        let b = SeriesKey::bare("mem");
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn series_id_byte_roundtrip() {
        let id = SeriesKey::bare("x").id();
        assert_eq!(SeriesId::from_bytes(id.to_bytes()), id);
    }

    #[test]
    fn matches_partial_labels() {
        let ls = LabelSet::new(vec![
            ("host".into(), "a".into()),
            ("region".into(), "eu".into()),
        ]);
        assert!(ls.matches(&[("host".into(), "a".into())]));
        assert!(ls.matches(&[("host".into(), "a".into()), ("region".into(), "eu".into())]));
        assert!(!ls.matches(&[("host".into(), "b".into())]));
        assert!(ls.matches(&[])); // empty matcher matches everything
    }
}
