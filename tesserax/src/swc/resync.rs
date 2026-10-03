//! Resync: how a subscriber that fell behind (or a fresh client) catches up.

use std::sync::Arc;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::types::{EventEnvelope, Snapshot};

/// Answer to [`Port::resync`](super::Port::resync)`(after_sequence)`.
///
/// `snapshot` and `events` are read under one lock, so
/// `snapshot.through_sequence == event_sequence` and, when `events` is not
/// empty, its last sequence is `event_sequence` too.
///
/// Client procedure: if `gap` is false, apply `events` (every retained event
/// with `sequence > after_sequence`) on top of what it had; if `gap` is true,
/// events it never saw are gone from the log, so it replaces its state with
/// `snapshot` wholesale and continues from `event_sequence`. A client whose
/// `after_sequence` is *ahead* of `event_sequence` also gets `gap = true`
/// (and no events): the log it followed is not this one.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResyncReply<V, S> {
    /// Last published sequence.
    pub event_sequence: u64,
    /// Oldest sequence still retained; `event_sequence + 1` when the log is
    /// empty.
    pub oldest_available: u64,
    /// True exactly when `after_sequence < oldest_available - 1` (at least one
    /// event after `after_sequence` has left the log) **or**
    /// `after_sequence > event_sequence` (the client is ahead of the log, e.g.
    /// it saw sequences from a kernel that has since restarted). Either way
    /// the client's state cannot be patched with `events` and must be
    /// replaced by `snapshot`.
    pub gap: bool,
    /// Current snapshot.
    pub snapshot: Arc<Snapshot<S>>,
    /// Retained events with `sequence > after_sequence`, in order.
    pub events: Vec<EventEnvelope<V>>,
}
