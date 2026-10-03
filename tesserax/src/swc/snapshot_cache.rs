//! The consumer-side copy of back-office state, typed as a cache.

use std::sync::Arc;

use super::port::Port;
use super::types::Snapshot;

/// Last snapshot a consumer has seen, replaced wholesale when the port's
/// revision advances and never mutated in place.
///
/// This is the one place an app (for example a UI frame loop) keeps
/// back-office data: poll it once per frame, render from
/// [`get`](Self::get), and after a resync with a gap install the reply's
/// snapshot with [`replace`](Self::replace).
#[derive(Clone, Debug)]
pub struct SnapshotCache<S> {
    current: Arc<Snapshot<S>>,
    seen_revision: u64,
}

impl<S> SnapshotCache<S> {
    /// Starts from `snapshot`.
    pub fn new(snapshot: Arc<Snapshot<S>>) -> Self {
        let seen_revision = snapshot.revision;
        Self {
            current: snapshot,
            seen_revision,
        }
    }

    /// Starts from the port's current snapshot.
    pub fn from_port<C, V, P>(port: &P) -> Self
    where
        P: Port<C, V, S> + ?Sized,
    {
        Self::new(port.snapshot())
    }

    /// Loads the port's snapshot (non-blocking) and keeps it iff its revision
    /// is newer than the one held. Returns true iff the revision advanced.
    pub fn poll<C, V, P>(&mut self, port: &P) -> bool
    where
        P: Port<C, V, S> + ?Sized,
    {
        let latest = port.snapshot();
        if latest.revision > self.seen_revision {
            self.seen_revision = latest.revision;
            self.current = latest;
            true
        } else {
            false
        }
    }

    /// Installs `snapshot` unconditionally (after a resync, or when the back
    /// office restarted and its revisions began again). Returns true iff the
    /// revision changed.
    pub fn replace(&mut self, snapshot: Arc<Snapshot<S>>) -> bool {
        let changed = snapshot.revision != self.seen_revision;
        self.seen_revision = snapshot.revision;
        self.current = snapshot;
        changed
    }

    /// The cached snapshot.
    pub fn get(&self) -> &Snapshot<S> {
        &self.current
    }

    /// The cached snapshot as a shared pointer.
    pub fn shared(&self) -> Arc<Snapshot<S>> {
        Arc::clone(&self.current)
    }

    /// Revision of the cached snapshot.
    pub fn revision(&self) -> u64 {
        self.seen_revision
    }
}
