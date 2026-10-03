//! Audit trail seam: [`AuditSink`] receives one [`AuditEvent`] per decision.
//!
//! Recording never fails the caller: a sink that cannot write drops or
//! buffers the event and reports that through its own channel (a counter, a
//! log), never through the request that produced it. Sinks must not block;
//! a sink that writes to disk hands the event to its own writer thread.

use std::sync::Arc;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// One audited action.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditEvent {
    /// Wall-clock time in milliseconds since the Unix epoch, supplied by the
    /// caller (this crate never reads a clock).
    pub ts_ms: u64,
    /// Door the request came through.
    pub door: String,
    /// Key id of the principal, if authenticated.
    pub principal: Option<String>,
    /// Client address or other client identity, if known.
    pub client: Option<String>,
    /// What was attempted (HTTP method, tool name, command kind).
    pub verb: String,
    /// What it was attempted on (path, subject).
    pub target: String,
    /// Outcome code (an HTTP status for HTTP doors).
    pub status: u16,
}

/// Receiver of audit events. Infallible and non-blocking by contract.
pub trait AuditSink: Send + Sync {
    /// Records `event`.
    fn record(&self, event: AuditEvent);
}

/// Sink that discards every event.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&self, _event: AuditEvent) {}
}

impl<T: AuditSink + ?Sized> AuditSink for Arc<T> {
    fn record(&self, event: AuditEvent) {
        (**self).record(event);
    }
}

impl<T: AuditSink + ?Sized> AuditSink for Box<T> {
    fn record(&self, event: AuditEvent) {
        (**self).record(event);
    }
}

impl<T: AuditSink + ?Sized> AuditSink for &T {
    fn record(&self, event: AuditEvent) {
        (**self).record(event);
    }
}
