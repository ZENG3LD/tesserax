//! [`ObservationSink`]: how effect results (and unsolicited facts) re-enter
//! the kernel.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tesserax::swc::{EffectEnvelope, Generation, ObservationEnvelope, OperationId, Subject};

use super::queue::{BoundedQueue, Refused};

/// The correlation data of one effect: what its observation must carry
/// back so the kernel can match it and drop it when stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EffectTicket {
    /// The effect's operation id.
    pub operation_id: OperationId,
    /// The effect's subject.
    pub subject: Option<Subject>,
    /// The subject's generation when the effect was issued.
    pub generation: Generation,
}

impl EffectTicket {
    /// The ticket of `effect`.
    pub fn of<E>(effect: &EffectEnvelope<E>) -> Self {
        Self {
            operation_id: effect.operation_id,
            subject: effect.subject,
            generation: effect.generation,
        }
    }

    /// Wraps `observation` as the answer to this effect.
    pub fn answer<O>(self, observation: O) -> ObservationEnvelope<O> {
        ObservationEnvelope {
            operation_id: Some(self.operation_id),
            subject: self.subject,
            generation: self.generation,
            observation,
        }
    }
}

/// Why the sink refused an observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, thiserror::Error)]
pub enum SinkError {
    /// The inbox is at capacity (the runtime is not keeping up, or the
    /// capacity is smaller than the effects in flight).
    #[error("observation inbox is full")]
    Full,
    /// The runtime is gone.
    #[error("runtime is gone")]
    Closed,
}

/// A refused observation, handed back to the caller.
#[derive(Debug)]
pub struct SinkRejected<O> {
    /// Why.
    pub reason: SinkError,
    /// The observation that was not taken.
    pub envelope: ObservationEnvelope<O>,
}

/// Counters of one sink (shared by all its clones).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct SinkStats {
    /// Observations taken into the inbox.
    pub accepted: u64,
    /// Observations refused because the inbox was full.
    pub refused_full: u64,
    /// Observations refused because the runtime was gone.
    pub refused_closed: u64,
}

pub(crate) struct Inbox<O> {
    queue: BoundedQueue<ObservationEnvelope<O>>,
    accepted: AtomicU64,
    refused_full: AtomicU64,
    refused_closed: AtomicU64,
}

impl<O> Inbox<O> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            queue: BoundedQueue::new(capacity),
            accepted: AtomicU64::new(0),
            refused_full: AtomicU64::new(0),
            refused_closed: AtomicU64::new(0),
        }
    }

    pub(crate) fn drain(&self, limit: usize) -> Vec<ObservationEnvelope<O>> {
        self.queue.drain(limit)
    }

    pub(crate) fn close(&self) {
        self.queue.close();
    }

    pub(crate) fn stats(&self) -> SinkStats {
        SinkStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            refused_full: self.refused_full.load(Ordering::Relaxed),
            refused_closed: self.refused_closed.load(Ordering::Relaxed),
        }
    }

    fn account(
        &self,
        result: Result<(), Refused<ObservationEnvelope<O>>>,
    ) -> Result<(), SinkRejected<O>> {
        match result {
            Ok(()) => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(Refused::Full(envelope)) => {
                self.refused_full.fetch_add(1, Ordering::Relaxed);
                Err(SinkRejected {
                    reason: SinkError::Full,
                    envelope,
                })
            }
            Err(Refused::Closed(envelope)) => {
                self.refused_closed.fetch_add(1, Ordering::Relaxed);
                Err(SinkRejected {
                    reason: SinkError::Closed,
                    envelope,
                })
            }
        }
    }
}

#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) enum Offer<O> {
    Taken,
    Full(ObservationEnvelope<O>),
    Closed,
}

/// The door observations use to reach the kernel: a bounded inbox the
/// runtime drains at the start of every tick.
///
/// Cheap to clone. [`submit`](Self::submit) never blocks and is safe on the
/// runtime's own thread; [`submit_timeout`](Self::submit_timeout) waits for
/// room and is meant for executor threads. A refusal hands the observation
/// back and is counted in [`stats`](Self::stats).
pub struct ObservationSink<O> {
    inbox: Arc<Inbox<O>>,
}

impl<O> Clone for ObservationSink<O> {
    fn clone(&self) -> Self {
        Self {
            inbox: Arc::clone(&self.inbox),
        }
    }
}

impl<O> core::fmt::Debug for ObservationSink<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObservationSink")
            .field("queued", &self.inbox.queue.len())
            .field("capacity", &self.inbox.queue.capacity())
            .field("stats", &self.inbox.stats())
            .finish()
    }
}

impl<O> ObservationSink<O> {
    pub(crate) fn new(inbox: Arc<Inbox<O>>) -> Self {
        Self { inbox }
    }

    /// Queues `envelope` if there is room; never blocks.
    pub fn submit(&self, envelope: ObservationEnvelope<O>) -> Result<(), SinkRejected<O>> {
        self.inbox.account(self.inbox.queue.try_push(envelope))
    }

    /// Queues `envelope`, waiting up to `timeout` for room. Not for the
    /// runtime's own thread.
    pub fn submit_timeout(
        &self,
        envelope: ObservationEnvelope<O>,
        timeout: Duration,
    ) -> Result<(), SinkRejected<O>> {
        self.inbox
            .account(self.inbox.queue.push_timeout(envelope, timeout))
    }

    /// [`submit`](Self::submit) of `observation` as the answer to `ticket`.
    pub fn answer(&self, ticket: EffectTicket, observation: O) -> Result<(), SinkRejected<O>> {
        self.submit(ticket.answer(observation))
    }

    /// Queues `envelope` if there is room, without counting a full inbox
    /// (for callers that retry; they call [`give_up`](Self::give_up) when
    /// they stop).
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn offer(&self, envelope: ObservationEnvelope<O>) -> Offer<O> {
        match self.inbox.queue.try_push(envelope) {
            Ok(()) => {
                self.inbox.accepted.fetch_add(1, Ordering::Relaxed);
                Offer::Taken
            }
            Err(Refused::Full(envelope)) => Offer::Full(envelope),
            Err(Refused::Closed(_)) => {
                self.inbox.refused_closed.fetch_add(1, Ordering::Relaxed);
                Offer::Closed
            }
        }
    }

    /// Counts one observation dropped on a full inbox after retries.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn give_up(&self) {
        self.inbox.refused_full.fetch_add(1, Ordering::Relaxed);
    }

    /// True once the runtime is gone.
    pub fn is_closed(&self) -> bool {
        self.inbox.queue.is_closed()
    }

    /// Counters shared by every clone of this sink.
    pub fn stats(&self) -> SinkStats {
        self.inbox.stats()
    }
}
