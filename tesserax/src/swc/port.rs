//! The port: [`Handle`] for shells, [`KernelPort`] for the kernel's runtime.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::edge::{Edge, PublishReport};
use super::queue::{PushError, Queue};
use super::resync::ResyncReply;
use super::subscription::Subscription;
use super::types::{CommandEnvelope, CommandId, EventEnvelope, Snapshot};
use crate::error::{DispatchError, PublishError, SubscribeError};

/// Largest command ingress a port accepts.
pub const MAX_INGRESS_CAPACITY: usize = 4_096;
/// Largest number of live subscribers per port.
pub const MAX_SUBSCRIBERS: usize = 128;
/// Largest event-log ring a port retains for resync.
pub const MAX_EVENT_LOG_CAPACITY: usize = 65_536;

/// The contract a shell sees: commands in, snapshot and events out.
///
/// Implemented by the in-process [`Handle`]; a remote shell (pipe, HTTP,
/// WebSocket, a wasm client over fetch) implements the same trait over the
/// wire form of the envelopes. Every method returns without waiting on the
/// kernel.
pub trait Port<C, V, S>: Send + Sync {
    /// Enqueues `command` under a fresh [`CommandId`], which is returned.
    fn dispatch(&self, command: C) -> Result<CommandId, DispatchError>;
    /// Enqueues an envelope keeping its id (a forwarding shell keeps the
    /// upstream id). Ids chosen here are not checked against ids issued by
    /// [`dispatch`](Self::dispatch); a forwarding handle should use only this
    /// method.
    fn dispatch_envelope(&self, envelope: CommandEnvelope<C>) -> Result<(), DispatchError>;
    /// The current snapshot.
    fn snapshot(&self) -> Arc<Snapshot<S>>;
    /// Opens a bounded event subscription with room for `capacity` events.
    ///
    /// Events published after this call are delivered; to start consistently
    /// read [`snapshot`](Self::snapshot) afterwards and skip events whose
    /// sequence is `<= snapshot.through_sequence`.
    fn subscribe(&self, capacity: usize) -> Result<Subscription<V>, SubscribeError>;
    /// Current snapshot plus every retained event after `after_sequence`.
    fn resync(&self, after_sequence: u64) -> ResyncReply<V, S>;
}

/// Sizes of one port. Values are clamped at construction: ingress to
/// `1..=`[`MAX_INGRESS_CAPACITY`], event log to
/// `1..=`[`MAX_EVENT_LOG_CAPACITY`], subscribers to `1..=`[`MAX_SUBSCRIBERS`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PortConfig {
    /// Commands that may wait in the ingress before `dispatch` returns `Full`.
    pub ingress_capacity: usize,
    /// Events retained for [`Port::resync`].
    pub event_log_capacity: usize,
    /// Live subscribers the port serves at once.
    pub max_subscribers: usize,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            ingress_capacity: 1_024,
            event_log_capacity: 1_024,
            max_subscribers: MAX_SUBSCRIBERS,
        }
    }
}

impl PortConfig {
    fn clamped(self) -> Self {
        Self {
            ingress_capacity: self.ingress_capacity.clamp(1, MAX_INGRESS_CAPACITY),
            event_log_capacity: self.event_log_capacity.clamp(1, MAX_EVENT_LOG_CAPACITY),
            max_subscribers: self.max_subscribers.clamp(1, MAX_SUBSCRIBERS),
        }
    }
}

/// In-process [`Port`]. Cheap to clone; all clones share one ingress, one
/// edge and one command-id counter.
pub struct Handle<C, V, S> {
    ingress: Arc<Queue<CommandEnvelope<C>>>,
    edge: Arc<Edge<V, S>>,
    next_id: Arc<AtomicU64>,
}

impl<C, V, S> Clone for Handle<C, V, S> {
    fn clone(&self) -> Self {
        Self {
            ingress: Arc::clone(&self.ingress),
            edge: Arc::clone(&self.edge),
            next_id: Arc::clone(&self.next_id),
        }
    }
}

impl<C, V, S> core::fmt::Debug for Handle<C, V, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handle")
            .field("queued_commands", &self.ingress.len())
            .finish_non_exhaustive()
    }
}

/// The kernel runtime's side of the port: drains commands, publishes events
/// and snapshots. Exactly one exists per port; dropping it disconnects every
/// handle and subscriber.
pub struct KernelPort<C, V, S> {
    ingress: Arc<Queue<CommandEnvelope<C>>>,
    edge: Arc<Edge<V, S>>,
}

impl<C, V, S> core::fmt::Debug for KernelPort<C, V, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelPort")
            .field("queued_commands", &self.ingress.len())
            .finish_non_exhaustive()
    }
}

/// Creates a port whose snapshot starts as `Snapshot::initial(S::default())`.
pub fn bounded_port<C, V, S: Default>(
    config: PortConfig,
) -> (Handle<C, V, S>, KernelPort<C, V, S>) {
    bounded_port_from(config, Snapshot::initial(S::default()))
}

/// Creates a port starting from `initial` (a kernel restored from storage
/// starts at its persisted revision and sequence).
pub fn bounded_port_from<C, V, S>(
    config: PortConfig,
    initial: Snapshot<S>,
) -> (Handle<C, V, S>, KernelPort<C, V, S>) {
    let config = config.clamped();
    let ingress = Arc::new(Queue::new(config.ingress_capacity));
    let edge = Arc::new(Edge::new(
        initial,
        config.event_log_capacity,
        config.max_subscribers,
    ));
    (
        Handle {
            ingress: Arc::clone(&ingress),
            edge: Arc::clone(&edge),
            next_id: Arc::new(AtomicU64::new(1)),
        },
        KernelPort { ingress, edge },
    )
}

impl<C, V, S> Port<C, V, S> for Handle<C, V, S>
where
    C: Send,
    V: Clone + Send,
    S: Send + Sync,
{
    fn dispatch(&self, command: C) -> Result<CommandId, DispatchError> {
        let id = self
            .next_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| DispatchError::IdsExhausted)?;
        let id = CommandId(id);
        self.dispatch_envelope(CommandEnvelope { id, command })?;
        Ok(id)
    }

    fn dispatch_envelope(&self, envelope: CommandEnvelope<C>) -> Result<(), DispatchError> {
        self.ingress.try_push(envelope).map_err(|e| match e {
            PushError::Full(_) => DispatchError::Full,
            PushError::Closed(_) => DispatchError::Disconnected,
        })
    }

    fn snapshot(&self) -> Arc<Snapshot<S>> {
        self.edge.snapshot()
    }

    fn subscribe(&self, capacity: usize) -> Result<Subscription<V>, SubscribeError> {
        self.edge.subscribe(capacity)
    }

    fn resync(&self, after_sequence: u64) -> ResyncReply<V, S> {
        self.edge.resync(after_sequence)
    }
}

impl<C, V: Clone, S> KernelPort<C, V, S> {
    /// Parks the calling thread until a command is queued or `timeout`
    /// elapses. Takes nothing. Returns true iff a command is queued.
    pub fn wait(&self, timeout: Duration) -> bool {
        self.ingress.wait_nonempty(timeout)
    }

    /// Takes up to `limit` queued commands in arrival order.
    pub fn drain_commands(&self, limit: usize) -> Vec<CommandEnvelope<C>> {
        self.ingress.drain(limit)
    }

    /// Publishes one tick: appends `events` to the log, swaps in `snapshot`
    /// and offers the events to every subscriber, all under the edge lock.
    ///
    /// `events` must continue the log by +1 each and `snapshot.through_sequence`
    /// must equal the last sequence afterwards (the previous one when
    /// `events` is empty); `snapshot.revision` must not go backwards. A
    /// refused batch changes nothing. A subscriber whose queue is full is
    /// sent `CoreEvent::ResyncRequired` and disconnected; the report counts it.
    pub fn publish(
        &self,
        events: Vec<EventEnvelope<V>>,
        snapshot: Snapshot<S>,
    ) -> Result<PublishReport, PublishError> {
        self.edge.publish(events, snapshot)
    }

    /// The snapshot currently published.
    pub fn snapshot(&self) -> Arc<Snapshot<S>> {
        self.edge.snapshot()
    }

    /// Live subscribers right now (dropped subscriptions are pruned first).
    pub fn subscriber_count(&self) -> usize {
        self.edge.subscriber_count()
    }
}

impl<C, V, S> Drop for KernelPort<C, V, S> {
    fn drop(&mut self) {
        self.ingress.close_rx();
        self.edge.close();
    }
}
