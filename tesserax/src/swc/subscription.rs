//! Bounded per-subscriber event queue.

use std::sync::Arc;
use std::time::Duration;

use super::queue::{PopError, PushError, Queue};
use super::types::EventEnvelope;
use crate::error::{RecvError, SendError};

/// Largest queue a single subscriber may ask for.
pub const MAX_SUBSCRIPTION_CAPACITY: usize = 1_024;

/// Receiving end of one subscriber's bounded event queue.
///
/// Events arrive in sequence order. If the subscriber falls behind, the
/// publisher appends one final [`CoreEvent::ResyncRequired`](super::CoreEvent::ResyncRequired)
/// after the queued events and disconnects it; after draining, receives
/// return [`RecvError::Disconnected`]. Dropping the subscription frees its
/// slot on the port.
pub struct Subscription<V> {
    queue: Arc<Queue<EventEnvelope<V>>>,
}

/// Sending end of a [`Subscription`], for [`Port`](super::Port)
/// implementations outside this crate (a remote port feeding events it read
/// from the wire). Dropping it disconnects the subscription.
pub struct SubscriptionSender<V> {
    queue: Arc<Queue<EventEnvelope<V>>>,
}

/// Creates a detached subscription pair with room for `capacity` events
/// (clamped to `1..=`[`MAX_SUBSCRIPTION_CAPACITY`]).
pub fn subscription_channel<V>(capacity: usize) -> (SubscriptionSender<V>, Subscription<V>) {
    let queue = Arc::new(Queue::new(bounded_subscription_capacity(capacity)));
    (
        SubscriptionSender {
            queue: Arc::clone(&queue),
        },
        Subscription { queue },
    )
}

pub(crate) fn bounded_subscription_capacity(requested: usize) -> usize {
    requested.clamp(1, MAX_SUBSCRIPTION_CAPACITY)
}

impl<V> Subscription<V> {
    /// Takes the next event without waiting.
    pub fn try_recv(&self) -> Result<EventEnvelope<V>, RecvError> {
        self.queue.try_pop().map_err(map_pop)
    }

    /// Waits up to `timeout` for the next event. Blocks the calling thread:
    /// not for a UI frame loop, and not available on `wasm32-unknown-unknown`
    /// at run time (use [`try_recv`](Self::try_recv) there).
    pub fn recv_timeout(&self, timeout: Duration) -> Result<EventEnvelope<V>, RecvError> {
        self.queue.pop_timeout(timeout).map_err(map_pop)
    }

    /// Takes every event queued right now, in order.
    pub fn drain(&self) -> Vec<EventEnvelope<V>> {
        self.queue.drain(usize::MAX)
    }

    /// Number of events queued right now.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// True when no event is queued right now.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<V> Drop for Subscription<V> {
    fn drop(&mut self) {
        self.queue.close_rx();
    }
}

impl<V> core::fmt::Debug for Subscription<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Subscription")
            .field("queued", &self.queue.len())
            .finish()
    }
}

impl<V> SubscriptionSender<V> {
    /// Enqueues `event` without waiting.
    pub fn try_send(&self, event: EventEnvelope<V>) -> Result<(), SendError> {
        self.queue.try_push(event).map_err(|e| match e {
            PushError::Full(_) => SendError::Full,
            PushError::Closed(_) => SendError::Closed,
        })
    }

    /// Enqueues `event` past capacity and disconnects the subscription after
    /// it (used for the terminal `ResyncRequired`). Returns false if the
    /// subscriber is already gone.
    pub fn send_final(&self, event: EventEnvelope<V>) -> bool {
        self.queue.push_final(event)
    }

    /// True once the subscriber dropped its [`Subscription`].
    pub fn is_closed(&self) -> bool {
        self.queue.is_rx_closed()
    }
}

impl<V> Drop for SubscriptionSender<V> {
    fn drop(&mut self) {
        self.queue.close_tx();
    }
}

impl<V> core::fmt::Debug for SubscriptionSender<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SubscriptionSender")
            .field("closed", &self.is_closed())
            .finish()
    }
}

fn map_pop(e: PopError) -> RecvError {
    match e {
        PopError::Empty => RecvError::Empty,
        PopError::Disconnected => RecvError::Disconnected,
    }
}
