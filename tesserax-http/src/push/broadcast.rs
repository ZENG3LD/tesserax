//! [`BroadcastChannel<T>`]: a typed wrapper over `tokio::sync::broadcast`.
//!
//! One sender shared by every clone, any number of receivers. A receiver
//! that falls more than `capacity` messages behind sees
//! `RecvError::Lagged(n)` and decides whether to skip ahead or disconnect.

use tokio::sync::broadcast;

/// Typed broadcast bus. Cheap to clone.
#[derive(Clone)]
pub struct BroadcastChannel<T> {
    tx: broadcast::Sender<T>,
}

impl<T: Clone + Send + 'static> BroadcastChannel<T> {
    /// `capacity` (at least 1) is how far each receiver may fall behind.
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    /// A new receiver that sees messages sent from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<T> {
        self.tx.subscribe()
    }

    /// Sends to every current receiver; returns how many there were.
    pub fn send(&self, msg: T) -> usize {
        self.tx.send(msg).unwrap_or(0)
    }

    /// Current receivers.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// The underlying sender.
    pub fn sender(&self) -> &broadcast::Sender<T> {
        &self.tx
    }
}

impl<T> std::fmt::Debug for BroadcastChannel<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BroadcastChannel")
            .field("receiver_count", &self.tx.receiver_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_reaches_all_subscribers() {
        let bus = BroadcastChannel::<u32>::new(8);
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        assert_eq!(bus.send(42), 2);
        assert_eq!(a.recv().await.unwrap(), 42);
        assert_eq!(b.recv().await.unwrap(), 42);
    }

    #[test]
    fn send_with_no_subscribers_is_zero() {
        let bus = BroadcastChannel::<u32>::new(8);
        assert_eq!(bus.send(1), 0);
    }
}
