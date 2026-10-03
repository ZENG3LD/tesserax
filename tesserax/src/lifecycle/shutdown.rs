//! [`ShutdownBroadcast`] — one producer side, many subscribers, message `()`.

use tokio::sync::broadcast;

/// Receiver handed to subscribers; `recv().await` resolves on shutdown.
pub type ShutdownReceiver = broadcast::Receiver<()>;

/// Fan-out shutdown notice. Clones share one channel. Firing more than
/// once has no further effect on a subscriber that already woke.
#[derive(Clone)]
pub struct ShutdownBroadcast {
    tx: broadcast::Sender<()>,
}

impl ShutdownBroadcast {
    /// New broadcast (buffer of one notice).
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(1);
        Self { tx }
    }

    /// Subscribes for the notice.
    pub fn subscribe(&self) -> ShutdownReceiver {
        self.tx.subscribe()
    }

    /// Fires the notice; returns how many subscribers were reached.
    pub fn fire(&self) -> usize {
        self.tx.send(()).unwrap_or(0)
    }

    /// Current subscriber count.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for ShutdownBroadcast {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ShutdownBroadcast {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownBroadcast")
            .field("receiver_count", &self.receiver_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fire_reaches_all_subscribers() {
        let bx = ShutdownBroadcast::new();
        let mut rx1 = bx.subscribe();
        let mut rx2 = bx.subscribe();
        assert_eq!(bx.receiver_count(), 2);
        assert_eq!(bx.fire(), 2);
        assert!(rx1.recv().await.is_ok());
        assert!(rx2.recv().await.is_ok());
    }

    #[tokio::test]
    async fn fire_with_no_subscribers_is_zero() {
        assert_eq!(ShutdownBroadcast::new().fire(), 0);
    }

    #[tokio::test]
    async fn stress_many_subscribers_all_receive() {
        const N: usize = 500;
        let bx = ShutdownBroadcast::new();
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let mut rx = bx.subscribe();
            handles.push(tokio::spawn(async move {
                tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
            }));
        }
        assert_eq!(bx.fire(), N);
        let mut received = 0;
        for h in handles {
            if h.await.unwrap_or(false) {
                received += 1;
            }
        }
        assert_eq!(received, N);
    }
}
