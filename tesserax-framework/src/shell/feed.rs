//! The event feed of one remote subscriber: a port [`Subscription`] (a
//! blocking queue) turned into a bounded async channel of [`FeedItem`]s.
//!
//! A dedicated thread owns the subscription. It first replays what the log
//! holds after the resume point (announcing a gap with a [`ResyncNotice`]),
//! then forwards live events, skipping any the replay already sent. The
//! channel holds one item, so a slow link backs up into the subscription's
//! own bounded queue, where the port cuts it off as slow; that cut is sent
//! as a notice and ends the feed. The thread ends when the receiver is
//! dropped (checked at least every `poll`), dropping the subscription and
//! freeing its slot on the port.

use std::sync::Arc;
use std::time::Duration;

use tesserax::swc::{CoreEvent, EventEnvelope, Port, RecvError, Subscription};
use tokio::sync::mpsc;

use super::wire::ResyncNotice;

/// One item of a feed.
pub(crate) enum FeedItem<V> {
    Event(EventEnvelope<V>),
    Resync(ResyncNotice),
}

/// Starts the feed thread. `None` when no thread could be spawned (the
/// subscription is dropped at once).
pub(crate) fn start<P, C, V, S>(
    port: Arc<P>,
    subscription: Subscription<V>,
    resume_after: Option<u64>,
    poll: Duration,
) -> Option<mpsc::Receiver<FeedItem<V>>>
where
    P: Port<C, V, S> + ?Sized + 'static,
    C: 'static,
    V: Send + 'static,
    S: 'static,
{
    let (tx, rx) = mpsc::channel(1);
    let poll = poll.max(Duration::from_millis(1));
    std::thread::Builder::new()
        .name("tesserax-shell-feed".into())
        .spawn(move || run(&*port, subscription, resume_after, poll, &tx))
        .ok()?;
    Some(rx)
}

fn run<P, C, V, S>(
    port: &P,
    subscription: Subscription<V>,
    resume_after: Option<u64>,
    poll: Duration,
    tx: &mpsc::Sender<FeedItem<V>>,
) where
    P: Port<C, V, S> + ?Sized,
{
    // Everything up to `floor` was sent by the replay.
    let mut floor = 0;
    if let Some(after) = resume_after {
        let reply = port.resync(after);
        if reply.gap {
            let notice = ResyncNotice {
                after,
                oldest: reply.oldest_available,
                last: reply.event_sequence,
            };
            if tx.blocking_send(FeedItem::Resync(notice)).is_err() {
                return;
            }
        }
        floor = reply.event_sequence;
        for event in reply.events {
            if tx.blocking_send(FeedItem::Event(event)).is_err() {
                return;
            }
        }
    }
    loop {
        match subscription.recv_timeout(poll) {
            Ok(event) => {
                if let CoreEvent::ResyncRequired { oldest_available } = event.event {
                    let notice = ResyncNotice {
                        after: event.sequence.saturating_sub(1),
                        oldest: oldest_available,
                        last: port.resync(u64::MAX).event_sequence,
                    };
                    let _ = tx.blocking_send(FeedItem::Resync(notice));
                    return;
                }
                if event.sequence <= floor {
                    continue;
                }
                if tx.blocking_send(FeedItem::Event(event)).is_err() {
                    return;
                }
            }
            Err(RecvError::Empty) => {
                if tx.is_closed() {
                    return;
                }
            }
            Err(RecvError::Disconnected) => return,
        }
    }
}
