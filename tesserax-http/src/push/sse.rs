//! [`SseHub`]: Server-Sent Events with `id:` and `Last-Event-ID` resume.
//!
//! Every published event gets a strictly increasing id (the hub's own
//! counter, or a sequence the caller supplies, e.g. an SWC event sequence)
//! and is kept in a bounded history ring. A client that reconnects with
//! `Last-Event-ID: n` (browsers send it automatically) first receives every
//! retained event with id `> n`, then the live stream; the handover happens
//! under one lock, so nothing is delivered twice and nothing is skipped.
//!
//! When the events after `n` are no longer in the ring (the client was away
//! too long, or `n` is ahead of the hub after a restart), the stream opens
//! with one `event: resync` whose data is
//! `{"after":n,"oldest":<first retained id or null>,"last":<last id>}` and
//! continues with what is retained: the client refetches a snapshot, as an
//! SWC resync would. A subscriber that falls behind the live channel is
//! caught up from the ring the same way.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::stream::{self, Stream};
use serde::Serialize;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use crate::error::HttpError;

/// Header a reconnecting `EventSource` sends.
pub const LAST_EVENT_ID: &str = "last-event-id";

/// Event name of the gap notice.
pub const RESYNC_EVENT: &str = "resync";

/// One published event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseMessage {
    /// Strictly increasing id (`id:` line).
    pub id: u64,
    /// Optional event name (`event:` line).
    pub event: Option<Arc<str>>,
    /// Payload (`data:` lines).
    pub data: Arc<str>,
}

impl SseMessage {
    fn to_event(&self) -> Event {
        let mut ev = Event::default().id(self.id.to_string()).data(&*self.data);
        if let Some(name) = &self.event {
            ev = ev.event(&**name);
        }
        ev
    }
}

struct Ring {
    last_id: u64,
    items: VecDeque<SseMessage>,
}

struct Inner {
    ring: Mutex<Ring>,
    tx: broadcast::Sender<SseMessage>,
    history: usize,
    keep_alive: Duration,
}

/// SSE broadcast hub with resumable ids. Cheap to clone.
#[derive(Clone)]
pub struct SseHub {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SseHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SseHub")
            .field("history", &self.inner.history)
            .field("last_id", &self.last_id())
            .field("subscribers", &self.receiver_count())
            .finish()
    }
}

/// What a subscriber is sent before the live stream.
struct Backlog {
    resync: Option<Event>,
    items: VecDeque<SseMessage>,
    last_sent: u64,
}

impl SseHub {
    /// A hub that retains the last `history` events for resume and lets a
    /// live subscriber fall `capacity` events behind before it is caught
    /// up from the ring. Both are at least 1.
    pub fn new(capacity: usize, history: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self {
            inner: Arc::new(Inner {
                ring: Mutex::new(Ring {
                    last_id: 0,
                    items: VecDeque::new(),
                }),
                tx,
                history: history.max(1),
                keep_alive: Duration::from_secs(15),
            }),
        }
    }

    /// Keep-alive comment interval (default 15 s). Call before cloning.
    pub fn with_keep_alive(mut self, every: Duration) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.keep_alive = every;
        }
        self
    }

    fn ring(&self) -> MutexGuard<'_, Ring> {
        self.inner.ring.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Id of the last published event (0 before the first).
    pub fn last_id(&self) -> u64 {
        self.ring().last_id
    }

    /// Live subscribers.
    pub fn receiver_count(&self) -> usize {
        self.inner.tx.receiver_count()
    }

    /// Publishes `data` with the next id. Returns the id.
    pub fn publish(&self, data: impl Into<String>) -> u64 {
        let mut ring = self.ring();
        let id = ring.last_id.saturating_add(1);
        self.push(&mut ring, id, None, data.into());
        id
    }

    /// Publishes `data` under the event name `event` with the next id.
    pub fn publish_event(&self, event: &str, data: impl Into<String>) -> u64 {
        let mut ring = self.ring();
        let id = ring.last_id.saturating_add(1);
        self.push(&mut ring, id, Some(Arc::from(event)), data.into());
        id
    }

    /// Publishes `payload` as JSON with the next id.
    pub fn publish_json<T: Serialize>(&self, payload: &T) -> Result<u64, HttpError> {
        let s = serde_json::to_string(payload).map_err(|e| HttpError::Serialize(e.to_string()))?;
        Ok(self.publish(s))
    }

    /// Publishes with a caller-chosen id (e.g. the sequence of an SWC
    /// event). Ids must strictly increase; gaps are allowed.
    pub fn publish_with_id(
        &self,
        id: u64,
        event: Option<&str>,
        data: impl Into<String>,
    ) -> Result<(), HttpError> {
        let mut ring = self.ring();
        if id <= ring.last_id {
            return Err(HttpError::IdNotIncreasing {
                last: ring.last_id,
                offered: id,
            });
        }
        self.push(&mut ring, id, event.map(Arc::from), data.into());
        Ok(())
    }

    fn push(&self, ring: &mut Ring, id: u64, event: Option<Arc<str>>, data: String) {
        let msg = SseMessage {
            id,
            event,
            data: Arc::from(data.as_str()),
        };
        ring.last_id = id;
        ring.items.push_back(msg.clone());
        while ring.items.len() > self.inner.history {
            ring.items.pop_front();
        }
        // Sent under the ring lock: a subscriber that snapshots the ring
        // under the same lock sees each event either in the ring or on its
        // receiver, never both unfiltered and never neither.
        let _ = self.inner.tx.send(msg);
    }

    /// Events after `after` still in the ring, and whether some were lost.
    fn backlog(ring: &Ring, after: u64) -> Backlog {
        let oldest = ring.items.front().map(|m| m.id);
        let lost = after > ring.last_id
            || (after < ring.last_id && oldest.is_some_and(|o| o > after.saturating_add(1)));
        let resync = lost.then(|| {
            let data = serde_json::json!({"after": after, "oldest": oldest, "last": ring.last_id});
            Event::default().event(RESYNC_EVENT).data(data.to_string())
        });
        // After a restart (`after` ahead of the hub) everything retained is new.
        let last_sent = if after > ring.last_id { 0 } else { after };
        let items: VecDeque<SseMessage> = ring
            .items
            .iter()
            .filter(|m| m.id > last_sent)
            .cloned()
            .collect();
        Backlog {
            resync,
            items,
            last_sent,
        }
    }

    /// The event stream for one subscriber. `last_event_id = None` starts
    /// with the next published event; `Some(n)` replays retained events
    /// after `n` first.
    pub fn subscribe(
        &self,
        last_event_id: Option<u64>,
    ) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
        self.subscribe_inner(last_event_id, None)
    }

    /// As [`subscribe`](Self::subscribe), and the stream ends when
    /// `shutdown` fires (e.g. `tesserax::lifecycle::ShutdownBroadcast::subscribe`),
    /// so open event streams do not hold a graceful shutdown until its
    /// timeout.
    pub fn subscribe_until(
        &self,
        last_event_id: Option<u64>,
        shutdown: broadcast::Receiver<()>,
    ) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
        self.subscribe_inner(last_event_id, Some(shutdown))
    }

    fn subscribe_inner(
        &self,
        last_event_id: Option<u64>,
        shutdown: Option<broadcast::Receiver<()>>,
    ) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
        let (rx, backlog) = {
            let ring = self.ring();
            let rx = self.inner.tx.subscribe();
            let backlog = match last_event_id {
                Some(after) => Self::backlog(&ring, after),
                None => Backlog {
                    resync: None,
                    items: VecDeque::new(),
                    last_sent: ring.last_id,
                },
            };
            (rx, backlog)
        };
        let state = SubState {
            hub: self.clone(),
            rx,
            shutdown,
            pending_resync: backlog.resync,
            pending: backlog.items,
            last_sent: backlog.last_sent,
        };
        stream::unfold(state, |mut st| async move {
            let ev = st.next_event().await?;
            Some((Ok(ev), st))
        })
    }

    /// The SSE response for a request carrying `headers` (honours
    /// `Last-Event-ID`; an unparsable value starts fresh).
    pub fn response(&self, headers: &HeaderMap) -> Response {
        self.sse(self.subscribe_inner(last_event_id(headers), None))
    }

    /// As [`response`](Self::response); the stream ends when `shutdown`
    /// fires. In a handler: `Extension(sd): Extension<ShutdownBroadcast>`
    /// (injected by the root server) and `hub.response_until(&headers,
    /// sd.subscribe())`.
    pub fn response_until(
        &self,
        headers: &HeaderMap,
        shutdown: broadcast::Receiver<()>,
    ) -> Response {
        self.sse(self.subscribe_inner(last_event_id(headers), Some(shutdown)))
    }

    fn sse(&self, s: impl Stream<Item = Result<Event, Infallible>> + Send + 'static) -> Response {
        Sse::new(s)
            .keep_alive(KeepAlive::new().interval(self.inner.keep_alive))
            .into_response()
    }
}

fn last_event_id(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(LAST_EVENT_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

struct SubState {
    hub: SseHub,
    rx: broadcast::Receiver<SseMessage>,
    shutdown: Option<broadcast::Receiver<()>>,
    pending_resync: Option<Event>,
    pending: VecDeque<SseMessage>,
    last_sent: u64,
}

impl SubState {
    async fn next_event(&mut self) -> Option<Event> {
        if let Some(ev) = self.pending_resync.take() {
            return Some(ev);
        }
        loop {
            if let Some(m) = self.pending.pop_front() {
                if m.id > self.last_sent {
                    self.last_sent = m.id;
                    return Some(m.to_event());
                }
                continue;
            }
            let item = match self.shutdown.as_mut() {
                Some(sd) => tokio::select! {
                    biased;
                    _ = sd.recv() => return None,
                    item = self.rx.recv() => item,
                },
                None => self.rx.recv().await,
            };
            match item {
                Ok(m) if m.id > self.last_sent => {
                    self.last_sent = m.id;
                    return Some(m.to_event());
                }
                Ok(_) => continue,
                Err(RecvError::Lagged(_)) => {
                    let backlog = {
                        let ring = self.hub.ring();
                        SseHub::backlog(&ring, self.last_sent)
                    };
                    self.pending = backlog.items;
                    if let Some(ev) = backlog.resync {
                        return Some(ev);
                    }
                }
                Err(RecvError::Closed) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_increase_and_ring_is_bounded() {
        let hub = SseHub::new(8, 3);
        for i in 1..=5 {
            assert_eq!(hub.publish(format!("m{i}")), i);
        }
        let ring = hub.ring();
        assert_eq!(ring.items.len(), 3);
        assert_eq!(ring.items.front().map(|m| m.id), Some(3));
    }

    #[test]
    fn publish_with_id_rejects_non_increasing() {
        let hub = SseHub::new(8, 8);
        hub.publish_with_id(10, None, "a").unwrap();
        assert!(hub.publish_with_id(10, None, "b").is_err());
        assert!(hub.publish_with_id(9, None, "b").is_err());
        hub.publish_with_id(12, Some("tick"), "c").unwrap();
        assert_eq!(hub.last_id(), 12);
        assert_eq!(hub.publish("d"), 13);
    }

    #[test]
    fn backlog_gap_rule() {
        let hub = SseHub::new(8, 3);
        for i in 1..=5 {
            hub.publish(format!("m{i}"));
        }
        let ring = hub.ring();
        // Retained 3..=5: resuming after 2 is complete, after 1 is not.
        let b = SseHub::backlog(&ring, 2);
        assert!(b.resync.is_none());
        assert_eq!(
            b.items.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert!(SseHub::backlog(&ring, 1).resync.is_some());
        // Up to date: nothing to replay, no gap.
        let b = SseHub::backlog(&ring, 5);
        assert!(b.resync.is_none() && b.items.is_empty());
        // Ahead of the hub (restart): gap, everything retained replayed.
        let b = SseHub::backlog(&ring, 99);
        assert!(b.resync.is_some());
        assert_eq!(b.items.len(), 3);
    }
}
