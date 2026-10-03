//! [`WsHub`]: WebSocket pub/sub with exact-match topic filtering.
//!
//! Each outbound frame is the JSON of a [`WsEnvelope`]
//! (`{"topic":..,"payload":..}`). A socket may filter on one topic. With
//! [`WsHub::with_ping`] the server pings every `interval` and closes a
//! socket after `max_missed` unanswered pings (half-open connections held
//! by proxies). Inbound application frames are ignored.

use std::time::Duration;

use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

/// One published message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WsEnvelope {
    /// Topic a subscriber filters on.
    pub topic: String,
    /// Payload.
    pub payload: serde_json::Value,
}

/// Server-side ping liveness check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsPingConfig {
    /// Interval between pings.
    pub interval: Duration,
    /// Unanswered pings before the socket is closed.
    pub max_missed: u32,
}

impl Default for WsPingConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            max_missed: 2,
        }
    }
}

/// WebSocket hub. Cheap to clone.
#[derive(Clone)]
pub struct WsHub {
    tx: broadcast::Sender<WsEnvelope>,
    ping: Option<WsPingConfig>,
}

impl std::fmt::Debug for WsHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsHub")
            .field("subscribers", &self.tx.receiver_count())
            .field("ping", &self.ping)
            .finish()
    }
}

impl WsHub {
    /// `capacity` (at least 1): how far a socket may fall behind before it
    /// skips ahead.
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self { tx, ping: None }
    }

    /// Enables the ping liveness check.
    pub fn with_ping(mut self, cfg: WsPingConfig) -> Self {
        self.ping = Some(cfg);
        self
    }

    /// The ping configuration, if enabled.
    pub fn ping_config(&self) -> Option<WsPingConfig> {
        self.ping
    }

    /// Publishes to every socket whose filter matches; returns the number
    /// of live sockets.
    pub fn publish(&self, topic: impl Into<String>, payload: serde_json::Value) -> usize {
        self.tx
            .send(WsEnvelope {
                topic: topic.into(),
                payload,
            })
            .unwrap_or(0)
    }

    /// Live sockets.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Completes the upgrade; the socket receives envelopes whose topic
    /// equals `topic_filter` (all when `None`).
    pub fn handle_upgrade(
        &self,
        upgrade: WebSocketUpgrade,
        topic_filter: Option<String>,
    ) -> Response {
        let rx = self.tx.subscribe();
        let ping = self.ping;
        upgrade.on_upgrade(move |socket| run_socket(socket, rx, topic_filter, ping))
    }
}

async fn run_socket(
    mut socket: WebSocket,
    mut rx: broadcast::Receiver<WsEnvelope>,
    topic_filter: Option<String>,
    ping: Option<WsPingConfig>,
) {
    let mut ticker = ping.map(|c| {
        let mut i = tokio::time::interval(c.interval);
        i.reset();
        i
    });
    let mut missed: u32 = 0;
    loop {
        tokio::select! {
            biased;
            inbound = socket.recv() => match inbound {
                Some(Ok(Message::Pong(_))) => missed = 0,
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
            item = rx.recv() => {
                let env = match item {
                    Ok(e) => e,
                    Err(RecvError::Lagged(n)) => {
                        tracing::debug!(skipped = n, "ws: subscriber lagged");
                        continue;
                    }
                    Err(RecvError::Closed) => break,
                };
                if topic_filter.as_ref().is_some_and(|f| *f != env.topic) {
                    continue;
                }
                let Ok(body) = serde_json::to_string(&env) else { continue };
                if socket.send(Message::Text(Utf8Bytes::from(body))).await.is_err() {
                    break;
                }
            },
            _ = async {
                match ticker.as_mut() {
                    Some(i) => { i.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                let Some(cfg) = ping else { continue };
                if missed >= cfg.max_missed {
                    tracing::debug!("ws: pings unanswered, closing");
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
                missed = missed.saturating_add(1);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_with_no_subscriber_is_zero() {
        let hub = WsHub::new(8);
        assert_eq!(hub.publish("t", serde_json::json!({"x": 1})), 0);
    }

    #[test]
    fn ping_config() {
        assert_eq!(
            WsPingConfig::default(),
            WsPingConfig {
                interval: Duration::from_secs(30),
                max_missed: 2
            }
        );
        let hub = WsHub::new(8).with_ping(WsPingConfig {
            interval: Duration::from_secs(5),
            max_missed: 4,
        });
        assert_eq!(hub.ping_config().map(|c| c.max_missed), Some(4));
    }

    #[test]
    fn envelope_roundtrip() {
        let env = WsEnvelope {
            topic: "ticker.a".into(),
            payload: serde_json::json!({"price": 1.5}),
        };
        let s = serde_json::to_string(&env).unwrap();
        assert_eq!(s, r#"{"topic":"ticker.a","payload":{"price":1.5}}"#);
        assert_eq!(serde_json::from_str::<WsEnvelope>(&s).unwrap(), env);
    }
}
