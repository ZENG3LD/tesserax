//! The wire form both shells speak: serde envelopes over JSON.
//!
//! These types are public so that a client in another language, or a wasm
//! app implementing `Port` over fetch itself, can speak the same frames.
//!
//! # HTTP ([`http_shell`](super::http_shell))
//!
//! | route | door | request | answer |
//! |---|---|---|---|
//! | `POST /v1/commands` | control | [`CommandRequest`] | `202` [`Dispatched`], `503` / `409` [`ErrorBody`] |
//! | `GET /v1/snapshot` | observe | `If-None-Match` | `200` `Snapshot<S>` + `ETag: "<revision>"`, `304` |
//! | `GET /v1/events?after=N&capacity=K` | observe | `Last-Event-ID` | `text/event-stream` |
//! | `POST /v1/resync` | control | [`ResyncRequest`] | `200` `ResyncReply<V, S>` |
//!
//! The event stream sends one SSE message per [`EventEnvelope`] with
//! `id: <sequence>` and the envelope as JSON `data:`; when events are
//! missing it sends `event: resync` (no `id:`) whose data is a
//! [`ResyncNotice`]. A resume point (`Last-Event-ID`, else `after`) first
//! replays what the log still holds; a gap opens the stream with the
//! notice and continues with what is retained (as `tesserax_http`'s
//! `SseHub` does). A subscriber cut for being slow gets the notice and the
//! stream ends.
//!
//! # Local link ([`local_shell`](super::local_shell))
//!
//! One JSON value per line (NDJSON), each line at most the configured
//! frame size. The link opens with a handshake that picks one door and
//! proves both ends hold that door's secret ([`LinkHello`],
//! [`LinkServerFrame::Challenge`], [`LinkAuthenticate`],
//! [`LinkServerFrame::Ready`]). Then the client sends
//! [`LinkRequestFrame`]s and gets one [`LinkReplyFrame`] each, in order.
//! After [`LinkRequest::Subscribe`] is answered with
//! [`LinkReply::Subscribed`], the connection carries only
//! [`LinkStreamFrame`]s until either end closes it.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tesserax::swc::{
    CommandEnvelope, CommandId, DispatchError, EventEnvelope, ResyncReply, Snapshot, SubscribeError,
};

/// `POST`: enqueue a command (control door).
pub const COMMANDS_PATH: &str = "/v1/commands";
/// `GET`: current snapshot (observe door).
pub const SNAPSHOT_PATH: &str = "/v1/snapshot";
/// `GET`: event stream (observe door).
pub const EVENTS_PATH: &str = "/v1/events";
/// `POST`: snapshot plus retained events (control door).
pub const RESYNC_PATH: &str = "/v1/resync";
/// SSE event name of a [`ResyncNotice`].
pub const RESYNC_EVENT: &str = "resync";
/// Header a reconnecting `EventSource` sends.
pub const LAST_EVENT_ID: &str = "last-event-id";

/// Body of `POST /v1/commands`. With `id` the command keeps that id
/// (`Port::dispatch_envelope`, for forwarding shells); without, the port
/// assigns a fresh one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRequest<C> {
    /// Caller-assigned id, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<CommandId>,
    /// The domain command.
    pub command: C,
}

/// Answer to an accepted `POST /v1/commands`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dispatched {
    /// Id the command is correlated by in events.
    pub id: CommandId,
}

/// Body of `POST /v1/resync`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResyncRequest {
    /// Last sequence the client applied.
    pub after: u64,
}

/// Query of `GET /v1/events`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsQuery {
    /// Resume after this sequence (`Last-Event-ID` wins when both are sent).
    #[serde(default)]
    pub after: Option<u64>,
    /// Subscriber queue size on the serving port.
    #[serde(default)]
    pub capacity: Option<usize>,
}

/// Events the client did not get are gone from its view: it replaces its
/// state from a snapshot (or `resync`) and continues.
///
/// Same shape as `tesserax_http`'s SSE `resync` event, except that
/// `oldest` is always a number: the port's `oldest_available`
/// (`last + 1` when the log is empty).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResyncNotice {
    /// Last sequence delivered to (or resumed from by) this subscriber.
    pub after: u64,
    /// Oldest sequence the log still holds.
    pub oldest: u64,
    /// Last sequence published.
    pub last: u64,
}

/// Machine-readable error class of every refusal on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireError {
    /// `DispatchError::Full`: retry later.
    Full,
    /// `DispatchError::Disconnected`: the kernel is gone.
    Disconnected,
    /// `DispatchError::IdsExhausted`.
    IdsExhausted,
    /// `SubscribeError::TooManySubscribers`.
    TooManySubscribers,
    /// The request is not valid for this door.
    Unauthorized,
    /// The request could not be decoded.
    BadRequest,
    /// The shell could not serve the request (for example no thread for a
    /// subscriber).
    Unavailable,
}

impl WireError {
    /// Wire class of a dispatch refusal.
    pub fn from_dispatch(e: DispatchError) -> Self {
        match e {
            DispatchError::Full => Self::Full,
            DispatchError::Disconnected => Self::Disconnected,
            DispatchError::IdsExhausted => Self::IdsExhausted,
        }
    }

    /// The dispatch refusal this class stands for, if it is one.
    pub fn to_dispatch(self) -> Option<DispatchError> {
        match self {
            Self::Full => Some(DispatchError::Full),
            Self::Disconnected => Some(DispatchError::Disconnected),
            Self::IdsExhausted => Some(DispatchError::IdsExhausted),
            _ => None,
        }
    }

    /// Wire class of a subscribe refusal.
    pub fn from_subscribe(e: SubscribeError) -> Self {
        match e {
            SubscribeError::TooManySubscribers => Self::TooManySubscribers,
        }
    }

    /// The subscribe refusal this class stands for, if it is one.
    pub fn to_subscribe(self) -> Option<SubscribeError> {
        match self {
            Self::TooManySubscribers => Some(SubscribeError::TooManySubscribers),
            _ => None,
        }
    }

    /// The HTTP status the HTTP shell answers with.
    pub fn status(self) -> u16 {
        match self {
            Self::Full | Self::TooManySubscribers | Self::Unavailable => 503,
            Self::Disconnected => 410,
            Self::IdsExhausted => 409,
            Self::Unauthorized => 403,
            Self::BadRequest => 400,
        }
    }
}

/// JSON body of every HTTP refusal of the shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Always `false`.
    pub ok: bool,
    /// Error class.
    pub error: WireError,
    /// Human-readable detail (may be empty).
    #[serde(default)]
    pub message: String,
}

impl ErrorBody {
    /// A refusal of class `error`.
    pub fn new(error: WireError, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error,
            message: message.into(),
        }
    }
}

/// The two doors of a shell: commands and resync go through `control`,
/// snapshot and events through `observe`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkDoor {
    /// Dispatch and resync.
    Control,
    /// Snapshot and event stream.
    Observe,
}

impl LinkDoor {
    /// Role byte bound into the link proof (`1` control, `2` observe), so a
    /// proof for one door never passes for the other.
    pub fn role_byte(self) -> u8 {
        match self {
            Self::Control => 1,
            Self::Observe => 2,
        }
    }

    /// `control` or `observe`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Observe => "observe",
        }
    }
}

/// First line of a local link, client to server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkHello {
    /// Door the client asks for.
    pub door: LinkDoor,
    /// Fresh 32-byte client nonce, lower-case hex.
    pub nonce: String,
}

/// Server lines of the handshake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkServerFrame {
    /// The server's nonce and its proof for the requested door.
    Challenge {
        /// Fresh 32-byte server nonce, lower-case hex.
        nonce: String,
        /// Server proof, lower-case hex.
        proof: String,
    },
    /// The client's proof matched: requests may follow.
    Ready,
    /// The handshake failed; the server closes the link.
    Refused {
        /// Why (never secret material).
        reason: String,
    },
}

/// Second client line of the handshake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkAuthenticate {
    /// Client proof, lower-case hex.
    pub proof: String,
}

/// One request on a local link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum LinkRequest<C> {
    /// `Port::dispatch` (control).
    Dispatch {
        /// The domain command.
        command: C,
    },
    /// `Port::dispatch_envelope` (control).
    DispatchEnvelope {
        /// Command with its id.
        envelope: CommandEnvelope<C>,
    },
    /// `Port::snapshot` (observe); `NotModified` when the revision matches.
    Snapshot {
        /// Revision the client already holds.
        #[serde(default)]
        if_revision: Option<u64>,
    },
    /// `Port::resync` (control).
    Resync {
        /// Last sequence the client applied.
        after: u64,
    },
    /// `Port::subscribe` (observe); the link becomes an event stream.
    Subscribe {
        /// Subscriber queue size on the serving port.
        capacity: usize,
        /// Resume after this sequence (replay, or a notice on a gap).
        #[serde(default)]
        after: Option<u64>,
    },
}

/// A request with its correlation id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkRequestFrame<C> {
    /// Echoed in the reply.
    pub id: u64,
    /// The request.
    pub request: LinkRequest<C>,
}

/// One reply on a local link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkReply<V, S> {
    /// The command was enqueued under `id`.
    Dispatched {
        /// Command id.
        id: CommandId,
    },
    /// The current snapshot.
    Snapshot {
        /// Snapshot.
        snapshot: Arc<Snapshot<S>>,
    },
    /// The client's revision is current.
    NotModified {
        /// Current revision.
        revision: u64,
    },
    /// Snapshot plus retained events.
    Resync {
        /// The port's reply.
        reply: ResyncReply<V, S>,
    },
    /// The subscription exists; stream frames follow.
    Subscribed,
    /// The request was refused.
    Error {
        /// Error class.
        error: WireError,
        /// Human-readable detail.
        #[serde(default)]
        message: String,
    },
}

/// A reply with the id of its request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkReplyFrame<V, S> {
    /// Id of the request answered (0 when the request was unreadable).
    pub id: u64,
    /// The reply.
    pub reply: LinkReply<V, S>,
}

/// One frame of a subscribed local link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkStreamFrame<V> {
    /// A published event.
    Event {
        /// The event.
        event: EventEnvelope<V>,
    },
    /// Events are missing (see [`ResyncNotice`]).
    Resync {
        /// What is missing.
        notice: ResyncNotice,
    },
}

/// Lower-case hex of `bytes`.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Exactly `N` bytes from lower- or upper-case hex.
pub(crate) fn hex_decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let raw = text.as_bytes();
    if raw.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(raw.chunks_exact(2)) {
        let digit = |c: u8| char::from(c).to_digit(16);
        let (hi, lo) = (digit(pair[0])?, digit(pair[1])?);
        *slot = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex_encode(&bytes), "0001abff");
        assert_eq!(hex_decode::<4>("0001abff"), Some(bytes));
        assert_eq!(hex_decode::<4>("0001ABFF"), Some(bytes));
        assert_eq!(hex_decode::<4>("0001abf"), None);
        assert_eq!(hex_decode::<4>("0001abfg"), None);
        assert_eq!(hex_decode::<2>("0001abff"), None);
    }

    #[test]
    fn wire_error_maps_port_errors_both_ways() {
        for e in [
            DispatchError::Full,
            DispatchError::Disconnected,
            DispatchError::IdsExhausted,
        ] {
            assert_eq!(WireError::from_dispatch(e).to_dispatch(), Some(e));
        }
        let e = SubscribeError::TooManySubscribers;
        assert_eq!(WireError::from_subscribe(e).to_subscribe(), Some(e));
        assert_eq!(WireError::Unauthorized.to_dispatch(), None);
    }

    #[test]
    fn frames_have_a_stable_json_shape() {
        let req: LinkRequestFrame<u32> = LinkRequestFrame {
            id: 3,
            request: LinkRequest::Resync { after: 9 },
        };
        assert_eq!(
            serde_json::to_string(&req).ok().as_deref(),
            Some(r#"{"id":3,"request":{"op":"resync","after":9}}"#)
        );
        let body = ErrorBody::new(WireError::TooManySubscribers, "");
        assert_eq!(
            serde_json::to_string(&body).ok().as_deref(),
            Some(r#"{"ok":false,"error":"too_many_subscribers","message":""}"#)
        );
        let notice = LinkStreamFrame::<u32>::Resync {
            notice: ResyncNotice {
                after: 1,
                oldest: 4,
                last: 9,
            },
        };
        assert_eq!(
            serde_json::to_string(&notice).ok().as_deref(),
            Some(r#"{"kind":"resync","notice":{"after":1,"oldest":4,"last":9}}"#)
        );
    }
}
