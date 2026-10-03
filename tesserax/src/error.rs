//! Error types of the root crate.
//!
//! Each enum belongs to one module and is re-exported there; they are
//! collected here so the whole failure surface of the root is readable in one
//! place. None of them carries a lock guard, a channel or a payload the caller
//! handed in, so every error is `Clone + Eq` and cheap to move across threads.

use thiserror::Error;

/// Why [`Port::dispatch`](crate::swc::Port::dispatch) refused a command.
///
/// Dispatch never blocks: a full ingress is reported, not waited on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Error)]
pub enum DispatchError {
    /// The bounded ingress is at capacity. The command was not enqueued;
    /// the caller keeps it and retries later.
    #[error("command ingress is full")]
    Full,
    /// The kernel side of the port is gone; no command will ever be drained.
    #[error("kernel ingress is disconnected")]
    Disconnected,
    /// The handle's command-id counter reached `u64::MAX`. Only
    /// [`Port::dispatch_envelope`](crate::swc::Port::dispatch_envelope) with
    /// caller-assigned ids still works.
    #[error("command id space is exhausted")]
    IdsExhausted,
}

/// Why [`Port::subscribe`](crate::swc::Port::subscribe) refused a subscriber.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Error)]
pub enum SubscribeError {
    /// The port already serves its configured maximum of live subscribers.
    #[error("subscriber limit reached")]
    TooManySubscribers,
}

/// Why [`KernelPort::publish`](crate::swc::KernelPort::publish) refused a
/// batch. A refused batch changes nothing: no event is logged or delivered and
/// the snapshot is not swapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Error)]
pub enum PublishError {
    /// Event sequences must continue the log strictly by +1.
    #[error("event sequence {found} does not follow {expected_previous}")]
    SequenceGap {
        /// Sequence of the last event already published (or the previous event of the batch).
        expected_previous: u64,
        /// Sequence the offending event carries.
        found: u64,
    },
    /// `snapshot.through_sequence` must equal the last published sequence
    /// after this batch.
    #[error("snapshot claims through_sequence {found}, the log ends at {expected}")]
    ThroughSequenceMismatch {
        /// Last sequence of the log after this batch.
        expected: u64,
        /// What the snapshot carried.
        found: u64,
    },
    /// `CoreEvent::ResyncRequired` is produced by the edge for one slow
    /// subscriber; a kernel never publishes it into the log.
    #[error("event {sequence} is ResyncRequired, which only the edge may emit")]
    EdgeOnlyEvent {
        /// Sequence the offending event carries.
        sequence: u64,
    },
    /// Snapshot revisions never go backwards.
    #[error("snapshot revision {found} is behind the published revision {current}")]
    RevisionRegressed {
        /// Revision currently published.
        current: u64,
        /// Revision the new snapshot carries.
        found: u64,
    },
}

/// Why a [`SubscriptionSender::try_send`](crate::swc::SubscriptionSender::try_send) failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Error)]
pub enum SendError {
    /// The subscriber's queue is at capacity.
    #[error("subscription queue is full")]
    Full,
    /// The subscriber dropped its [`Subscription`](crate::swc::Subscription),
    /// or the sender side was already closed.
    #[error("subscription is closed")]
    Closed,
}

/// Why a [`Subscription`](crate::swc::Subscription) receive returned no event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Error)]
pub enum RecvError {
    /// No event is queued right now (or the timeout elapsed).
    #[error("no event queued")]
    Empty,
    /// The queue is drained and the publisher disconnected this subscriber
    /// (slow consumer, or the kernel side is gone). Nothing more will arrive.
    #[error("subscription is disconnected")]
    Disconnected,
}

/// Why a [`Scope`](crate::tier::Scope), [`KeyId`](crate::principal::KeyId)
/// or [`DoorName`](crate::principal::DoorName) string was refused.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Error)]
pub enum NameError {
    /// Empty string.
    #[error("name is empty")]
    Empty,
    /// Longer than [`MAX_NAME_LEN`](crate::tier::MAX_NAME_LEN) bytes.
    #[error("name is {len} bytes, the limit is {max}")]
    TooLong {
        /// Length of the offered name in bytes.
        len: usize,
        /// Maximum length in bytes.
        max: usize,
    },
    /// Contains a character outside `[A-Za-z0-9._:-]`.
    #[error("name contains the disallowed character {0:?}")]
    BadChar(char),
}

/// Why a CIDR string was refused by [`Cidr::parse`](crate::net::Cidr::parse).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Error)]
pub enum CidrError {
    /// The address part is not an IPv4 or IPv6 address.
    #[error("bad ip address {0:?}")]
    BadAddress(String),
    /// The prefix part is not a number.
    #[error("bad prefix length {0:?}")]
    BadPrefix(String),
    /// The prefix is longer than the address family allows.
    #[error("prefix /{prefix_len} exceeds /{max}")]
    PrefixTooLong {
        /// Offered prefix length.
        prefix_len: u8,
        /// 32 for IPv4, 128 for IPv6.
        max: u8,
    },
}

/// Why [`ServerBuilder::build`](crate::builder::ServerBuilder::build) refused
/// to build. Setters never fail; everything is validated here.
#[cfg(feature = "server")]
#[derive(Debug, Error)]
pub enum BuildError {
    /// No [`Transport`](crate::config::Transport) was set.
    #[error("no transport set: call .transport(...)")]
    MissingTransport,
    /// A route template is not usable (must start with `/`).
    #[error("route {method} {path:?} is invalid: {reason}")]
    InvalidRoute {
        /// Verb.
        method: crate::route_table::HttpMethod,
        /// Template.
        path: String,
        /// What is wrong.
        reason: &'static str,
    },
    /// The same `(method, path)` was registered twice (built-in routes count).
    #[error("route {method} {path} is registered twice")]
    DuplicateRoute {
        /// Verb.
        method: crate::route_table::HttpMethod,
        /// Template.
        path: String,
    },
    /// A route at `Admin` or `Root` would be served without any gate at the
    /// `TierGate` stage on a transport reachable from other hosts.
    #[error(
        "route {method} {path} requires {tier} but no gate is installed at LayerStage::TierGate \
         and the transport is reachable from other hosts"
    )]
    UnauthenticatedAdminRoute {
        /// Verb.
        method: crate::route_table::HttpMethod,
        /// Template.
        path: String,
        /// Tier the route declares.
        tier: crate::tier::Tier,
    },
    /// The transport needs an accept loop the root does not provide.
    #[error(
        "transport {kind} has no accept loop in this build; add the transport extension that provides it"
    )]
    TransportNotWired {
        /// Transport kind.
        kind: &'static str,
    },
    /// A plugin refused the build.
    #[error("plugin {plugin} failed: {message}")]
    Plugin {
        /// Plugin name.
        plugin: &'static str,
        /// Reason.
        message: String,
    },
}

/// Why a built server failed to start or run.
#[cfg(feature = "server")]
#[derive(Debug, Error)]
pub enum RunError {
    /// A listener could not be bound.
    #[error(transparent)]
    Bind(#[from] crate::lifecycle::BindError),
    /// A lifecycle hook failed.
    #[error("lifecycle hook failed: {0}")]
    Lifecycle(String),
    /// Other IO failure, including a listener driver that could not bind.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
