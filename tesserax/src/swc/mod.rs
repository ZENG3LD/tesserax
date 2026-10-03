//! Single-writer core (SWC) contract: commands in, snapshots and events out.
//!
//! Role: types + handle. This module never needs an async runtime, a socket
//! or a file; it compiles for `wasm32-unknown-unknown`.
//!
//! ```text
//!   shells ── Port::dispatch ──► bounded ingress ──► KernelPort::drain_commands ─┐
//!                                                                                kernel tick
//!   shells ◄─ Port::snapshot ── ArcSwap<Snapshot> ◄─┐                           │
//!   shells ◄─ Subscription ◄── per-subscriber queue ◄┴─ KernelPort::publish ◄────┘
//!   shells ── Port::resync ──► event-log ring + snapshot (read under one lock)
//! ```
//!
//! Rules the types encode:
//! - **command**: one door ([`Port::dispatch`]); the ingress is bounded
//!   (≤ [`MAX_INGRESS_CAPACITY`]); a full ingress returns
//!   [`DispatchError::Full`] and never blocks.
//! - **effect / observation**: work leaves as an [`EffectEnvelope`] and its
//!   result comes back as an [`ObservationEnvelope`] with the same
//!   `operation_id`, `subject` and `generation`; the kernel drops stale
//!   generations.
//! - **event**: `sequence` rises strictly by +1 ([`KernelPort::publish`]
//!   refuses anything else); each subscriber has a bounded queue; a slow one
//!   gets [`CoreEvent::ResyncRequired`] and is disconnected, counted in
//!   [`PublishReport::disconnected_slow`].
//! - **snapshot**: immutable `Arc<Snapshot<S>>`, `revision` never goes back,
//!   `through_sequence` is the last event it reflects; readers never lock.
//! - **resync**: [`Port::resync`] returns the snapshot plus retained events;
//!   `gap` is true exactly when `after < oldest_available - 1` or
//!   `after > event_sequence` (the client is ahead of the log).
//! - **atomicity**: events are logged and the snapshot swapped under one edge
//!   lock, so a resync reply is always a consistent pair.
//!
//! The kernel itself holds no lock and no channel; everything with a lock
//! here is the edge, which belongs to the shell layer.

mod edge;
mod port;
mod queue;
mod resync;
mod snapshot_cache;
mod subscription;
mod types;

pub use edge::PublishReport;
pub use port::{
    Handle, KernelPort, MAX_EVENT_LOG_CAPACITY, MAX_INGRESS_CAPACITY, MAX_SUBSCRIBERS, Port,
    PortConfig, bounded_port, bounded_port_from,
};
pub use resync::ResyncReply;
pub use snapshot_cache::SnapshotCache;
pub use subscription::{
    MAX_SUBSCRIPTION_CAPACITY, Subscription, SubscriptionSender, subscription_channel,
};
pub use types::{
    CommandEnvelope, CommandId, CoreEvent, CoreHealth, EffectEnvelope, EventEnvelope, Generation,
    ObservationEnvelope, OperationId, Reject, RejectCode, Snapshot, Subject,
};

pub use crate::error::{DispatchError, PublishError, RecvError, SendError, SubscribeError};
