//! Transport shells over a port, and the remote handle that speaks to them.
//!
//! Role: shell. A kernel is reached through one contract, the root
//! [`Port`](tesserax::swc::Port); where it runs is deployment, not
//! architecture. These shells put a port on a wire, and
//! [`RemoteHandle`] puts the wire back behind the same `Port`:
//!
//! ```text
//!   in-process Handle ──► http_shell  ══ HTTP + SSE ═══► RemoteHandle ─┐
//!                    └──► local_shell ══ NDJSON over an ═► RemoteHandle ├─► impl Port
//!                                        owner-only socket / pipe       │
//!   in-process Handle ─────────────────────────────────────────────────┘
//! ```
//!
//! - feature `shell`: [`http_shell`] (a `DocRouter` of four routes) and
//!   [`local_shell`] (an accept loop on an `OwnerOnlyListener`).
//! - feature `client`: [`RemoteHandle`] over either, with [`HttpRemote`] /
//!   [`LocalRemote`].
//! - both: [`wire`] (the serde envelopes, public for other clients) and
//!   [`LinkKeys`].
//!
//! # Doors
//!
//! Every shell has two doors. **control** takes commands and answers
//! resync; **observe** serves the snapshot and the event stream. Over HTTP
//! each route is checked by the `AuthGate` restricted to its door, so an
//! observe-only key is refused on commands even when some other door's
//! policy would admit the path. Over the local link each door has its own
//! secret, bound into a mutual proof: a link proves one door and is served
//! that door's requests only.
//!
//! # Resync over the wire
//!
//! `resync(after)` returns the serving port's `ResyncReply` unchanged,
//! `gap` included. An event stream opened with a resume point (SSE
//! `Last-Event-ID` or `?after=`) replays the retained events first; if some
//! are gone it starts with a `resync` notice and continues with what is
//! retained. A subscriber cut as slow ends with a notice; the remote handle
//! turns that into the port's `ResyncRequired` marker.

#[cfg(feature = "shell")]
mod feed;
#[cfg(feature = "shell")]
mod http;
mod link;
#[cfg(feature = "shell")]
mod local;
#[cfg(feature = "client")]
mod remote;
pub mod wire;

#[cfg(feature = "shell")]
pub use self::http::{DEFAULT_SUBSCRIPTION_CAPACITY, ShellOpts, http_shell};
pub use self::link::{DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_FRAME_BYTES, LinkKeys};
#[cfg(feature = "shell")]
pub use self::local::{LocalShellOpts, local_shell};
#[cfg(feature = "client")]
pub use self::remote::{HttpRemote, LocalRemote, RemoteHandle};
pub use tesserax_transport::proof::LinkContext;
