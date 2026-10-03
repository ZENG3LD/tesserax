//! NCP tier scaffolding (design §5): one roster, one downward client and
//! one oracle per tier, and exactly one tier builder per binary.
//!
//! ```text
//!   tier above ◄── AttachListener (AcceptIn: roster id + link proof)
//!   this tier  ──► DownLink (DialOut: the ONLY client type, points down)
//!        └── spawn_poller: parallel oracle pulls ──► FleetCache (Published)
//! ```
//!
//! The rule "no client for the tier above" (NCP §11c) is mechanical, not
//! prose: each tier's code sits behind its own cargo feature (`node`,
//! `c2`, `hq` — default: none), a binary builds with exactly its own tier,
//! so no symbol of the tier above exists in it. The shared modules
//! ([`roster`], [`link`], [`oracle`]) know only "below". The single
//! client constructor is [`DownLink`]; tier builders have no method that
//! takes an endpoint to report to.
//!
//! Supervision is not control (§5.4): a tier reads the health of the tier
//! below over the link it already holds ([`DownLink::health`]). The root
//! server's `/health`, `/livez`, `/readyz` stay read-only loopback
//! endpoints for a process supervisor; they have no type here.
//!
//! # Contract
//!
//! ```text
//! Role:      shell (fleet wiring over the SWC port contract; no kernel types here)
//! Owns:      per process: one roster (immutable after load), one DownLink per roster
//!            entry, one poller task per fleet, attach listeners for AcceptIn entries.
//! Exports:   shared: EntryId, Reach, CredentialSource, LinkSpec, DialEntry, RosterEntry,
//!            LinkTarget, Roster, RosterSource, RosterError, DownLink, RawResponse, LinkError,
//!            LinkCursor, Incarnation, LinkEvent, LinkEventKind, AttachListener, AttachError,
//!            LinkStream, Oracle, OracleError, OracleView, FleetCache, PollConfig, spawn_poller,
//!            Identified, Reconciled, reconcile, TierKind, NcpError;
//!            feature c2: C2Builder, C2, PassthroughPolicy, AllowRule, PathTemplate;
//!            feature hq: the HQ builder; feature node: NodeBuilder, Node, ServiceRoster,
//!            NodeService, dial_attach, AttachLink; feature node-os: node::os.
//! Imports:   tesserax (default-features = false), tesserax-transport, serde, toml, tokio,
//!            futures-util, hyper, http-body-util, bytes, zeroize.
//! Forbidden: any client or builder method addressing the tier above; insert / remove on
//!            a loaded roster (operator edit + restart, NCP §5); OS-process APIs
//!            outside `node/os.rs` (checked by tests/ncp_gates.rs); product vocabulary.
//! ```

mod link;
mod oracle;
mod roster;

#[cfg(feature = "c2")]
pub mod c2;
#[cfg(feature = "hq")]
pub mod hq;
#[cfg(feature = "node")]
pub mod node;

pub use link::{
    AttachError, AttachListener, DownLink, Incarnation, LinkCursor, LinkError, LinkEvent,
    LinkEventKind, LinkStream, Method, RawResponse,
};
pub use oracle::{
    FleetCache, Identified, Oracle, OracleError, OracleView, PollConfig, Reconciled, reconcile,
    spawn_poller, spawn_poller_with,
};
pub use roster::{
    CredentialSource, DialEntry, EntryId, EnvLookup, LinkSpec, LinkTarget, Reach, Roster,
    RosterEntry, RosterError, RosterSource,
};

use thiserror::Error;

/// The three tier kinds. Documentation and tests only: no runtime code
/// branches on it — the tier of a binary is decided by its cargo feature,
/// not by a value (NCP §11c).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TierKind {
    /// Edge process that wraps local services and dials the tier above.
    Node,
    /// Middle tier: routes, mirrors, resyncs, persists; never touches an
    /// OS process.
    C2,
    /// Top tier; the only one that may name C2 links as "below".
    Hq,
}

/// Every failure of the NCP scaffolding by layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NcpError {
    /// Roster load or validation failed.
    #[error("roster: {0}")]
    Roster(#[from] RosterError),
    /// A down link failed.
    #[error("link: {0}")]
    Link(#[from] LinkError),
    /// An attach (AcceptIn admission) failed.
    #[error("attach: {0}")]
    Attach(#[from] AttachError),
    /// An oracle pull failed.
    #[error("oracle: {0}")]
    Oracle(#[from] OracleError),
}
