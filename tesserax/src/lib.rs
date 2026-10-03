//! `tesserax` — core of a back-office library family built on the
//! single-writer core (SWC) discipline: one writer per domain, a synchronous
//! kernel, and a contract of commands in, snapshots and events out.
//!
//! The always-compiled half carries the contract ([`swc`]) and the small
//! pure types every other part of a back office needs: access tiers and
//! scopes ([`tier`]), the authenticated caller ([`principal`]), the audit
//! seam ([`audit`]), CIDR and trusted-proxy helpers ([`net`]), lock-free
//! published values and flags ([`publish`]), a bounded LRU map ([`cache`]),
//! the family's single constant-time compare and HMAC-SHA256 ([`ct`]) and
//! the [`route_table`]. With `default-features = false` it depends on
//! `arc-swap`, `thiserror`, `sha2` and `subtle` only and compiles for
//! `wasm32-unknown-unknown`.
//!
//! The default feature `server` adds the shell half: a satellite-agnostic
//! HTTP server builder ([`builder`]) with fixed layer slots and plugins, the
//! running server ([`server`]), lifecycle primitives ([`lifecycle`]),
//! listener profiles ([`config`]) and the [`listener`] driver hook through
//! which a transport crate supplies the accept loop of `Tls` / `Ipc`.
//!
//! # Contract
//!
//! ```text
//! Role:      types + handle (modules swc, tier, principal, audit, net, publish, cache, ct, route_table, error;
//!            always compiled)
//!            shell (feature `server`: modules builder, server, lifecycle, listener, config)
//! Owns:      no domain state. The port edge owns only the published snapshot, event-log ring and subscriber
//!            list of one port. `server`: the layer-slot table of one builder, listener tasks, shutdown
//!            broadcast, drain flag.
//! Exports:   swc::{CommandEnvelope, EffectEnvelope, ObservationEnvelope, EventEnvelope, CoreEvent, Snapshot,
//!            Handle, Port, KernelPort, bounded_port, ResyncReply, SnapshotCache}; Tier, TierSet, Scope, ScopeSet,
//!            Principal, KeyId, DoorName, AuditSink, AuditEvent; Cidr, CidrList, honest_client_ip; Published<T>,
//!            Flags, LruCache; RouteTable, RouteEntry, HttpMethod; ct::{ct_eq, ct_eq_str, ct_eq_array, hmac_sha256};
//!            feature server: ServerBuilder, Server, RunningServer, ServerPlugin, BuildCx, LayerStage, Transport,
//!            BuildError, RunError, lifecycle::*, listener::{ListenerDriver, DriverListener, ListenerAddr,
//!            ShutdownSignal} (the accept-loop hook transport crates use for Tls / Ipc).
//! Imports:   arc-swap, thiserror, sha2, subtle; feature serde: serde; feature server: tokio, axum, tracing, serde_json.
//! Forbidden: any other tesserax-* crate; database, crypto beyond sha2 (+ subtle for ct), outbound network clients; in the always-compiled
//!            modules: tokio, axum, tower, std::fs, sockets; reading any configuration file implicitly;
//!            any product, host or consumer name.
//! ```
//!
//! # Features
//!
//! - `server` (default) — the shell half; enables `serde`.
//! - `serde` — `Serialize`/`Deserialize` on the envelopes, events, snapshot,
//!   resync reply and the pure types, for ports that cross a process or
//!   network boundary.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod cache;
pub mod ct;
pub mod error;
pub mod net;
pub mod principal;
pub mod publish;
pub mod route_table;
pub mod swc;
pub mod tier;

#[cfg(feature = "server")]
pub mod builder;
#[cfg(feature = "server")]
pub mod config;
#[cfg(feature = "server")]
pub mod lifecycle;
#[cfg(feature = "server")]
pub mod listener;
#[cfg(feature = "server")]
pub mod server;

pub use audit::{AuditEvent, AuditSink, NullAuditSink};
pub use cache::LruCache;
pub use net::{Cidr, CidrList, honest_client_ip};
pub use principal::{DoorName, KeyId, Principal};
pub use publish::{Flags, Published};
pub use route_table::{HttpMethod, RouteEntry, RouteTable};
pub use tier::{Scope, ScopeSet, Tier, TierSet};

#[cfg(feature = "server")]
pub use builder::{BuildCx, LayerStage, ServerBuilder, ServerPlugin, StartedInfo};
#[cfg(feature = "server")]
pub use config::{ReloadConfig, TlsConfig, Transport};
#[cfg(feature = "server")]
pub use error::{BuildError, RunError};
#[cfg(feature = "server")]
pub use listener::{DriverListener, ListenerAddr, ListenerDriver, ShutdownSignal};
#[cfg(feature = "server")]
pub use server::{RequestId, RunningServer, Server};
