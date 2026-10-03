//! `tesserax-framework` — the back-office framework on `tesserax`: a
//! single-writer kernel for one [`Domain`], the [`Runtime`] that owns and
//! drives it, and [`Executor`]s that run the kernel's effects off its
//! thread and report back as observations.
//!
//! ```text
//!   products ── Handle::dispatch ──► port ingress ─┐
//!                                                  ▼
//!   Runtime tick:  inbox + ingress drain → Core::step → effects → publish ──► snapshot + events
//!                  ▲                                     │
//!                  └── ObservationSink ◄── Executor ◄────┘   (threads / tokio tasks / store)
//! ```
//!
//! - [`kernel`]: [`Domain`] (payload types + pure reducers), [`Tick`],
//!   [`Core`] and [`Step`]. Fixed phase order: advance the logical tick,
//!   commands in arrival order, generation-checked observations, project
//!   (revision +1 iff changed), stamp event sequences. Counters saturate
//!   into [`CoreHealth`](tesserax::swc::CoreHealth) and then commands are
//!   rejected with [`RejectCode::Exhausted`](tesserax::swc::RejectCode::Exhausted).
//! - [`runtime`]: [`Runtime`] (owns the core and the
//!   [`KernelPort`](tesserax::swc::KernelPort); ticks on its own thread or
//!   on demand), [`Executor`], [`ThreadExecutor`], [`ObservationSink`];
//!   feature `tokio`: `TokioExecutor`; feature `store`: `PersistExecutor`
//!   (flush acknowledgement through `tesserax-store`).
//! - `shell` (features `shell` / `client`): the port on a wire —
//!   `http_shell`, `local_shell`, and `RemoteHandle`, which implements the
//!   root `Port` over either wire and passes the same contract suite as
//!   the in-process `Handle`.
//! - [`FrameworkError`]: every failure of the framework by layer
//!   (kernel, runtime, shell); [`ShellError`] for the shells.
//!
//! The contract types (envelopes, `Handle`, `Port`, `SnapshotCache`,
//! resync) are the root crate's `tesserax::swc`; this crate adds the kernel
//! and the shells that drive it.
//!
//! # Contract
//!
//! ```text
//! Role:      kernel (module kernel); shell (modules runtime, shell)
//! Owns:      the kernel of one Domain (single writer: domain, counters, step bookkeeping); per runtime: the
//!            kernel side of one port, one bounded observation inbox, one executor.
//! Exports:   Domain, Tick, Core, CoreResume, CoreStats, CoreError, ObservationDrops, Step, Counter, Exhausted;
//!            Runtime, DomainHandle, RuntimeConfig, RuntimeHandle, RuntimeStats, RuntimeError, TickReport,
//!            Executor, Refusal, ThreadExecutor, ThreadExecutorConfig, ObservationSink, EffectTicket, SinkError,
//!            SinkRejected, SinkStats; feature tokio: TokioExecutor, TokioExecutorConfig; feature store: PersistExecutor,
//!            PersistConfig, PersistOutcome; FrameworkError, ShellError; feature shell: shell::{http_shell,
//!            ShellOpts, local_shell, LocalShellOpts}; feature client: shell::{RemoteHandle, HttpRemote,
//!            LocalRemote}; shell or client: shell::{wire, LinkKeys, LinkContext};
//!            tier features (node / c2 / hq, node-os): ncp::{TierKind, EntryId, Reach, CredentialSource,
//!            LinkSpec, DialEntry, Roster, DownLink, AttachListener, Oracle, FleetCache, spawn_poller,
//!            reconcile, PassthroughPolicy (c2), the tier builders, NcpError};
//!            feature agent: agent::{Verb, VerbCx, VerbCode, VerbError, AgentDoor, AgentSurface,
//!            VERBS_PATH_PREFIX}.
//! Imports:   tesserax (default-features = false), thiserror; feature tokio: tokio (rt, time);
//!            feature store: tesserax-store; feature shell: tesserax-auth, tesserax-http,
//!            tesserax-transport, axum, tokio, serde, tracing; feature client: tesserax-transport, hyper,
//!            tokio, serde; feature agent: tesserax-auth, tesserax-http, tesserax-mcp, axum, serde.
//! Forbidden: in `kernel`: tokio, locks, channels, atomics, threads, fs, network (SWC law 3 — checked by
//!            tests/kernel_purity.rs); a second door into the kernel beside the port and the observation
//!            sink; product vocabulary.
//! ```
//!
//! # Features
//!
//! - default: none — the kernel, the runtime and [`ThreadExecutor`] need
//!   only `std`.
//! - `tokio` — `TokioExecutor`: effects as tasks on a caller-owned tokio
//!   runtime.
//! - `store` — `PersistExecutor`: effects as `tesserax-store` batch writes,
//!   answered after a durability barrier.
//! - `shell` — `http_shell` (a `tesserax_http::DocRouter`, doors enforced
//!   by a `tesserax_auth::AuthGate`) and `local_shell` (on a
//!   `tesserax_transport` owner-only listener).
//! - `client` — `RemoteHandle` over HTTP or the local link.
//! - `node` / `c2` / `hq` — [`ncp`]: the NCP tier scaffolding (shared
//!   roster / down link / fleet oracle plus one builder per tier; a
//!   binary builds with exactly its own tier). `node-os` adds the node
//!   process supervisor.
//! - `agent` — [`agent`]: one [`Verb`](agent::Verb) answered over REST
//!   and MCP from a single registration, every mutating call audited
//!   inside the shared dispatch.
//!
//! Without features the dependency tree has no tokio, axum, tower,
//! rusqlite or reqwest.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "agent")]
pub mod agent;
mod error;
pub mod kernel;
#[cfg(feature = "ncp-shared")]
pub mod ncp;
pub mod runtime;
#[cfg(any(feature = "shell", feature = "client"))]
pub mod shell;

pub use error::{FrameworkError, ShellError};

pub use kernel::{
    Core, CoreError, CoreResume, CoreStats, Counter, Domain, Exhausted, ObservationDrops, Step,
    Tick,
};
pub use runtime::{
    DomainHandle, EffectTicket, Executor, ObservationSink, Refusal, Runtime, RuntimeConfig,
    RuntimeError, RuntimeHandle, RuntimeStats, SinkError, SinkRejected, SinkStats, ThreadExecutor,
    ThreadExecutorConfig, TickReport,
};
#[cfg(feature = "store")]
pub use runtime::{PersistConfig, PersistExecutor, PersistOutcome};
#[cfg(feature = "tokio")]
pub use runtime::{TokioExecutor, TokioExecutorConfig};
