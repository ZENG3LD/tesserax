//! Process lifecycle primitives of a server (feature `server`).
//!
//! - [`ShutdownBroadcast`] — one shutdown notice fanned out to the listeners
//!   and every background task.
//! - [`BackgroundTask`] — an interval task that stops when the broadcast
//!   fires.
//! - [`graceful_shutdown_signal`] — resolves on SIGINT/SIGTERM (Unix) or
//!   Ctrl-C (elsewhere).
//! - [`bind_with_retry`] — TCP bind with exponential backoff.
//! - [`DrainState`] / [`readiness`] — the drain flag behind `/readyz` and
//!   `POST /admin/drain`.
//! - [`HealthState`] / [`DependencyCheck`] — the detailed `/health` report.
//! - [`LifecycleCtx`], [`hook`] — start / stop / reload hooks.

mod background;
mod bind;
mod drain;
mod health;
mod hooks;
mod shutdown;
mod signal;

pub use background::BackgroundTask;
pub use bind::{BindError, BindRetryPolicy, bind_with_retry};
pub use drain::{DrainState, readiness};
pub use health::{DependencyCheck, DependencyStatus, HealthReport, HealthState};
pub use hooks::{BoxError, BoxFuture, HookFn, LifecycleCtx, OnReload, OnStart, OnStop, hook};
pub use shutdown::{ShutdownBroadcast, ShutdownReceiver};
pub use signal::graceful_shutdown_signal;
