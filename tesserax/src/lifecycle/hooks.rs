//! Start / stop / reload hooks.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

/// Boxed `Send` future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Error type of hooks, background tasks and plugins' fallible callbacks.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// What a hook is told about the server.
#[derive(Clone, Debug)]
pub struct LifecycleCtx {
    /// Server name.
    pub name: Arc<str>,
    /// Primary listener address as configured (port 0 until bound).
    pub bind: SocketAddr,
}

/// Shape shared by every hook.
pub type HookFn =
    dyn for<'a> Fn(&'a LifecycleCtx) -> BoxFuture<'a, Result<(), BoxError>> + Send + Sync + 'static;

/// Runs before the listeners bind; an error aborts start-up.
pub type OnStart = Arc<HookFn>;
/// Runs after the listeners drained; errors are logged.
pub type OnStop = Arc<HookFn>;
/// Runs on `POST /reload`; an error answers 500.
pub type OnReload = Arc<HookFn>;

/// Wraps an async closure into a hook.
pub fn hook<F, Fut>(f: F) -> Arc<HookFn>
where
    F: for<'a> Fn(&'a LifecycleCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), BoxError>> + Send + 'static,
{
    Arc::new(move |ctx| Box::pin(f(ctx)))
}
