//! [`Server`] (built, not yet listening) and [`RunningServer`] (feature `server`).
//!
//! Built-in routes:
//!
//! | route | tier | answer |
//! |---|---|---|
//! | `GET /health` | Public | `{"ok":true}`, or the detailed report (200 / 503) |
//! | `GET /livez` | Public | `{"ok":true}` while the process answers |
//! | `GET /readyz` | Public | `{"ready":true,"reason":null}`; 503 `{"ready":false,"reason":"draining"}` once draining |
//! | `POST /admin/drain` | Admin | sets the drain flag, `{"ok":true,"draining":true}` |
//! | `POST /reload` | Admin | only with `with_reload`: runs `on_reload`, `{"ok":true,"message":"reload accepted"}` |
//!
//! `/admin/drain` and `/reload` sit in the gated sub-router with the user
//! routes; the three probes stay outside the gate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde_json::json;
use tracing::{error, info, warn};

use crate::builder::{Assembly, BackgroundTaskSpec, LayerStage, ServerPlugin, StartedInfo};
use crate::config::Transport;
use crate::error::RunError;
use crate::lifecycle::{
    BackgroundTask, BindRetryPolicy, DependencyCheck, DrainState, HealthState, LifecycleCtx,
    OnReload, OnStart, OnStop, ShutdownBroadcast, bind_with_retry, graceful_shutdown_signal,
    readiness,
};
use crate::listener::{ListenerAddr, ListenerDriver};
use crate::route_table::{HttpMethod, RouteEntry, RouteTable};
use crate::tier::Tier;

const REQUEST_ID_HEADER: &str = "x-request-id";

/// Table entries of the built-in routes.
pub(crate) fn builtin_entries(reload: bool) -> Vec<RouteEntry> {
    let mut v = vec![
        RouteEntry::new(HttpMethod::Get, "/health", Tier::Public),
        RouteEntry::new(HttpMethod::Get, "/livez", Tier::Public),
        RouteEntry::new(HttpMethod::Get, "/readyz", Tier::Public),
        RouteEntry::new(HttpMethod::Post, "/admin/drain", Tier::Admin),
    ];
    if reload {
        v.push(RouteEntry::new(HttpMethod::Post, "/reload", Tier::Admin));
    }
    for e in &mut v {
        e.builtin = true;
    }
    v
}

/// Everything `ServerBuilder::build` hands over after validation.
pub(crate) struct Parts {
    pub(crate) name: Arc<str>,
    pub(crate) version: Option<String>,
    pub(crate) transport: Transport,
    pub(crate) bind: SocketAddr,
    pub(crate) driver: Option<Arc<dyn ListenerDriver>>,
    pub(crate) asm: Assembly,
    pub(crate) plugins: Vec<Box<dyn ServerPlugin>>,
    pub(crate) background_tasks: Vec<BackgroundTaskSpec>,
    pub(crate) bind_retry: BindRetryPolicy,
    pub(crate) on_start: Option<OnStart>,
    pub(crate) on_stop: Option<OnStop>,
    pub(crate) on_reload: Option<OnReload>,
    pub(crate) dependency_checks: Vec<DependencyCheck>,
    pub(crate) detail_health: bool,
    pub(crate) request_id: bool,
    pub(crate) body_size_limit: Option<usize>,
    pub(crate) shutdown_timeout: Duration,
    pub(crate) reload_endpoint: bool,
    pub(crate) auto_extensions: bool,
}

/// A validated server, ready to [`start`](Self::start).
pub struct Server {
    name: Arc<str>,
    transport: Transport,
    bind: SocketAddr,
    driver: Option<Arc<dyn ListenerDriver>>,
    router: Router,
    table: Arc<RouteTable>,
    drain: DrainState,
    shutdown_bx: ShutdownBroadcast,
    plugins: Vec<Box<dyn ServerPlugin>>,
    background_tasks: Vec<BackgroundTaskSpec>,
    bind_retry: BindRetryPolicy,
    on_start: Option<OnStart>,
    on_stop: Option<OnStop>,
    shutdown_timeout: Duration,
}

pub(crate) fn assemble(p: Parts) -> Server {
    let Parts {
        name,
        version,
        transport,
        bind,
        driver,
        mut asm,
        plugins,
        background_tasks,
        bind_retry,
        on_start,
        on_stop,
        on_reload,
        dependency_checks,
        detail_health,
        request_id,
        body_size_limit,
        shutdown_timeout,
        reload_endpoint,
        auto_extensions,
    } = p;
    let table = Arc::new(asm.table.clone());
    let drain = DrainState::new();
    let shutdown_bx = ShutdownBroadcast::new();
    let ctx = LifecycleCtx {
        name: Arc::clone(&name),
        bind,
    };

    // Gated sub-router: user and plugin routes plus the admin built-ins.
    let mut gated = Router::new();
    for (path, handler) in std::mem::take(&mut asm.handlers) {
        gated = gated.route(&path, handler);
    }
    let d = drain.clone();
    gated = gated.route(
        "/admin/drain",
        axum::routing::post(move || {
            let d = d.clone();
            async move {
                d.drain();
                warn!("/admin/drain: readiness probe now fails");
                Json(json!({"ok": true, "draining": true}))
            }
        }),
    );
    if reload_endpoint {
        let hook = on_reload;
        let ctx = ctx.clone();
        gated = gated.route(
            "/reload",
            axum::routing::post(move || {
                let hook = hook.clone();
                let ctx = ctx.clone();
                async move {
                    match hook {
                        Some(h) => match h(&ctx).await {
                            Ok(()) => (StatusCode::OK, Json(json!({"ok": true, "message": "reload accepted"}))),
                            Err(e) => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"ok": false, "error": "reload_failed", "reason": e.to_string()})),
                            ),
                        },
                        None => (StatusCode::OK, Json(json!({"ok": true, "message": "reload accepted"}))),
                    }
                }
            }),
        );
    }
    for stage in LayerStage::ALL.into_iter().filter(|s| s.is_route_scoped()) {
        for f in std::mem::take(&mut asm.stages[stage.index()]) {
            gated = f(gated);
        }
    }

    // Public probes outside the gate.
    let mut router = Router::new().merge(gated);
    if detail_health {
        let names = background_tasks.iter().map(|t| t.name.clone()).collect();
        let state = HealthState::new(name.to_string(), version, dependency_checks, names);
        router = router.route(
            "/health",
            axum::routing::get(move || {
                let state = state.clone();
                async move {
                    let report = state.report().await;
                    let status = if report.ok {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    };
                    let body = serde_json::to_value(&report)
                        .unwrap_or_else(|_| json!({"ok": false, "error": "serialize_failure"}));
                    (status, Json(body))
                }
            }),
        );
    } else {
        router = router.route(
            "/health",
            axum::routing::get(|| async { Json(json!({"ok": true})) }),
        );
    }
    router = router.route(
        "/livez",
        axum::routing::get(|| async { Json(json!({"ok": true})) }),
    );
    let d = drain.clone();
    router = router.route(
        "/readyz",
        axum::routing::get(move || {
            let d = d.clone();
            async move {
                let (ready, reason) = readiness(&d, true);
                let status = if ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                (status, Json(json!({"ready": ready, "reason": reason})))
            }
        }),
    );
    for r in std::mem::take(&mut asm.routers) {
        router = router.merge(r);
    }

    // Extensions innermost, so handlers see them under every layer.
    if auto_extensions {
        router = router
            .layer(axum::Extension(shutdown_bx.clone()))
            .layer(axum::Extension(drain.clone()))
            .layer(axum::Extension(Arc::clone(&table)));
    }
    for f in std::mem::take(&mut asm.extensions) {
        router = f(router);
    }

    // Whole-router stages, innermost first; the root's own layer of a stage
    // goes inside the ones installed there by extensions.
    for stage in LayerStage::ALL.into_iter().filter(|s| !s.is_route_scoped()) {
        match stage {
            LayerStage::BodyLimit => {
                if let Some(limit) = body_size_limit {
                    router = router
                        .layer(DefaultBodyLimit::max(limit))
                        .layer(middleware::from_fn(move |req: Request, next: Next| {
                            body_limit_layer(limit, req, next)
                        }));
                }
            }
            LayerStage::RequestId if request_id => {
                router = router.layer(middleware::from_fn(request_id_layer));
            }
            _ => {}
        }
        for f in std::mem::take(&mut asm.stages[stage.index()]) {
            router = f(router);
        }
    }

    Server {
        name,
        transport,
        bind,
        driver,
        router,
        table,
        drain,
        shutdown_bx,
        plugins,
        background_tasks,
        bind_retry,
        on_start,
        on_stop,
        shutdown_timeout,
    }
}

/// 413 when `Content-Length` announces more than `limit` bytes. Bodies
/// without a length are bounded by `DefaultBodyLimit` in the extractors.
async fn body_limit_layer(limit: usize, req: Request, next: Next) -> Response {
    let too_large = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > limit as u64);
    if too_large {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"ok": false, "error": "payload_too_large"})),
        )
            .into_response();
    }
    next.run(req).await
}

/// The id attached to every request that passes the request-id layer;
/// extract it with `Extension<RequestId>`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RequestId(Arc<str>);

impl RequestId {
    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Keeps an inbound `X-Request-Id` of at most 128 visible ASCII characters,
/// otherwise mints one; stores it as an extension and echoes it.
async fn request_id_layer(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|h| h.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_owned)
        .unwrap_or_else(mint_request_id);
    let id: Arc<str> = Arc::from(id.as_str());
    req.extensions_mut().insert(RequestId(Arc::clone(&id)));
    let mut resp = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    resp
}

/// UUID-shaped (version 4 layout) id from a per-process random hasher and a
/// counter: unique within the process, not a secret.
fn mint_request_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    static SEED: std::sync::OnceLock<std::collections::hash_map::RandomState> =
        std::sync::OnceLock::new();
    let seed = SEED.get_or_init(std::collections::hash_map::RandomState::new);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut h1 = seed.build_hasher();
    h1.write_u64(n);
    let a = h1.finish();
    let mut h2 = seed.build_hasher();
    h2.write_u64(!n);
    let b = h2.finish();
    let bits = (u128::from(a) << 64 | u128::from(b)) & !(0xF000u128 << 64) | (0x4000u128 << 64);
    let bits = bits & !(0xC000_0000_0000_0000u128) | 0x8000_0000_0000_0000u128;
    let hex = format!("{bits:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

impl Server {
    /// Server name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Configured transport.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Configured primary address (port 0 until started; `0.0.0.0:0` for a
    /// transport without a socket address, such as `Ipc`).
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Final route table.
    pub fn route_table(&self) -> &Arc<RouteTable> {
        &self.table
    }

    /// The assembled router (for in-process testing).
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Drain flag behind `/readyz`.
    pub fn drain_state(&self) -> DrainState {
        self.drain.clone()
    }

    /// Shutdown broadcast shared by listeners and background tasks.
    pub fn shutdown_broadcast(&self) -> ShutdownBroadcast {
        self.shutdown_bx.clone()
    }

    /// Runs `on_start`, starts background tasks, binds the listeners, starts
    /// serving and calls every plugin's `on_started`. Must run inside a
    /// tokio runtime.
    pub async fn start(self) -> Result<RunningServer, RunError> {
        let Server {
            name,
            transport,
            bind,
            driver,
            router,
            table,
            drain,
            shutdown_bx,
            mut plugins,
            background_tasks,
            bind_retry,
            on_start,
            on_stop,
            shutdown_timeout,
        } = self;
        let ctx = LifecycleCtx {
            name: Arc::clone(&name),
            bind,
        };
        if let Some(h) = on_start.as_ref() {
            h(&ctx)
                .await
                .map_err(|e| RunError::Lifecycle(format!("on_start: {e}")))?;
        }

        // A driver binds before background tasks start, like the TCP path.
        let (primary, local_addr, local_path) = match driver.as_ref() {
            Some(d) => {
                let mut rx = shutdown_bx.subscribe();
                let signal = Box::pin(async move {
                    let _ = rx.recv().await;
                });
                let (local, fut) = d
                    .start(&transport, router.clone(), signal)
                    .await?
                    .into_parts();
                match local {
                    ListenerAddr::Socket(a) => (Primary::Driven(fut), a, None),
                    ListenerAddr::Path(p) => (Primary::Driven(fut), bind, Some(p)),
                }
            }
            None => {
                let l = bind_with_retry(bind, &bind_retry).await?;
                let a = l.local_addr()?;
                (Primary::Tcp(l), a, None)
            }
        };
        let admin = match transport.admin_addr() {
            Some(addr) if matches!(primary, Primary::Tcp(_)) => {
                let l = bind_with_retry(addr, &bind_retry).await?;
                let a = l.local_addr()?;
                Some((l, a))
            }
            _ => None,
        };
        let admin_addr = admin.as_ref().map(|(_, a)| *a);
        match &local_path {
            Some(p) => info!(service = %name, path = %p.display(), "listening"),
            None => info!(service = %name, addr = %local_addr, "listening"),
        }

        let spawned: Vec<BackgroundTask> = background_tasks
            .into_iter()
            .map(|spec| {
                let work = Arc::clone(&spec.work);
                BackgroundTask::spawn(spec.name.as_str(), spec.period, &shutdown_bx, move || {
                    work()
                })
            })
            .collect();

        let serve = |listener: tokio::net::TcpListener, router: Router, label: &'static str| {
            let mut rx = shutdown_bx.subscribe();
            let name = Arc::clone(&name);
            tokio::spawn(async move {
                let serve = axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(async move {
                    let _ = rx.recv().await;
                });
                if let Err(e) = serve.await {
                    error!(service = %name, listener = label, "serve exited: {e}");
                }
            })
        };
        let admin_handle = admin.map(|(l, a)| {
            info!(service = %name, addr = %a, "admin listening");
            serve(l, router.clone(), "admin")
        });
        let serve_handle = match primary {
            Primary::Driven(fut) => tokio::spawn(fut),
            Primary::Tcp(l) => serve(l, router, "public"),
        };

        let info = StartedInfo {
            name: Arc::clone(&name),
            local_addr,
            admin_addr,
            local_path: local_path.clone(),
            route_table: table,
        };
        for p in &mut plugins {
            p.on_started(&info);
        }

        Ok(RunningServer {
            name,
            ctx,
            local_addr,
            admin_addr,
            local_path,
            drain,
            shutdown_bx,
            shutdown_timeout,
            serve_handle: Some(serve_handle),
            admin_handle,
            background_tasks: spawned,
            on_stop,
        })
    }

    /// Starts and serves until SIGINT/SIGTERM, then drains.
    pub async fn run(self) -> Result<(), RunError> {
        self.start().await?.wait_for_signal().await
    }
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("name", &self.name)
            .field("transport", &self.transport)
            .field("routes", &self.table.len())
            .finish_non_exhaustive()
    }
}

/// The primary listener: the root's own TCP loop or a driver's serve future.
enum Primary {
    Tcp(tokio::net::TcpListener),
    Driven(crate::lifecycle::BoxFuture<'static, ()>),
}

/// Status of one background task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackgroundTaskStatus {
    /// Task name.
    pub name: String,
    /// True once the task has finished.
    pub finished: bool,
}

/// A server that is listening.
pub struct RunningServer {
    name: Arc<str>,
    ctx: LifecycleCtx,
    local_addr: SocketAddr,
    admin_addr: Option<SocketAddr>,
    local_path: Option<std::path::PathBuf>,
    drain: DrainState,
    shutdown_bx: ShutdownBroadcast,
    shutdown_timeout: Duration,
    serve_handle: Option<tokio::task::JoinHandle<()>>,
    admin_handle: Option<tokio::task::JoinHandle<()>>,
    background_tasks: Vec<BackgroundTask>,
    on_stop: Option<OnStop>,
}

impl RunningServer {
    /// Server name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Bound primary address (the actual port when 0 was configured).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Bound admin address of a dual transport.
    pub fn admin_addr(&self) -> Option<SocketAddr> {
        self.admin_addr
    }

    /// Socket path or pipe name when a listener driver bound one (`Ipc`);
    /// `local_addr` is then the placeholder `0.0.0.0:0`.
    pub fn local_path(&self) -> Option<&std::path::Path> {
        self.local_path.as_deref()
    }

    /// Drain flag behind `/readyz`.
    pub fn drain_state(&self) -> DrainState {
        self.drain.clone()
    }

    /// Shutdown broadcast (to wire a custom shutdown trigger).
    pub fn shutdown_broadcast(&self) -> ShutdownBroadcast {
        self.shutdown_bx.clone()
    }

    /// Per-task status.
    pub fn background_status(&self) -> Vec<BackgroundTaskStatus> {
        self.background_tasks
            .iter()
            .map(|t| BackgroundTaskStatus {
                name: t.name().to_owned(),
                finished: t.is_finished(),
            })
            .collect()
    }

    /// Fires the shutdown broadcast; does not wait.
    pub fn shutdown(&self) {
        let reached = self.shutdown_bx.fire();
        info!(service = %self.name, reached, "shutdown fired");
    }

    /// Waits for the listeners (each bounded by the shutdown timeout) and
    /// background tasks (5 s each) to drain, then runs `on_stop` (10 s).
    /// Call after shutdown was triggered.
    pub async fn wait(mut self) -> Result<(), RunError> {
        for (label, handle) in [
            ("public", self.serve_handle.take()),
            ("admin", self.admin_handle.take()),
        ] {
            if let Some(h) = handle
                && tokio::time::timeout(self.shutdown_timeout, h)
                    .await
                    .is_err()
            {
                warn!(service = %self.name, listener = label, "drain exceeded {:?}", self.shutdown_timeout);
            }
        }
        self.shutdown_bx.fire();
        for task in self.background_tasks.drain(..) {
            let task_name = task.name().to_owned();
            if tokio::time::timeout(Duration::from_secs(5), task.detach())
                .await
                .is_err()
            {
                warn!(service = %self.name, task = %task_name, "background task drain timed out");
            }
        }
        if let Some(h) = self.on_stop.as_ref() {
            match tokio::time::timeout(Duration::from_secs(10), h(&self.ctx)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(service = %self.name, "on_stop error: {e}"),
                Err(_) => warn!(service = %self.name, "on_stop timed out"),
            }
        }
        info!(service = %self.name, "stopped");
        Ok(())
    }

    /// Waits for SIGINT/SIGTERM, fires shutdown and drains.
    pub async fn wait_for_signal(self) -> Result<(), RunError> {
        graceful_shutdown_signal().await;
        self.shutdown_bx.fire();
        self.wait().await
    }
}

impl std::fmt::Debug for RunningServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningServer")
            .field("name", &self.name)
            .field("local_addr", &self.local_addr)
            .field("admin_addr", &self.admin_addr)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_ids_are_uuid_shaped_and_distinct() {
        let a = mint_request_id();
        let b = mint_request_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(a.matches('-').count(), 4);
        assert_eq!(&a[14..15], "4");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"));
    }
}
