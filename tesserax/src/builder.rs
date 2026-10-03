//! [`ServerBuilder`]: satellite-agnostic HTTP server assembly (feature `server`).
//!
//! The root knows no authentication scheme, database, security middleware or
//! metrics backend. It owns the route table, a fixed table of layer slots
//! ([`LayerStage`]), the lifecycle (hooks, background tasks, drain, shutdown)
//! and the built-in probes. Everything else arrives through
//! [`layer_at`](ServerBuilder::layer_at), [`extension`](ServerBuilder::extension)
//! and [`ServerPlugin`]s, typically wrapped in an extension trait by the crate
//! that owns the dependency.
//!
//! Setters never fail; [`build`](ServerBuilder::build) validates everything.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::MethodRouter;

use crate::config::{ReloadConfig, Transport};
use crate::error::BuildError;
use crate::lifecycle::{
    BindRetryPolicy, BoxError, BoxFuture, DependencyCheck, OnReload, OnStart, OnStop,
};
use crate::listener::ListenerDriver;
use crate::route_table::{HttpMethod, RouteEntry, RouteTable};
use crate::server::{self, Server};
use crate::tier::Tier;

/// A function that wraps a router in one or more layers.
pub type LayerFn = Box<dyn FnOnce(Router) -> Router + Send>;

/// Fixed slots of the middleware stack, innermost first.
///
/// A request passes the stages from the last ([`ServerTiming`](Self::ServerTiming),
/// outermost) to the first ([`Idempotency`](Self::Idempotency), innermost)
/// and the response travels back out. The order is the one the server
/// assembly has always used, kept as one table so each extension only
/// picks its slot.
///
/// `TierGate`, `TierRateLimit` and `Idempotency` wrap only the gated
/// sub-router (every route in the [`RouteTable`] except the public probes
/// `/health`, `/livez`, `/readyz`); a function installed there should use
/// `Router::route_layer`. Every other stage wraps the whole router. Routes
/// added with `merge_router` are outside all three.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum LayerStage {
    /// Idempotency-key replay cache. Inside the gate, so it can key the
    /// cache by the `Principal` the gate admitted (two callers never share
    /// a stored response), and inside the tier rate limit, so a refused
    /// (429) request never claims or fills a slot.
    Idempotency,
    /// Per-tier rate limit. Inside the gate, so it sees the `Principal` the
    /// gate admitted.
    TierRateLimit,
    /// Admission against the route table (authentication + tier/scope check).
    TierGate,
    /// Request body size limit (the root fills it from `with_body_size_limit`).
    BodyLimit,
    /// Request metrics.
    Metrics,
    /// `ETag` / conditional responses.
    Etag,
    /// CSRF protection.
    Csrf,
    /// Response signing (inside compression: peers verify the raw body).
    ResponseSigning,
    /// W3C `traceparent` propagation.
    Traceparent,
    /// `X-Request-Id` (the root fills it unless `without_request_id`).
    RequestId,
    /// Peer gatekeepers: IP allow/deny lists, ban lists.
    PeerGuard,
    /// Response compression.
    Compression,
    /// Response decoration: CORS, security headers.
    Decorate,
    /// One log line per request.
    AccessLog,
    /// `Server-Timing` (outermost: measures everything inside).
    ServerTiming,
}

impl LayerStage {
    /// Every stage, innermost first.
    pub const ALL: [LayerStage; 15] = [
        LayerStage::Idempotency,
        LayerStage::TierRateLimit,
        LayerStage::TierGate,
        LayerStage::BodyLimit,
        LayerStage::Metrics,
        LayerStage::Etag,
        LayerStage::Csrf,
        LayerStage::ResponseSigning,
        LayerStage::Traceparent,
        LayerStage::RequestId,
        LayerStage::PeerGuard,
        LayerStage::Compression,
        LayerStage::Decorate,
        LayerStage::AccessLog,
        LayerStage::ServerTiming,
    ];

    /// True for the stages that wrap only the gated sub-router.
    pub fn is_route_scoped(self) -> bool {
        matches!(
            self,
            LayerStage::Idempotency | LayerStage::TierRateLimit | LayerStage::TierGate
        )
    }

    pub(crate) fn index(self) -> usize {
        self as usize
    }
}

/// Everything routes and layers contribute, shared by the builder and
/// plugins.
pub(crate) struct Assembly {
    pub(crate) table: RouteTable,
    pub(crate) handlers: Vec<(String, MethodRouter)>,
    pub(crate) stages: Vec<Vec<LayerFn>>,
    pub(crate) extensions: Vec<LayerFn>,
    pub(crate) routers: Vec<Router>,
}

impl Assembly {
    fn new() -> Self {
        Self {
            table: RouteTable::new(),
            handlers: Vec::new(),
            stages: LayerStage::ALL.iter().map(|_| Vec::new()).collect(),
            extensions: Vec::new(),
            routers: Vec::new(),
        }
    }

    fn route(&mut self, entry: RouteEntry, handler: MethodRouter) {
        self.handlers.push((entry.path.clone(), handler));
        self.table.push(entry);
    }

    fn layer_at(&mut self, stage: LayerStage, f: LayerFn) {
        self.stages[stage.index()].push(f);
    }

    fn extension<T: Clone + Send + Sync + 'static>(&mut self, value: T) {
        self.extensions
            .push(Box::new(move |r: Router| r.layer(axum::Extension(value))));
    }
}

/// What a [`ServerPlugin`] sees and may change during
/// [`build`](ServerBuilder::build).
pub struct BuildCx<'a> {
    name: &'a str,
    transport: &'a Transport,
    asm: &'a mut Assembly,
}

impl BuildCx<'_> {
    /// Server name.
    pub fn name(&self) -> &str {
        self.name
    }

    /// Configured transport.
    pub fn transport(&self) -> &Transport {
        self.transport
    }

    /// Route table so far: user routes, built-in routes, and routes added by
    /// plugins that ran earlier.
    pub fn route_table(&self) -> &RouteTable {
        &self.asm.table
    }

    /// Adds a gated route and records it in the table.
    pub fn route(&mut self, entry: RouteEntry, handler: MethodRouter) {
        self.asm.route(entry, handler);
    }

    /// Adds a layer at `stage` (after the ones already there, i.e. outside them).
    pub fn layer_at(
        &mut self,
        stage: LayerStage,
        f: impl FnOnce(Router) -> Router + Send + 'static,
    ) {
        self.asm.layer_at(stage, Box::new(f));
    }

    /// Makes `value` available to handlers as `Extension<T>`.
    pub fn extension<T: Clone + Send + Sync + 'static>(&mut self, value: T) {
        self.asm.extension(value);
    }

    /// Merges a router whose routes are neither recorded in the table nor
    /// gated (a flow that handles its own admission). Paths must not overlap
    /// any other route; axum panics on overlap.
    pub fn merge_router(&mut self, router: Router) {
        self.asm.routers.push(router);
    }

    /// True once something is installed at [`LayerStage::TierGate`].
    pub fn has_gate(&self) -> bool {
        !self.asm.stages[LayerStage::TierGate.index()].is_empty()
    }
}

/// Information handed to plugins once the listeners are bound.
#[derive(Clone, Debug)]
pub struct StartedInfo {
    /// Server name.
    pub name: Arc<str>,
    /// Bound primary listener address (actual port).
    pub local_addr: SocketAddr,
    /// Bound admin listener address of a dual transport.
    pub admin_addr: Option<SocketAddr>,
    /// Socket path or pipe name when a [`ListenerDriver`] bound one (then
    /// `local_addr` is the unspecified placeholder `0.0.0.0:0`).
    pub local_path: Option<std::path::PathBuf>,
    /// Final route table.
    pub route_table: Arc<RouteTable>,
}

/// Extension point for crates that add capabilities to a server without the
/// root knowing them (authentication, registration with a control plane,
/// OpenAPI, …).
pub trait ServerPlugin: Send + 'static {
    /// Name used in errors and logs.
    fn name(&self) -> &'static str;

    /// Called once inside [`ServerBuilder::build`], in registration order,
    /// after built-in routes are in the table. May add routes, layers and
    /// extensions; an error aborts the build.
    fn on_build(&mut self, cx: &mut BuildCx<'_>) -> Result<(), BuildError>;

    /// Called once after the listeners are bound. Infallible: a plugin can
    /// never fail a running server.
    fn on_started(&mut self, info: &StartedInfo) {
        let _ = info;
    }
}

/// A periodic task registered on the builder.
pub(crate) struct BackgroundTaskSpec {
    pub(crate) name: String,
    pub(crate) period: Duration,
    pub(crate) work: Arc<dyn Fn() -> BoxFuture<'static, Result<(), BoxError>> + Send + Sync>,
}

/// Fluent builder of a [`Server`].
pub struct ServerBuilder {
    name: String,
    transport: Option<Transport>,
    version: Option<String>,
    asm: Assembly,
    plugins: Vec<Box<dyn ServerPlugin>>,
    background_tasks: Vec<BackgroundTaskSpec>,
    bind_retry: BindRetryPolicy,
    on_start: Option<OnStart>,
    on_stop: Option<OnStop>,
    on_reload: Option<OnReload>,
    dependency_checks: Vec<DependencyCheck>,
    detail_health: bool,
    request_id: bool,
    body_size_limit: Option<usize>,
    shutdown_timeout: Duration,
    reload: Option<ReloadConfig>,
    auto_extensions: bool,
    drivers: Vec<Arc<dyn ListenerDriver>>,
}

impl ServerBuilder {
    /// New builder for a server called `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            transport: None,
            version: None,
            asm: Assembly::new(),
            plugins: Vec::new(),
            background_tasks: Vec::new(),
            bind_retry: BindRetryPolicy::default(),
            on_start: None,
            on_stop: None,
            on_reload: None,
            dependency_checks: Vec::new(),
            detail_health: false,
            request_id: true,
            body_size_limit: None,
            shutdown_timeout: Duration::from_secs(30),
            reload: None,
            auto_extensions: true,
            drivers: Vec::new(),
        }
    }

    /// Where to listen.
    pub fn transport(mut self, t: Transport) -> Self {
        self.transport = Some(t);
        self
    }

    /// Version reported by the detailed `/health`.
    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }

    /// Registers a gated route described by `entry`.
    pub fn route_entry(mut self, entry: RouteEntry, handler: MethodRouter) -> Self {
        self.asm.route(entry, handler);
        self
    }

    /// Registers `handler` for `method path` at `tier`. The declared
    /// `method` must match the method the `MethodRouter` answers.
    pub fn route_tier_with_method(
        self,
        method: HttpMethod,
        path: impl Into<String>,
        handler: MethodRouter,
        tier: Tier,
    ) -> Self {
        self.route_entry(RouteEntry::new(method, path, tier), handler)
    }

    /// `GET path` at `tier`.
    pub fn get_tier(self, path: impl Into<String>, handler: MethodRouter, tier: Tier) -> Self {
        self.route_tier_with_method(HttpMethod::Get, path, handler, tier)
    }

    /// `POST path` at `tier`.
    pub fn post_tier(self, path: impl Into<String>, handler: MethodRouter, tier: Tier) -> Self {
        self.route_tier_with_method(HttpMethod::Post, path, handler, tier)
    }

    /// `PUT path` at `tier`.
    pub fn put_tier(self, path: impl Into<String>, handler: MethodRouter, tier: Tier) -> Self {
        self.route_tier_with_method(HttpMethod::Put, path, handler, tier)
    }

    /// `PATCH path` at `tier`.
    pub fn patch_tier(self, path: impl Into<String>, handler: MethodRouter, tier: Tier) -> Self {
        self.route_tier_with_method(HttpMethod::Patch, path, handler, tier)
    }

    /// `DELETE path` at `tier`.
    pub fn delete_tier(self, path: impl Into<String>, handler: MethodRouter, tier: Tier) -> Self {
        self.route_tier_with_method(HttpMethod::Delete, path, handler, tier)
    }

    /// Installs a layer function at `stage` (outside earlier ones at the
    /// same stage).
    pub fn layer_at(
        mut self,
        stage: LayerStage,
        f: impl FnOnce(Router) -> Router + Send + 'static,
    ) -> Self {
        self.asm.layer_at(stage, Box::new(f));
        self
    }

    /// Makes `value` available to handlers as `Extension<T>`.
    pub fn extension<T: Clone + Send + Sync + 'static>(mut self, value: T) -> Self {
        self.asm.extension(value);
        self
    }

    /// Adds a plugin; plugins run in registration order.
    pub fn with_plugin(mut self, plugin: impl ServerPlugin) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Adds a dependency probe to the detailed `/health` (enables it).
    pub fn with_dependency_check(mut self, check: DependencyCheck) -> Self {
        self.dependency_checks.push(check);
        self.detail_health = true;
        self
    }

    /// Serves the detailed `/health` report instead of `{"ok":true}`.
    pub fn with_detail_health(mut self) -> Self {
        self.detail_health = true;
        self
    }

    /// Mints/propagates `X-Request-Id` (on by default).
    pub fn with_request_id(mut self) -> Self {
        self.request_id = true;
        self
    }

    /// Turns the `X-Request-Id` layer off.
    pub fn without_request_id(mut self) -> Self {
        self.request_id = false;
        self
    }

    /// Refuses request bodies over `bytes` with 413.
    pub fn with_body_size_limit(mut self, bytes: usize) -> Self {
        self.body_size_limit = Some(bytes);
        self
    }

    /// Upper bound on draining each listener at shutdown (default 30 s).
    pub fn with_shutdown_timeout(mut self, d: Duration) -> Self {
        self.shutdown_timeout = d;
        self
    }

    /// Bind retry schedule.
    pub fn with_bind_retry(mut self, policy: BindRetryPolicy) -> Self {
        self.bind_retry = policy;
        self
    }

    /// Serves `POST /reload` (tier `Admin`) running the `on_reload` hook.
    pub fn with_reload(mut self, cfg: ReloadConfig) -> Self {
        self.reload = Some(cfg);
        self
    }

    /// Hook run before the listeners bind.
    pub fn on_start(mut self, h: OnStart) -> Self {
        self.on_start = Some(h);
        self
    }

    /// Hook run after shutdown drained.
    pub fn on_stop(mut self, h: OnStop) -> Self {
        self.on_stop = Some(h);
        self
    }

    /// Hook run by `POST /reload`.
    pub fn on_reload(mut self, h: OnReload) -> Self {
        self.on_reload = Some(h);
        self
    }

    /// Periodic task started with the server and stopped by its shutdown.
    pub fn with_background_task<F, Fut>(
        mut self,
        name: impl Into<String>,
        period: Duration,
        work: F,
    ) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), BoxError>> + Send + 'static,
    {
        self.background_tasks.push(BackgroundTaskSpec {
            name: name.into(),
            period,
            work: Arc::new(move || Box::pin(work())),
        });
        self
    }

    /// Registers the accept loop for one transport kind (see
    /// [`listener`](crate::listener)). At build, the last registered driver
    /// whose kind equals the transport's kind serves it; this is how
    /// `Transport::Tls` and `Transport::Ipc` get wired.
    pub fn listener_driver(mut self, driver: impl ListenerDriver) -> Self {
        self.drivers.push(Arc::new(driver));
        self
    }

    /// Stops injecting `ShutdownBroadcast`, `DrainState` and
    /// `Arc<RouteTable>` as extensions.
    pub fn without_auto_extensions(mut self) -> Self {
        self.auto_extensions = false;
        self
    }

    /// Validates and assembles the server. Order: built-in routes enter the
    /// table, plugins run, the table is validated, the admin-gate rule is
    /// checked, the router is assembled stage by stage.
    pub async fn build(self) -> Result<Server, BuildError> {
        let transport = self.transport.ok_or(BuildError::MissingTransport)?;
        let driver = self
            .drivers
            .iter()
            .rev()
            .find(|d| d.kind() == transport.kind())
            .cloned();
        let bind = match (&transport, &driver) {
            // A driver binds it; `0.0.0.0:0` stands in until it reports.
            (t, Some(_)) => t
                .primary_addr()
                .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
            (Transport::Tls { .. } | Transport::Ipc { .. }, None) => {
                return Err(BuildError::TransportNotWired {
                    kind: transport.kind(),
                });
            }
            (other, None) => other
                .primary_addr()
                .ok_or(BuildError::TransportNotWired { kind: other.kind() })?,
        };
        let mut asm = self.asm;

        // User routes may not take a built-in path.
        let builtins = server::builtin_entries(self.reload.as_ref().is_some_and(|r| r.endpoint));
        for entry in asm.table.iter() {
            if builtins.iter().any(|b| b.path == entry.path) {
                return Err(BuildError::InvalidRoute {
                    method: entry.method,
                    path: entry.path.clone(),
                    reason: "path is reserved for a built-in route",
                });
            }
        }
        for b in builtins {
            asm.table.push(b);
        }

        let mut plugins = self.plugins;
        for plugin in &mut plugins {
            let mut cx = BuildCx {
                name: &self.name,
                transport: &transport,
                asm: &mut asm,
            };
            plugin.on_build(&mut cx)?;
        }

        validate_table(&asm.table)?;
        if !transport.is_local_only()
            && asm.stages[LayerStage::TierGate.index()].is_empty()
            && let Some(r) = asm.table.privileged().next()
        {
            return Err(BuildError::UnauthenticatedAdminRoute {
                method: r.method,
                path: r.path.clone(),
                tier: r.tier,
            });
        }

        Ok(server::assemble(server::Parts {
            name: Arc::from(self.name.as_str()),
            version: self.version,
            transport,
            bind,
            driver,
            asm,
            plugins,
            background_tasks: self.background_tasks,
            bind_retry: self.bind_retry,
            on_start: self.on_start,
            on_stop: self.on_stop,
            on_reload: self.on_reload,
            dependency_checks: self.dependency_checks,
            detail_health: self.detail_health,
            request_id: self.request_id,
            body_size_limit: self.body_size_limit,
            shutdown_timeout: self.shutdown_timeout,
            reload_endpoint: self.reload.is_some_and(|r| r.endpoint),
            auto_extensions: self.auto_extensions,
        }))
    }
}

impl std::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("name", &self.name)
            .field("transport", &self.transport)
            .field("routes", &self.asm.table.len())
            .field(
                "plugins",
                &self.plugins.iter().map(|p| p.name()).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Rejects templates axum would panic on and duplicate `(method, path)` pairs.
fn validate_table(table: &RouteTable) -> Result<(), BuildError> {
    for r in table.iter() {
        let reason = if !r.path.starts_with('/') {
            Some("must start with '/'")
        } else if r.path.split('/').any(|seg| seg.starts_with(':')) {
            Some("use {name} for parameters, not :name")
        } else if r.path.split('/').any(|seg| seg.starts_with('*')) {
            Some("use {*name} for wildcards, not *name")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(BuildError::InvalidRoute {
                method: r.method,
                path: r.path.clone(),
                reason,
            });
        }
    }
    if let Some(r) = table.first_duplicate() {
        return Err(BuildError::DuplicateRoute {
            method: r.method,
            path: r.path.clone(),
        });
    }
    Ok(())
}
