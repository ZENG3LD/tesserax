//! [`HttpExt`]: installs this crate's routes and middleware on a
//! `tesserax::ServerBuilder`, each at its [`LayerStage`].

use std::sync::{Arc, OnceLock};

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tesserax::{
    BuildCx, BuildError, HttpMethod, LayerStage, RouteEntry, RouteTable, ServerBuilder,
    ServerPlugin, Tier,
};
use tower_http::compression::CompressionLayer;

use crate::access_log::access_log_mw;
use crate::assets::StaticDir;
use crate::caching::{EtagConfig, etag_mw, server_timing_mw};
use crate::doc_router::DocRouter;
use crate::guard::{
    ConnCap, CorsPolicy, CsrfState, IdempotencyStore, IpAcl, RateLimit, SecurityHeaders,
    TierRateLimit, conn_cap_mw, cors_policy, csrf_mw, idempotency_mw, ip_acl_mw, rate_limit_mw,
    tier_rate_limit_mw,
};
use crate::openapi::{OpenApiInput, SecurityScheme, build_openapi, swagger_ui_html};
use crate::trace::traceparent_mw;

/// How [`HttpExt::with_openapi_config`] serves the document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenApiConfig {
    /// Route path, e.g. `/openapi.json`.
    pub path: String,
    /// `info.title` (default: the server name).
    pub title: Option<String>,
    /// `info.version`.
    pub version: Option<String>,
    /// `info.description`.
    pub description: Option<String>,
    /// `servers[0].url`.
    pub server_url: Option<String>,
    /// Schemes of non-public routes (default: bearer).
    pub security: Vec<SecurityScheme>,
    /// Tier of the document route (default `Public`).
    pub tier: Tier,
}

impl OpenApiConfig {
    /// Defaults at `path`.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            title: None,
            version: None,
            description: None,
            server_url: None,
            security: vec![SecurityScheme::Bearer],
            tier: Tier::Public,
        }
    }

    /// `info.version`.
    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }

    /// `info.title`.
    pub fn title(mut self, t: impl Into<String>) -> Self {
        self.title = Some(t.into());
        self
    }

    /// Tier of the document route.
    pub fn tier(mut self, tier: Tier) -> Self {
        self.tier = tier;
        self
    }
}

/// Adds the HTTP surface of this crate to a server builder.
pub trait HttpExt: Sized {
    /// Registers every route of `routes` in the route table with its tier,
    /// scope and description (so an auth gate enforces them and OpenAPI
    /// lists them). A blank description fails the build.
    fn with_routes(self, routes: DocRouter) -> Self;
    /// Response compression (gzip, deflate) at `Compression`.
    fn with_compression(self) -> Self;
    /// Weak `ETag` / 304 at `Etag`.
    fn with_etag(self, cfg: EtagConfig) -> Self;
    /// `Server-Timing` at `ServerTiming`.
    fn with_server_timing(self) -> Self;
    /// W3C `traceparent` at `Traceparent`.
    fn with_traceparent(self) -> Self;
    /// One log line per request at `AccessLog`.
    fn with_access_log(self) -> Self;
    /// CORS at `Decorate`.
    fn with_cors(self, policy: CorsPolicy) -> Self;
    /// Security response headers at `Decorate`.
    fn with_security_headers(self, cfg: SecurityHeaders) -> Self;
    /// Double-submit CSRF at `Csrf`.
    fn with_csrf(self, state: CsrfState) -> Self;
    /// IP allow / deny lists at `PeerGuard`.
    fn with_ip_acl(self, acl: IpAcl) -> Self;
    /// Per-address concurrency cap at `PeerGuard`.
    fn with_conn_cap(self, cap: Arc<ConnCap>) -> Self;
    /// Per-address token bucket at `PeerGuard`.
    fn with_rate_limit(self, limit: RateLimit) -> Self;
    /// Per-tier token bucket at `TierRateLimit` (inside the auth gate).
    fn with_tier_rate_limit(self, limit: TierRateLimit) -> Self;
    /// `Idempotency-Key` replay at `Idempotency` (inside the auth gate and
    /// the tier rate limit; keyed by the admitted Principal, or by the
    /// honest client address on anonymous routes).
    fn with_idempotency(self, store: Arc<IdempotencyStore>) -> Self;
    /// OpenAPI document of the final route table at `path` (public).
    fn with_openapi(self, path: &str) -> Self;
    /// OpenAPI document with explicit settings.
    fn with_openapi_config(self, cfg: OpenApiConfig) -> Self;
    /// Swagger UI page at `path` loading `spec_url` (public).
    fn with_swagger_ui(self, path: &str, spec_url: &str) -> Self;
    /// Serves `dir` for every path no route matches (public, not in the
    /// route table, not behind the gate).
    fn with_static_dir(self, dir: StaticDir) -> Self;
    /// Response signing at `ResponseSigning` (feature `signing`).
    #[cfg(feature = "signing")]
    fn with_response_signing(
        self,
        state: Arc<tesserax_secrets::signing::ResponseSigningState>,
    ) -> Self;
    /// `GET /admin/identity` (tier Admin, described in the route table and
    /// OpenAPI): `{"daemon":{"name","pubkey_fingerprint","pubkey_b64"}}`
    /// with the server name, the identity's fingerprint and its raw
    /// ed25519 public key (base64url, no padding). `tesserax-opctl
    /// discover` probes it first. Feature `signing`.
    #[cfg(feature = "signing")]
    fn with_identity_endpoint(self, identity: &tesserax_secrets::DaemonIdentity) -> Self;
    /// Request metrics at `Metrics` and a Prometheus scrape route at
    /// `path` / `tier`; installs the global `metrics` recorder at build
    /// (the build fails if one is already installed). Feature `metrics`.
    #[cfg(feature = "metrics")]
    fn with_prometheus_metrics(self, path: &str, tier: Tier) -> Self;
    /// As [`with_prometheus_metrics`](Self::with_prometheus_metrics) with
    /// a recorder the caller installed. Feature `metrics`.
    #[cfg(feature = "metrics")]
    fn with_prometheus_state(
        self,
        path: &str,
        tier: Tier,
        state: crate::metrics::PrometheusState,
    ) -> Self;
    /// The CORS proxy routes (feature `cors-proxy`); an invalid config
    /// fails the build.
    #[cfg(feature = "cors-proxy")]
    fn with_cors_proxy(self, cfg: crate::cors_proxy::CorsProxyConfig) -> Self;
}

/// Fails the build with a fixed reason.
struct FailBuild {
    plugin: &'static str,
    message: String,
}

impl ServerPlugin for FailBuild {
    fn name(&self) -> &'static str {
        self.plugin
    }

    fn on_build(&mut self, _cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        Err(BuildError::Plugin {
            plugin: self.plugin,
            message: std::mem::take(&mut self.message),
        })
    }
}

struct OpenApiPlugin {
    cfg: OpenApiConfig,
}

impl ServerPlugin for OpenApiPlugin {
    fn name(&self) -> &'static str {
        "openapi"
    }

    fn on_build(&mut self, cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        let cfg = Arc::new(OpenApiConfig {
            title: Some(
                self.cfg
                    .title
                    .clone()
                    .unwrap_or_else(|| cx.name().to_owned()),
            ),
            ..self.cfg.clone()
        });
        let cache: Arc<OnceLock<serde_json::Value>> = Arc::new(OnceLock::new());
        let handler = move |table: Option<Extension<Arc<RouteTable>>>| {
            let cfg = Arc::clone(&cfg);
            let cache = Arc::clone(&cache);
            async move {
                let Some(Extension(table)) = table else {
                    // The final table is injected by the root unless
                    // `without_auto_extensions()` was called.
                    return crate::guard::refuse(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "route_table_missing",
                    );
                };
                let doc = cache.get_or_init(|| {
                    build_openapi(OpenApiInput {
                        title: cfg.title.as_deref().unwrap_or_default(),
                        version: cfg.version.as_deref(),
                        description: cfg.description.as_deref(),
                        table: &table,
                        security: &cfg.security,
                        server_url: cfg.server_url.as_deref(),
                    })
                });
                Json(doc.clone()).into_response()
            }
        };
        cx.route(
            RouteEntry::new(HttpMethod::Get, self.cfg.path.clone(), self.cfg.tier)
                .with_label("OpenAPI 3.1 document of this server's routes."),
            get(handler),
        );
        Ok(())
    }
}

struct StaticPlugin {
    dir: Option<StaticDir>,
}

impl ServerPlugin for StaticPlugin {
    fn name(&self) -> &'static str {
        "static-dir"
    }

    fn on_build(&mut self, cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        if let Some(dir) = self.dir.take() {
            cx.merge_router(dir.into_router());
        }
        Ok(())
    }
}

/// Path of the identity endpoint (see [`HttpExt::with_identity_endpoint`]).
#[cfg(feature = "signing")]
pub const IDENTITY_PATH: &str = "/admin/identity";

#[cfg(feature = "signing")]
struct IdentityPlugin {
    fingerprint: String,
    pubkey_b64: String,
}

#[cfg(feature = "signing")]
impl ServerPlugin for IdentityPlugin {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn on_build(&mut self, cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        let body = Arc::new(serde_json::json!({
            "daemon": {
                "name": cx.name(),
                "pubkey_fingerprint": self.fingerprint,
                "pubkey_b64": self.pubkey_b64,
            }
        }));
        let routes = DocRouter::new().get(
            IDENTITY_PATH,
            move || {
                let body = Arc::clone(&body);
                async move { Json(body.as_ref().clone()) }
            },
            crate::RouteDoc::bearer(
                "Daemon identity: service name, public-key fingerprint and raw ed25519 \
                 public key, for operators to pin.",
            )
            .tier(Tier::Admin),
        );
        for (entry, handler) in routes.into_entries() {
            cx.route(entry, handler);
        }
        Ok(())
    }
}

#[cfg(feature = "metrics")]
struct MetricsPlugin {
    path: String,
    tier: Tier,
    state: Option<crate::metrics::PrometheusState>,
}

#[cfg(feature = "metrics")]
impl ServerPlugin for MetricsPlugin {
    fn name(&self) -> &'static str {
        "prometheus"
    }

    fn on_build(&mut self, cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        let state = match self.state.take() {
            Some(s) => s,
            None => crate::metrics::PrometheusState::install().map_err(|e| BuildError::Plugin {
                plugin: "prometheus",
                message: e.to_string(),
            })?,
        };
        cx.layer_at(LayerStage::Metrics, |r: Router| {
            r.layer(from_fn(crate::metrics::metrics_mw))
        });
        cx.route(
            RouteEntry::new(HttpMethod::Get, self.path.clone(), self.tier)
                .with_label("Prometheus metrics (text exposition format)."),
            get(move || {
                let state = state.clone();
                async move { state.render() }
            }),
        );
        Ok(())
    }
}

#[cfg(feature = "cors-proxy")]
struct CorsProxyPlugin {
    cfg: Option<crate::cors_proxy::CorsProxyConfig>,
}

#[cfg(feature = "cors-proxy")]
impl ServerPlugin for CorsProxyPlugin {
    fn name(&self) -> &'static str {
        "cors-proxy"
    }

    fn on_build(&mut self, cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        let Some(cfg) = self.cfg.take() else {
            return Ok(());
        };
        let tier = cfg.tier;
        let path = cfg.mount_path.clone();
        let state =
            crate::cors_proxy::CorsProxyState::new(cfg).map_err(|e| BuildError::Plugin {
                plugin: "cors-proxy",
                message: e.to_string(),
            })?;
        for (method, handler) in state.handlers() {
            let (m, t, label) = match method {
                axum::http::Method::GET => (
                    HttpMethod::Get,
                    tier,
                    "CORS proxy: GET the upstream URL in ?url=.",
                ),
                axum::http::Method::POST => (
                    HttpMethod::Post,
                    tier,
                    "CORS proxy: POST to the upstream URL in ?url=.",
                ),
                _ => (HttpMethod::Options, Tier::Public, "CORS proxy preflight."),
            };
            cx.route(
                RouteEntry::new(m, path.clone(), t).with_label(label),
                handler,
            );
        }
        Ok(())
    }
}

fn html(body: String) -> Response {
    Html(body).into_response()
}

impl HttpExt for ServerBuilder {
    fn with_routes(self, routes: DocRouter) -> Self {
        let blank = routes.undescribed();
        let mut b = self;
        for (entry, handler) in routes.into_entries() {
            b = b.route_entry(entry, handler);
        }
        if let Some((m, p)) = blank.first() {
            b = b.with_plugin(FailBuild {
                plugin: "doc-router",
                message: format!("route {m} {p} has a blank description"),
            });
        }
        b
    }

    fn with_compression(self) -> Self {
        self.layer_at(LayerStage::Compression, |r: Router| {
            r.layer(CompressionLayer::new())
        })
    }

    fn with_etag(self, cfg: EtagConfig) -> Self {
        self.layer_at(LayerStage::Etag, move |r: Router| {
            r.layer(from_fn_with_state(cfg, etag_mw))
        })
    }

    fn with_server_timing(self) -> Self {
        self.layer_at(LayerStage::ServerTiming, |r: Router| {
            r.layer(from_fn(server_timing_mw))
        })
    }

    fn with_traceparent(self) -> Self {
        self.layer_at(LayerStage::Traceparent, |r: Router| {
            r.layer(from_fn(traceparent_mw))
        })
    }

    fn with_access_log(self) -> Self {
        self.layer_at(LayerStage::AccessLog, |r: Router| {
            r.layer(from_fn(access_log_mw))
        })
    }

    fn with_cors(self, policy: CorsPolicy) -> Self {
        self.layer_at(LayerStage::Decorate, move |r: Router| {
            r.layer(cors_policy(policy))
        })
    }

    fn with_security_headers(self, cfg: SecurityHeaders) -> Self {
        self.layer_at(LayerStage::Decorate, move |r: Router| cfg.apply(r))
    }

    fn with_csrf(self, state: CsrfState) -> Self {
        self.layer_at(LayerStage::Csrf, move |r: Router| {
            r.layer(from_fn_with_state(state, csrf_mw))
        })
    }

    fn with_ip_acl(self, acl: IpAcl) -> Self {
        self.layer_at(LayerStage::PeerGuard, move |r: Router| {
            r.layer(from_fn_with_state(acl, ip_acl_mw))
        })
    }

    fn with_conn_cap(self, cap: Arc<ConnCap>) -> Self {
        self.layer_at(LayerStage::PeerGuard, move |r: Router| {
            r.layer(from_fn_with_state(cap, conn_cap_mw))
        })
    }

    fn with_rate_limit(self, limit: RateLimit) -> Self {
        self.layer_at(LayerStage::PeerGuard, move |r: Router| {
            r.layer(from_fn_with_state(limit, rate_limit_mw))
        })
    }

    fn with_tier_rate_limit(self, limit: TierRateLimit) -> Self {
        self.layer_at(LayerStage::TierRateLimit, move |r: Router| {
            r.route_layer(from_fn_with_state(limit, tier_rate_limit_mw))
        })
    }

    fn with_idempotency(self, store: Arc<IdempotencyStore>) -> Self {
        self.layer_at(LayerStage::Idempotency, move |r: Router| {
            r.route_layer(from_fn_with_state(store, idempotency_mw))
        })
    }

    fn with_openapi(self, path: &str) -> Self {
        self.with_openapi_config(OpenApiConfig::new(path))
    }

    fn with_openapi_config(self, cfg: OpenApiConfig) -> Self {
        self.with_plugin(OpenApiPlugin { cfg })
    }

    fn with_swagger_ui(self, path: &str, spec_url: &str) -> Self {
        let page = Arc::new(swagger_ui_html(spec_url, "API"));
        self.route_entry(
            RouteEntry::new(HttpMethod::Get, path, Tier::Public)
                .with_label("Swagger UI for the OpenAPI document."),
            get(move || {
                let page = Arc::clone(&page);
                async move { html(page.to_string()) }
            }),
        )
    }

    fn with_static_dir(self, dir: StaticDir) -> Self {
        self.with_plugin(StaticPlugin { dir: Some(dir) })
    }

    #[cfg(feature = "signing")]
    fn with_response_signing(
        self,
        state: Arc<tesserax_secrets::signing::ResponseSigningState>,
    ) -> Self {
        self.layer_at(LayerStage::ResponseSigning, move |r: Router| {
            r.layer(from_fn_with_state(state, crate::guard::response_signing_mw))
        })
    }

    #[cfg(feature = "signing")]
    fn with_identity_endpoint(self, identity: &tesserax_secrets::DaemonIdentity) -> Self {
        use base64::Engine as _;
        self.with_plugin(IdentityPlugin {
            fingerprint: identity.pubkey_fingerprint().to_owned(),
            pubkey_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(identity.pubkey_bytes()),
        })
    }

    #[cfg(feature = "metrics")]
    fn with_prometheus_metrics(self, path: &str, tier: Tier) -> Self {
        self.with_plugin(MetricsPlugin {
            path: path.to_owned(),
            tier,
            state: None,
        })
    }

    #[cfg(feature = "metrics")]
    fn with_prometheus_state(
        self,
        path: &str,
        tier: Tier,
        state: crate::metrics::PrometheusState,
    ) -> Self {
        self.with_plugin(MetricsPlugin {
            path: path.to_owned(),
            tier,
            state: Some(state),
        })
    }

    #[cfg(feature = "cors-proxy")]
    fn with_cors_proxy(self, cfg: crate::cors_proxy::CorsProxyConfig) -> Self {
        self.with_plugin(CorsProxyPlugin { cfg: Some(cfg) })
    }
}
