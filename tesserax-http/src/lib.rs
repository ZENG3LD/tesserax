//! `tesserax-http` — the HTTP surface of a `tesserax` server.
//!
//! - [`DocRouter`]: routes that cannot be added without a description;
//!   [`DocRouter::route_table`] merges tier, scope and description into the
//!   root's [`RouteTable`](tesserax::RouteTable) (the description is each
//!   entry's `label`), [`HttpExt::with_routes`] puts them in a server's
//!   table so an auth gate enforces them.
//! - [`openapi`]: an OpenAPI 3.1 document generated from the route table,
//!   and a Swagger UI page.
//! - [`push`]: a typed broadcast bus, an SSE hub whose events carry `id:`
//!   and resume after `Last-Event-ID` without duplicates or gaps (or say
//!   `resync` when the gap cannot be filled), and a WebSocket hub.
//! - [`guard`]: CORS, security headers, CSRF, IP allow / deny, concurrency
//!   cap, rate limits (per address and per tier), idempotency keys,
//!   webhook signatures, response signing (feature `signing`).
//! - [`caching`], [`trace`], [`access_log`]: `ETag`, `Server-Timing`,
//!   `traceparent`, access log; `metrics` (feature) for Prometheus.
//! - [`assets`]: static directories, wasm isolation headers, an inline
//!   dashboard page; `cors_proxy` (feature) for browser clients of
//!   CORS-less APIs.
//! - [`HttpExt`]: installs all of it on a `tesserax::ServerBuilder`, each
//!   middleware at its fixed [`LayerStage`](tesserax::LayerStage).
//!
//! # Contract
//!
//! ```text
//! Role:      shell (HTTP surface)
//! Owns:      middleware state objects (rate buckets, idempotency cache, CSRF secret, concurrency counters,
//!            SSE history ring and hub subscriber lists). No persistent state.
//! Exports:   DocRouter, RouteDoc, Endpoint, AuthKind, HttpExt, OpenApiConfig, HttpError,
//!            IDENTITY_PATH (feature signing);
//!            guard::{cors_policy, CorsPolicy, SecurityHeaders, CsrfState, csrf_mw, IpAcl, ip_acl_mw, ConnCap,
//!            conn_cap_mw, RateLimit, RateLimitState, rate_limit_mw, TierRateLimit, TierRateLimitPolicy,
//!            tier_rate_limit_mw, IdempotencyStore, IdempotencyConfig, idempotency_mw, WebhookVerifier,
//!            client_ip, response_signing_mw (feature signing)};
//!            openapi::{build_openapi, swagger_ui_html, OpenApiInput, SecurityScheme};
//!            push::{BroadcastChannel, SseHub, SseMessage, WsHub, WsEnvelope, WsPingConfig};
//!            caching::{EtagConfig, etag_mw, server_timing_mw}; trace::{TraceContext, traceparent_mw};
//!            access_log::access_log_mw; assets::{StaticDir, wasm_headers, Dashboard};
//!            feature metrics: metrics::{PrometheusState, metrics_mw};
//!            feature cors-proxy: cors_proxy::{CorsProxyConfig, CorsProxyState, CorsOrigin, CorsProxyError}.
//! Imports:   tesserax (server; ct for every HMAC and secret compare), axum, tower-http, tower-layer,
//!            tower-service, tokio, futures-util, serde, serde_json, thiserror, tracing, getrandom, base64;
//!            feature signing: tesserax-secrets; feature cors-proxy: reqwest, percent-encoding;
//!            feature metrics: metrics, metrics-exporter-prometheus.
//! Forbidden: Domain / Core types; control-plane registration vocabulary; tesserax-store, -framework;
//!            a second constant-time compare or HMAC (use tesserax::ct); plain equality on secret material;
//!            open-by-default behaviour; any product, host or consumer name.
//! ```
//!
//! # Features
//!
//! - `signing` — `guard::response_signing_mw` and
//!   `HttpExt::with_response_signing` over `tesserax_secrets::signing`;
//!   `HttpExt::with_identity_endpoint` serves `GET /admin/identity`
//!   (`IDENTITY_PATH`, tier Admin) for
//!   `tesserax-opctl discover`.
//! - `cors-proxy` — `cors_proxy` and `HttpExt::with_cors_proxy`.
//! - `metrics` — Prometheus request metrics and scrape route.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod access_log;
pub mod assets;
pub mod caching;
#[cfg(feature = "cors-proxy")]
pub mod cors_proxy;
mod doc_router;
mod error;
mod ext;
pub mod guard;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod openapi;
pub mod push;
pub mod trace;

pub use doc_router::{AuthKind, DocRouter, Endpoint, RouteDoc};
pub use error::HttpError;
#[cfg(feature = "signing")]
pub use ext::IDENTITY_PATH;
pub use ext::{HttpExt, OpenApiConfig};
