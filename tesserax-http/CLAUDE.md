# tesserax-http

Contract header. The crate docs mirror this block.

```text
Role:      shell (HTTP surface)
Owns:      middleware state objects (rate buckets, idempotency cache, CSRF secret, concurrency counters,
           SSE history ring and hub subscriber lists). No persistent state.
Exports:   DocRouter, RouteDoc, Endpoint, AuthKind, HttpExt, OpenApiConfig, HttpError,
           IDENTITY_PATH (feature signing);
           guard::{cors_policy, CorsPolicy, SecurityHeaders, CsrfState, csrf_mw, IpAcl, ip_acl_mw, ConnCap,
           conn_cap_mw, RateLimit, RateLimitState, rate_limit_mw, TierRateLimit, TierRateLimitPolicy,
           tier_rate_limit_mw, IdempotencyStore, IdempotencyConfig, idempotency_mw, WebhookVerifier,
           client_ip, response_signing_mw (feature signing)};
           openapi::{build_openapi, swagger_ui_html, OpenApiInput, SecurityScheme};
           push::{BroadcastChannel, SseHub, SseMessage, WsHub, WsEnvelope, WsPingConfig};
           caching::{EtagConfig, etag_mw, server_timing_mw}; trace::{TraceContext, traceparent_mw};
           access_log::access_log_mw; assets::{StaticDir, wasm_headers, Dashboard};
           feature metrics: metrics::{PrometheusState, metrics_mw};
           feature cors-proxy: cors_proxy::{CorsProxyConfig, CorsProxyState, CorsOrigin, CorsProxyError}.
Imports:   tesserax (server; ct for every HMAC and secret compare), axum, tower-http, tower-layer,
           tower-service, tokio, futures-util, serde, serde_json, thiserror, tracing, getrandom, base64;
           feature signing: tesserax-secrets; feature cors-proxy: reqwest, percent-encoding;
           feature metrics: metrics, metrics-exporter-prometheus.
Forbidden: Domain / Core types; control-plane registration vocabulary; tesserax-store, -framework;
           a second constant-time compare or HMAC (use tesserax::ct); plain equality on secret material;
           open-by-default behaviour; any product, host or consumer name.
```
