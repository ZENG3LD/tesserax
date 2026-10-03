//! Same-origin reverse proxy for browser clients (feature `cors-proxy`).
//!
//! A browser (or wasm) client cannot read a REST API whose responses lack
//! `Access-Control-Allow-Origin`. The proxy forwards such calls from a
//! same-origin endpoint and decorates the answer with CORS headers:
//!
//! ```text
//! GET     <mount>?url=<percent-encoded upstream URL>
//! POST    <mount>?url=<percent-encoded upstream URL>   (body forwarded)
//! OPTIONS <mount>                                       (preflight, 204)
//! ```
//!
//! SSRF guard: the upstream host must be in the allow list (exact,
//! case-insensitive; there is no default, an empty list refuses
//! everything); only `http` / `https`, no user-info; redirects are not
//! followed (an allowed host cannot bounce the proxy elsewhere); the host
//! check and the request use the same parsed URL. Request and response
//! bodies are bounded by `max_body_bytes`. Only `Content-Type` and the
//! headers listed in `forward_headers` go upstream.
//!
//! Mounted through [`HttpExt::with_cors_proxy`](crate::HttpExt::with_cors_proxy)
//! the `GET` / `POST` routes are in the route table at the configured tier
//! (default `Authenticated`, so an auth gate covers them); the preflight is
//! `Public` because browsers send it without credentials.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, options, post};
use percent_encoding::percent_decode_str;
use reqwest::Url;
use serde::Deserialize;
use tesserax::Tier;

use crate::error::HttpError;

/// Why a proxied call failed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CorsProxyError {
    /// No `?url=`.
    #[error("upstream URL missing or empty")]
    MissingUrl,
    /// Not an absolute `http(s)` URL without user-info.
    #[error("upstream URL is not a valid http(s) URL: {0}")]
    BadUrl(String),
    /// Host not in the allow list.
    #[error("upstream host not in allowlist: {0}")]
    HostNotAllowed(String),
    /// The upstream call failed.
    #[error("upstream request failed: {0}")]
    Upstream(String),
    /// A body exceeded `max_body_bytes`.
    #[error("body exceeded max_body_bytes ({0})")]
    BodyTooLarge(usize),
}

impl CorsProxyError {
    fn status(&self) -> StatusCode {
        match self {
            Self::MissingUrl | Self::BadUrl(_) => StatusCode::BAD_REQUEST,
            Self::HostNotAllowed(_) => StatusCode::FORBIDDEN,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::BodyTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }
}

/// Which origins the proxy answers with `Access-Control-Allow-Origin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorsOrigin {
    /// `*` (no credentials).
    Any,
    /// The request's `Origin`, echoed only when it is in this list.
    Whitelist(Vec<String>),
}

/// Proxy configuration.
#[derive(Clone, Debug)]
pub struct CorsProxyConfig {
    /// Route path, e.g. `/proxy`.
    pub mount_path: String,
    /// Upstream hosts the proxy may call (exact, case-insensitive, no port).
    pub allowed_upstream_hosts: Vec<String>,
    /// CORS origin policy (default `Any`).
    pub allowed_origins: CorsOrigin,
    /// Upstream timeout (default 30 s).
    pub timeout: Duration,
    /// Request and response body bound (default 10 MiB).
    pub max_body_bytes: usize,
    /// Request headers forwarded verbatim besides `Content-Type`.
    pub forward_headers: Vec<String>,
    /// Tier of the `GET` / `POST` routes (default `Authenticated`).
    pub tier: Tier,
}

impl CorsProxyConfig {
    /// A proxy at `mount_path` for `allowed_upstream_hosts`.
    pub fn new(mount_path: impl Into<String>, allowed_upstream_hosts: Vec<String>) -> Self {
        Self {
            mount_path: mount_path.into(),
            allowed_upstream_hosts,
            allowed_origins: CorsOrigin::Any,
            timeout: Duration::from_secs(30),
            max_body_bytes: 10 * 1024 * 1024,
            forward_headers: Vec::new(),
            tier: Tier::Authenticated,
        }
    }

    /// Origin policy.
    pub fn with_allowed_origins(mut self, origins: CorsOrigin) -> Self {
        self.allowed_origins = origins;
        self
    }

    /// Upstream timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Body bound.
    pub fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }

    /// Extra forwarded request headers.
    pub fn with_forward_headers(mut self, headers: Vec<String>) -> Self {
        self.forward_headers = headers;
        self
    }

    /// Tier of the proxied routes.
    pub fn with_tier(mut self, tier: Tier) -> Self {
        self.tier = tier;
        self
    }
}

/// Runtime state (config, allow sets, HTTP client). Cheap to clone.
#[derive(Clone)]
pub struct CorsProxyState {
    cfg: Arc<CorsProxyConfig>,
    hosts: Arc<HashSet<String>>,
    forward: Arc<Vec<HeaderName>>,
    client: reqwest::Client,
}

impl std::fmt::Debug for CorsProxyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CorsProxyState")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl CorsProxyState {
    /// Builds the client; fails on an invalid forward header name or a
    /// client that cannot be built.
    pub fn new(cfg: CorsProxyConfig) -> Result<Self, HttpError> {
        let hosts = cfg
            .allowed_upstream_hosts
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        let forward = cfg
            .forward_headers
            .iter()
            .map(|s| {
                HeaderName::try_from(s.as_str())
                    .map_err(|e| HttpError::Config(format!("forward header {s:?}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| HttpError::Config(format!("http client: {e}")))?;
        Ok(Self {
            cfg: Arc::new(cfg),
            hosts: Arc::new(hosts),
            forward: Arc::new(forward),
            client,
        })
    }

    /// The configuration.
    pub fn config(&self) -> &CorsProxyConfig {
        &self.cfg
    }

    /// `(method, handler)` pairs to mount at the configured path.
    pub fn handlers(&self) -> [(Method, MethodRouter); 3] {
        [
            (Method::GET, get(handle).with_state(self.clone())),
            (Method::POST, post(handle).with_state(self.clone())),
            (Method::OPTIONS, options(preflight).with_state(self.clone())),
        ]
    }

    /// A standalone router with the three routes (no table, no gate).
    pub fn router(&self) -> Router {
        let path = self.cfg.mount_path.clone();
        self.handlers()
            .into_iter()
            .fold(Router::new(), |r, (_, h)| r.route(&path, h))
    }

    fn check_target(&self, raw: &str) -> Result<Url, CorsProxyError> {
        // `Query` already decoded one level; clients that encoded the URL
        // twice get the second level decoded here.
        let once;
        let text = if raw.starts_with("http://") || raw.starts_with("https://") {
            raw
        } else {
            once = percent_decode_str(raw)
                .decode_utf8()
                .map_err(|_| CorsProxyError::BadUrl("not valid utf-8".into()))?
                .into_owned();
            &once
        };
        let url = Url::parse(text).map_err(|e| CorsProxyError::BadUrl(e.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(CorsProxyError::BadUrl(
                "scheme must be http or https".into(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(CorsProxyError::BadUrl("user-info is not allowed".into()));
        }
        let host = url
            .host_str()
            .ok_or_else(|| CorsProxyError::BadUrl("no host".into()))?
            .to_ascii_lowercase();
        if !self.hosts.contains(&host) {
            return Err(CorsProxyError::HostNotAllowed(host));
        }
        Ok(url)
    }

    fn decorate(&self, headers: &mut HeaderMap, origin: Option<&HeaderValue>) {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("*"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"),
        );
        match &self.cfg.allowed_origins {
            CorsOrigin::Any => {
                headers.insert(
                    header::ACCESS_CONTROL_ALLOW_ORIGIN,
                    HeaderValue::from_static("*"),
                );
            }
            CorsOrigin::Whitelist(list) => {
                headers.append(header::VARY, HeaderValue::from_static("origin"));
                if let Some(o) =
                    origin.filter(|o| list.iter().any(|l| o.as_bytes() == l.as_bytes()))
                {
                    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, o.clone());
                }
            }
        }
    }

    fn error(&self, e: CorsProxyError, origin: Option<&HeaderValue>) -> Response {
        let mut resp = (e.status(), e.to_string()).into_response();
        self.decorate(resp.headers_mut(), origin);
        resp
    }
}

#[derive(Deserialize)]
struct UrlQuery {
    url: Option<String>,
}

async fn preflight(State(st): State<CorsProxyState>, headers: HeaderMap) -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    st.decorate(resp.headers_mut(), headers.get(header::ORIGIN));
    resp
}

async fn handle(
    State(st): State<CorsProxyState>,
    Query(q): Query<UrlQuery>,
    req: Request,
) -> Response {
    let origin = req.headers().get(header::ORIGIN).cloned();
    match forward(&st, q, req).await {
        Ok(mut resp) => {
            st.decorate(resp.headers_mut(), origin.as_ref());
            resp
        }
        Err(e) => {
            if matches!(e, CorsProxyError::HostNotAllowed(_)) {
                tracing::warn!(error = %e, "cors-proxy refused");
            }
            st.error(e, origin.as_ref())
        }
    }
}

async fn forward(
    st: &CorsProxyState,
    q: UrlQuery,
    req: Request,
) -> Result<Response, CorsProxyError> {
    let raw = q
        .url
        .filter(|u| !u.is_empty())
        .ok_or(CorsProxyError::MissingUrl)?;
    let url = st.check_target(&raw)?;
    let limit = st.cfg.max_body_bytes;
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, limit)
        .await
        .map_err(|_| CorsProxyError::BodyTooLarge(limit))?;

    let mut up = st.client.request(method, url);
    match parts.headers.get(header::CONTENT_TYPE) {
        Some(ct) => up = up.header(header::CONTENT_TYPE, ct.clone()),
        None if !body.is_empty() => up = up.header(header::CONTENT_TYPE, "application/json"),
        None => {}
    }
    for name in st.forward.iter() {
        if let Some(v) = parts.headers.get(name) {
            up = up.header(name.clone(), v.clone());
        }
    }
    if !body.is_empty() {
        up = up.body(body);
    }
    let mut upstream = up
        .send()
        .await
        .map_err(|e| CorsProxyError::Upstream(e.to_string()))?;
    if upstream.content_length().is_some_and(|n| n > limit as u64) {
        return Err(CorsProxyError::BodyTooLarge(limit));
    }
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let ct = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/octet-stream"));
    let mut buf = Vec::new();
    while let Some(chunk) = upstream
        .chunk()
        .await
        .map_err(|e| CorsProxyError::Upstream(format!("read body: {e}")))?
    {
        if buf.len() + chunk.len() > limit {
            return Err(CorsProxyError::BodyTooLarge(limit));
        }
        buf.extend_from_slice(&chunk);
    }
    let mut resp = Response::new(Body::from(buf));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, ct);
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tower::ServiceExt;

    fn state(hosts: &[&str]) -> CorsProxyState {
        CorsProxyState::new(CorsProxyConfig::new(
            "/proxy",
            hosts.iter().map(|s| s.to_string()).collect(),
        ))
        .unwrap()
    }

    async fn call(st: &CorsProxyState, method: &str, uri: &str, origin: Option<&str>) -> Response {
        let mut b = axum::http::Request::builder().method(method).uri(uri);
        if let Some(o) = origin {
            b = b.header("origin", o);
        }
        st.router()
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[test]
    fn target_checks() {
        let st = state(&["api.example.com"]);
        assert!(st.check_target("https://API.example.com/v1/x?q=1").is_ok());
        assert!(
            st.check_target("https%3A%2F%2Fapi.example.com%2Fv1")
                .is_ok()
        );
        assert_eq!(
            st.check_target("https://evil.example.org/"),
            Err(CorsProxyError::HostNotAllowed("evil.example.org".into()))
        );
        // Parser differentials resolve to the host the client would call.
        assert!(matches!(
            st.check_target("https://api.example.com@evil.example.org/"),
            Err(CorsProxyError::BadUrl(_))
        ));
        assert!(matches!(
            st.check_target("https://evil.example.org\\@api.example.com/"),
            Err(CorsProxyError::HostNotAllowed(_))
        ));
        assert!(matches!(
            st.check_target("ftp://api.example.com/"),
            Err(CorsProxyError::BadUrl(_))
        ));
        assert!(matches!(
            state(&[]).check_target("https://api.example.com/"),
            Err(CorsProxyError::HostNotAllowed(_))
        ));
    }

    #[tokio::test]
    async fn preflight_and_refusals_carry_cors() {
        let st = state(&["api.example.com"]);
        let r = call(&st, "OPTIONS", "/proxy", None).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        assert_eq!(r.headers()["access-control-allow-origin"], "*");
        let r = call(&st, "GET", "/proxy", None).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(r.headers().contains_key("access-control-allow-origin"));
        let r = call(
            &st,
            "GET",
            "/proxy?url=https%3A%2F%2Fevil.example.org%2F",
            None,
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(r.into_body(), 1024).await.unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("not in allowlist")
        );
    }

    #[tokio::test]
    async fn whitelist_echoes_listed_origin_only() {
        let st = CorsProxyState::new(
            CorsProxyConfig::new("/proxy", vec!["api.example.com".into()]).with_allowed_origins(
                CorsOrigin::Whitelist(vec!["https://app.example.com".into()]),
            ),
        )
        .unwrap();
        let r = call(&st, "OPTIONS", "/proxy", Some("https://app.example.com")).await;
        assert_eq!(
            r.headers()["access-control-allow-origin"],
            "https://app.example.com"
        );
        let r = call(&st, "OPTIONS", "/proxy", Some("https://evil.example")).await;
        assert!(r.headers().get("access-control-allow-origin").is_none());
    }

    #[test]
    fn config_defaults() {
        let c = CorsProxyConfig::new("/p", vec!["x".into()]);
        assert_eq!(c.timeout, Duration::from_secs(30));
        assert_eq!(c.max_body_bytes, 10 * 1024 * 1024);
        assert_eq!(c.tier, Tier::Authenticated);
        assert!(CorsProxyState::new(c.with_forward_headers(vec!["bad header".into()])).is_err());
    }
}
