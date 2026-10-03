//! Weak `ETag` / `If-None-Match` and `Server-Timing`.
//!
//! [`etag_mw`]: for a `GET` / `HEAD` answered 2xx with a body of known
//! length up to `max_body_bytes`, sets `ETag: W/"<16 hex of SHA-256>"` and
//! answers `304 Not Modified` (no body; `ETag` and `Cache-Control` kept)
//! when `If-None-Match` lists it or `*`. Other responses pass untouched.
//!
//! [`server_timing_mw`]: appends `Server-Timing: total;dur=<ms>`.

use std::time::Instant;

use axum::body::{Body, HttpBody, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// `ETag` limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EtagConfig {
    /// Larger bodies are not hashed.
    pub max_body_bytes: usize,
}

impl Default for EtagConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
        }
    }
}

/// The weak entity tag of `bytes`.
pub fn weak_etag(bytes: &[u8]) -> String {
    let h = tesserax::ct::sha256(bytes);
    let hex: String = h.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("W/\"{hex}\"")
}

/// RFC 9110 weak comparison against an `If-None-Match` list.
fn etag_matches(if_none_match: &str, etag: &str) -> bool {
    let ours = etag.trim_start_matches("W/");
    if_none_match
        .split(',')
        .map(str::trim)
        .any(|c| c == "*" || c.trim_start_matches("W/") == ours)
}

/// The `ETag` middleware (`from_fn_with_state(cfg, etag_mw)`).
pub async fn etag_mw(State(cfg): State<EtagConfig>, req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return next.run(req).await;
    }
    let inm = req
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let resp = next.run(req).await;
    let hashable = resp.status().is_success()
        && resp
            .body()
            .size_hint()
            .exact()
            .is_some_and(|n| n <= cfg.max_body_bytes as u64);
    if !hashable {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let Ok(bytes) = to_bytes(body, cfg.max_body_bytes).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let tag = weak_etag(&bytes);
    let Ok(tag_value) = HeaderValue::from_str(&tag) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    if inm.as_deref().is_some_and(|c| etag_matches(c, &tag)) {
        let mut nm = StatusCode::NOT_MODIFIED.into_response();
        nm.headers_mut().insert(header::ETAG, tag_value);
        if let Some(cc) = parts.headers.get(header::CACHE_CONTROL) {
            nm.headers_mut().insert(header::CACHE_CONTROL, cc.clone());
        }
        return nm;
    }
    parts.headers.insert(header::ETAG, tag_value);
    Response::from_parts(parts, Body::from(bytes))
}

/// The `Server-Timing` middleware (`from_fn(server_timing_mw)`).
pub async fn server_timing_mw(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let mut resp = next.run(req).await;
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    if let Ok(v) = HeaderValue::from_str(&format!("total;dur={ms:.2}")) {
        resp.headers_mut().append("server-timing", v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::middleware::{from_fn, from_fn_with_state};
    use axum::routing::get;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route(
                "/ping",
                get(|| async { "pong" }).post(|| async { "posted" }),
            )
            .route("/missing", get(|| async { (StatusCode::NOT_FOUND, "no") }))
            .layer(from_fn_with_state(EtagConfig::default(), etag_mw))
    }

    async fn call(method: Method, uri: &str, inm: Option<&str>) -> Response {
        let mut b = axum::http::Request::builder().method(method).uri(uri);
        if let Some(v) = inm {
            b = b.header(header::IF_NONE_MATCH, v);
        }
        app().oneshot(b.body(Body::empty()).unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn etag_then_304() {
        let r = call(Method::GET, "/ping", None).await;
        let tag = r.headers()[header::ETAG].to_str().unwrap().to_owned();
        assert_eq!(tag, weak_etag(b"pong"));
        assert_eq!(tag.len(), 3 + 16 + 1);
        let r = call(Method::GET, "/ping", Some(&tag)).await;
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
        assert!(to_bytes(r.into_body(), 64).await.unwrap().is_empty());
        assert!(
            call(Method::POST, "/ping", None)
                .await
                .headers()
                .get(header::ETAG)
                .is_none()
        );
        assert!(
            call(Method::GET, "/missing", None)
                .await
                .headers()
                .get(header::ETAG)
                .is_none()
        );
    }

    #[test]
    fn matching() {
        assert!(etag_matches("*", "W/\"abc\""));
        assert!(etag_matches("\"abc\"", "W/\"abc\""));
        assert!(etag_matches("W/\"a\", W/\"abc\"", "W/\"abc\""));
        assert!(!etag_matches("W/\"xyz\"", "W/\"abc\""));
    }

    #[tokio::test]
    async fn server_timing_header() {
        let app = Router::new()
            .route("/", get(|| async { "x" }))
            .layer(from_fn(server_timing_mw));
        let r = app
            .oneshot(axum::http::Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let v = r.headers()["server-timing"].to_str().unwrap();
        assert!(v.starts_with("total;dur="));
        let _ms: f64 = v.trim_start_matches("total;dur=").parse().unwrap();
    }
}
