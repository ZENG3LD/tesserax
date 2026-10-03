//! [`wasm_headers`]: `Cross-Origin-Opener-Policy: same-origin` and
//! `Cross-Origin-Embedder-Policy: require-corp`, which a page needs for
//! `SharedArrayBuffer` / wasm threads. Apply them to the router that serves
//! the wasm bundle. (`.wasm` files are served as `application/wasm` by
//! [`StaticDir`](super::StaticDir) through the file extension.)

use axum::http::HeaderValue;
use axum::http::header::HeaderName;
use tower_http::set_header::SetResponseHeaderLayer;

/// The two cross-origin isolation layers.
pub fn wasm_headers() -> [SetResponseHeaderLayer<HeaderValue>; 2] {
    [
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-embedder-policy"),
            HeaderValue::from_static("require-corp"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt;

    #[tokio::test]
    async fn sets_both() {
        let [a, b] = wasm_headers();
        let app = Router::new()
            .route("/", get(|| async { "x" }))
            .layer(a)
            .layer(b);
        let r = app
            .oneshot(axum::http::Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.headers()["cross-origin-opener-policy"], "same-origin");
        assert_eq!(r.headers()["cross-origin-embedder-policy"], "require-corp");
    }
}
