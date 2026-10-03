//! CORS layer from a few canonical policies.

use axum::http::HeaderValue;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, Any, CorsLayer};

/// A CORS policy.
#[derive(Clone, Debug)]
pub enum CorsPolicy {
    /// `Access-Control-Allow-Origin: *`, any method and header, no
    /// credentials. For fully public read-only APIs.
    AllowAny,
    /// Echo the request's origin, method and headers and allow
    /// credentials. Only for a page served by the same host.
    SameOrigin,
    /// Only these origins (full origins such as `https://app.example.com`),
    /// any method and header, no credentials. Unparsable entries are
    /// dropped.
    Whitelist(Vec<String>),
    /// A hand-built layer.
    Custom(Box<CorsLayer>),
}

/// The `tower_http` layer of `policy`.
pub fn cors_policy(policy: CorsPolicy) -> CorsLayer {
    match policy {
        CorsPolicy::AllowAny => CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any),
        // Credentials forbid the `*` wildcards; mirror the request instead.
        CorsPolicy::SameOrigin => CorsLayer::new()
            .allow_origin(AllowOrigin::mirror_request())
            .allow_methods(AllowMethods::mirror_request())
            .allow_headers(AllowHeaders::mirror_request())
            .allow_credentials(true),
        CorsPolicy::Whitelist(origins) => {
            let parsed: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
            CorsLayer::new()
                .allow_origin(parsed)
                .allow_methods(Any)
                .allow_headers(Any)
        }
        CorsPolicy::Custom(layer) => *layer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    async fn preflight(policy: CorsPolicy, origin: &str) -> (StatusCode, Option<String>) {
        let app = Router::new()
            .route("/x", get(|| async { "x" }))
            .layer(cors_policy(policy));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/x")
                    .header("origin", origin)
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-headers", "content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap().to_owned());
        (resp.status(), acao)
    }

    #[tokio::test]
    async fn every_policy_serves() {
        assert_eq!(
            preflight(CorsPolicy::AllowAny, "https://a.example")
                .await
                .1
                .as_deref(),
            Some("*")
        );
        // Would panic inside tower-http if credentials were combined with `*`.
        assert_eq!(
            preflight(CorsPolicy::SameOrigin, "https://a.example")
                .await
                .1
                .as_deref(),
            Some("https://a.example")
        );
        let wl = || CorsPolicy::Whitelist(vec!["https://app.example.com".into()]);
        assert_eq!(
            preflight(wl(), "https://app.example.com")
                .await
                .1
                .as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(preflight(wl(), "https://evil.example").await.1, None);
    }
}
