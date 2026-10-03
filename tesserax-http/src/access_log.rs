//! One `tracing` line per request: method, path, status, latency and the
//! root's `RequestId` when present.

use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use tesserax::RequestId;

/// The middleware (`from_fn(access_log_mw)`).
pub async fn access_log_mw(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let id = req.extensions().get::<RequestId>().cloned();
    let start = Instant::now();
    let resp = next.run(req).await;
    let latency_ms = start.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();
    match id {
        Some(id) => tracing::info!(%method, %path, status, latency_ms, request_id = %id, "request"),
        None => tracing::info!(%method, %path, status, latency_ms, "request"),
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::middleware::from_fn;
    use axum::routing::get;
    use tower::ServiceExt;

    #[tokio::test]
    async fn transparent() {
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(from_fn(access_log_mw));
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::get("/ping")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            &axum::body::to_bytes(r.into_body(), 64).await.unwrap()[..],
            b"pong"
        );
        let r = app
            .oneshot(
                axum::http::Request::get("/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }
}
