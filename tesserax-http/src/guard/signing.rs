//! Response signing middleware over `tesserax_secrets::signing` (feature
//! `signing`).
//!
//! For a request whose path the state's scope covers, the response body is
//! buffered and signed with [`ResponseSigningState::sign`]; the headers
//! `x-tesserax-sig`, `x-tesserax-sig-time` and `x-tesserax-sig-fingerprint` (frozen wire
//! names, see `tesserax_secrets::signing`) are added. A response whose
//! length is not known up front or exceeds
//! [`MAX_SIGNED_BODY_BYTES`](tesserax_secrets::signing::MAX_SIGNED_BODY_BYTES)
//! (streams, large downloads) is passed through unsigned: a verifier
//! refuses it for the missing headers, and nothing is buffered without
//! bound. Installed at `LayerStage::ResponseSigning`, inside compression,
//! so the signature covers the uncompressed body.

use std::sync::Arc;

use axum::body::{Body, HttpBody, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tesserax_secrets::signing::{
    HEADER_SIG, HEADER_SIG_FP, HEADER_SIG_TIME, MAX_SIGNED_BODY_BYTES, ResponseSigningState,
};

use super::{refuse, unix_now};

/// The middleware (`from_fn_with_state(Arc<ResponseSigningState>, response_signing_mw)`).
pub async fn response_signing_mw(
    State(state): State<Arc<ResponseSigningState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_owned();
    if !state.applies_to(&path) {
        return next.run(req).await;
    }
    let resp = next.run(req).await;
    let bounded = resp
        .body()
        .size_hint()
        .exact()
        .is_some_and(|n| n <= MAX_SIGNED_BODY_BYTES as u64);
    if !bounded {
        tracing::debug!(%path, "response not signed: body length unknown or too large");
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let bytes = match to_bytes(body, MAX_SIGNED_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, %path, "response signing: body failed");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, "response_body_failed");
        }
    };
    let sig = state.sign(unix_now(), parts.status.as_u16(), &path, &bytes);
    let pairs = [
        (HEADER_SIG, sig.signature_b64),
        (HEADER_SIG_TIME, sig.unix_seconds.to_string()),
        (HEADER_SIG_FP, sig.fingerprint),
    ];
    for (name, value) in pairs {
        if let Ok(v) = HeaderValue::from_str(&value) {
            parts.headers.insert(HeaderName::from_static(name), v);
        }
    }
    Response::from_parts(parts, Body::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use tesserax_secrets::DaemonIdentity;
    use tesserax_secrets::signing::{SignedResponseConfig, verify_response};
    use tower::ServiceExt;

    fn app(id: DaemonIdentity) -> Router {
        let state = Arc::new(ResponseSigningState::new(
            id,
            SignedResponseConfig::default(),
        ));
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/admin/info", get(|| async { r#"{"info":true}"# }))
            .route(
                "/admin/stream",
                get(|| async {
                    let s = futures_util::stream::iter([Ok::<_, std::io::Error>("a"), Ok("b")]);
                    Body::from_stream(s)
                }),
            )
            .layer(from_fn_with_state(state, response_signing_mw))
    }

    async fn get_path(app: Router, path: &str) -> Response {
        app.oneshot(axum::http::Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn admin_response_verifies_and_health_is_unsigned() {
        let id = DaemonIdentity::generate().unwrap();
        let resp = get_path(app(id.clone()), "/admin/info").await;
        let h = resp.headers().clone();
        let sig = h[HEADER_SIG].to_str().unwrap().to_owned();
        let t: u64 = h[HEADER_SIG_TIME].to_str().unwrap().parse().unwrap();
        assert_eq!(h[HEADER_SIG_FP].to_str().unwrap(), id.pubkey_fingerprint());
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(verify_response(
            id.verifying_key(),
            t,
            200,
            "/admin/info",
            &body,
            &sig
        ));
        assert!(!verify_response(
            id.verifying_key(),
            t,
            200,
            "/admin/info",
            b"tampered",
            &sig
        ));

        let resp = get_path(app(id.clone()), "/health").await;
        assert!(resp.headers().get(HEADER_SIG).is_none());
        // Streamed body of unknown length: passed through, unsigned, intact.
        let resp = get_path(app(id), "/admin/stream").await;
        assert!(resp.headers().get(HEADER_SIG).is_none());
        assert_eq!(&to_bytes(resp.into_body(), 1024).await.unwrap()[..], b"ab");
    }
}
