//! W3C Trace Context (`traceparent`) propagation.
//!
//! A valid inbound `traceparent` (`00-<32 hex>-<16 hex>-<2 hex>`, neither
//! id all zero) keeps its trace id and flags; otherwise a trace id is
//! minted. Either way this hop gets a fresh span id. The resulting
//! [`TraceContext`] is a request extension (for outbound calls) and is
//! echoed in the response `traceparent`.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// Header name.
pub const TRACEPARENT: &str = "traceparent";

/// This hop's trace context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceContext {
    /// 32 lower-case hex digits.
    pub trace_id: String,
    /// 16 lower-case hex digits: this hop's span.
    pub span_id: String,
    /// Trace flags (bit 0 = sampled).
    pub flags: u8,
    /// True if the trace id came from the request.
    pub inbound: bool,
}

impl TraceContext {
    /// W3C header form.
    pub fn to_header(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.flags)
    }
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `(trace_id, flags)` of a valid header.
fn parse(s: &str) -> Option<(String, u8)> {
    let mut it = s.trim().split('-');
    let (v, t, p, f) = (it.next()?, it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || v != "00" || !is_hex(t, 32) || !is_hex(p, 16) || !is_hex(f, 2) {
        return None;
    }
    if t.bytes().all(|b| b == b'0') || p.bytes().all(|b| b == b'0') {
        return None;
    }
    Some((t.to_ascii_lowercase(), u8::from_str_radix(f, 16).ok()?))
}

/// `n` random bytes as lower-case hex; never all zero.
fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    if getrandom::fill(&mut buf).is_err() || buf.iter().all(|b| *b == 0) {
        // Not a secret: uniqueness only. Fall back to a clock + counter hash.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let seed = format!(
            "{:?}|{}",
            std::time::SystemTime::now(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let h = tesserax::ct::sha256(seed.as_bytes());
        buf.copy_from_slice(&h[..n]);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// The middleware (`from_fn(traceparent_mw)`).
pub async fn traceparent_mw(mut req: Request, next: Next) -> Response {
    let inbound = req
        .headers()
        .get(TRACEPARENT)
        .and_then(|v| v.to_str().ok())
        .and_then(parse);
    let ctx = match inbound {
        Some((trace_id, flags)) => TraceContext {
            trace_id,
            span_id: random_hex(8),
            flags,
            inbound: true,
        },
        None => TraceContext {
            trace_id: random_hex(16),
            span_id: random_hex(8),
            flags: 0x01,
            inbound: false,
        },
    };
    let header = ctx.to_header();
    req.extensions_mut().insert(ctx);
    let mut resp = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&header) {
        resp.headers_mut().insert(TRACEPARENT, v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::middleware::from_fn;
    use axum::routing::get;
    use tower::ServiceExt;

    const INBOUND: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    async fn call(tp: Option<&str>) -> (String, String) {
        let app = Router::new()
            .route(
                "/",
                get(|Extension(tc): Extension<TraceContext>| async move { tc.to_header() }),
            )
            .layer(from_fn(traceparent_mw));
        let mut b = axum::http::Request::get("/");
        if let Some(v) = tp {
            b = b.header(TRACEPARENT, v);
        }
        let r = app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
        let h = r.headers()[TRACEPARENT].to_str().unwrap().to_owned();
        let body = axum::body::to_bytes(r.into_body(), 256).await.unwrap();
        (h, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn propagates_and_mints() {
        let (h, ext) = call(Some(INBOUND)).await;
        assert_eq!(h, ext);
        assert!(h.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert_ne!(h.split('-').nth(2), Some("00f067aa0ba902b7"));
        for bad in [None, Some("garbage")] {
            let (h, _) = call(bad).await;
            let (t, _) = parse(&h).unwrap();
            assert_ne!(t, "4bf92f3577b34da6a3ce929d0e0e4736");
        }
    }

    #[test]
    fn parser() {
        assert_eq!(
            parse(INBOUND),
            Some(("4bf92f3577b34da6a3ce929d0e0e4736".into(), 1))
        );
        assert!(parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none());
        assert!(parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_none());
        assert!(parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01").is_none());
        assert!(parse("00-short-00f067aa0ba902b7-01").is_none());
        assert!(parse(&format!("{INBOUND}-x")).is_none());
        assert_ne!(random_hex(8), random_hex(8));
    }
}
