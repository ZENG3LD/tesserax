//! Double-submit CSRF token bound to a server secret.
//!
//! A safe request (`GET`, `HEAD`, `OPTIONS`, `TRACE`) that carries no valid
//! token cookie gets one: `csrf_token=<r>.<m>; Path=/; SameSite=Lax`, where
//! `r` is 32 random bytes and `m = HMAC-SHA256(secret, r)`, both URL-safe
//! base64 without padding. The cookie is readable by page scripts on
//! purpose.
//!
//! A state-changing request must echo the cookie's value in the
//! `X-CSRF-Token` header; it is admitted only if the header is present,
//! equals the cookie (constant time) and its MAC verifies. A cross-site
//! form can make the browser send the cookie but cannot read it to set the
//! header, and a token forged without the secret fails the MAC. Otherwise
//! `403 {"ok":false,"error":"csrf_token_invalid"}`.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use tesserax::ct::{ct_eq, ct_eq_str, hmac_sha256};

use super::refuse;
use crate::error::HttpError;

/// Cookie carrying the token.
pub const CSRF_COOKIE: &str = "csrf_token";
/// Header a state-changing request echoes the token in.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Minimum secret length in bytes.
const MIN_SECRET: usize = 16;

/// The CSRF secret. Cheap to clone.
#[derive(Clone)]
pub struct CsrfState {
    secret: Arc<[u8]>,
}

impl std::fmt::Debug for CsrfState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrfState")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl CsrfState {
    /// A state over `secret` (at least 16 bytes; keep it stable across
    /// restarts, e.g. sealed with `tesserax-secrets`).
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, HttpError> {
        let secret = secret.into();
        if secret.len() < MIN_SECRET {
            return Err(HttpError::Config(format!(
                "csrf secret must be at least {MIN_SECRET} bytes"
            )));
        }
        Ok(Self {
            secret: Arc::from(secret.into_boxed_slice()),
        })
    }

    /// A fresh token `<r>.<m>`.
    pub fn issue(&self) -> Result<String, HttpError> {
        let mut r = [0u8; 32];
        getrandom::fill(&mut r).map_err(|_| HttpError::Random)?;
        let m = hmac_sha256(&self.secret, &r);
        Ok(format!("{}.{}", B64.encode(r), B64.encode(m)))
    }

    /// True iff `token` has the issued shape and its MAC verifies.
    pub fn validate(&self, token: &str) -> bool {
        let Some((r64, m64)) = token.split_once('.') else {
            return false;
        };
        let (Ok(r), Ok(m)) = (B64.decode(r64), B64.decode(m64)) else {
            return false;
        };
        if r.len() != 32 {
            return false;
        }
        ct_eq(&hmac_sha256(&self.secret, &r), &m)
    }
}

fn is_safe(m: &Method) -> bool {
    matches!(
        *m,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// The value of cookie `name` in a `Cookie` header value.
fn cookie_value<'a>(header_value: &'a str, name: &str) -> Option<&'a str> {
    header_value.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

fn request_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|s| cookie_value(s, CSRF_COOKIE))
        .map(str::to_owned)
}

/// The middleware (`from_fn_with_state(state, csrf_mw)`).
pub async fn csrf_mw(State(state): State<CsrfState>, req: Request, next: Next) -> Response {
    let cookie = request_cookie(req.headers());
    if is_safe(req.method()) {
        let needs_cookie = !cookie.as_deref().is_some_and(|c| state.validate(c));
        let mut resp = next.run(req).await;
        if needs_cookie {
            match state.issue() {
                Ok(t) => {
                    let set = format!("{CSRF_COOKIE}={t}; Path=/; SameSite=Lax");
                    if let Ok(v) = HeaderValue::from_str(&set) {
                        resp.headers_mut().append(header::SET_COOKIE, v);
                    }
                }
                Err(e) => tracing::error!(error = %e, "csrf: cannot issue a cookie"),
            }
        }
        return resp;
    }
    let submitted = req
        .headers()
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let admitted = match (submitted.as_deref(), cookie.as_deref()) {
        (Some(s), Some(c)) => ct_eq_str(s, c) && state.validate(s),
        _ => false,
    };
    if admitted {
        next.run(req).await
    } else {
        tracing::warn!(method = %req.method(), "csrf check failed");
        refuse(StatusCode::FORBIDDEN, "csrf_token_invalid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use tower::ServiceExt;

    const SECRET: &[u8] = b"csrf-secret-0123456789";

    fn st() -> CsrfState {
        CsrfState::new(SECRET.to_vec()).unwrap()
    }

    #[test]
    fn short_secret_refused() {
        assert!(CsrfState::new(b"short".to_vec()).is_err());
    }

    #[test]
    fn token_shape_and_validation() {
        let s = st();
        let t = s.issue().unwrap();
        let (r, m) = t.split_once('.').unwrap();
        assert_eq!((r.len(), m.len()), (43, 43));
        assert!(s.validate(&t));
        let other = CsrfState::new(b"another-secret-0123456".to_vec()).unwrap();
        assert!(!other.validate(&t));
        let mut forged = t.clone().into_bytes();
        let last = forged.len() - 1;
        forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
        assert!(!s.validate(&String::from_utf8(forged).unwrap()));
        for bad in ["", "nodot", "a.b", "....."] {
            assert!(!s.validate(bad));
        }
    }

    /// The MAC is the family HMAC: RFC 4231 case 2 through `tesserax::ct`.
    #[test]
    fn mac_is_rfc4231_hmac() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn cookie_parsing() {
        assert_eq!(
            cookie_value("a=1; csrf_token=xyz; b=2", CSRF_COOKIE),
            Some("xyz")
        );
        assert_eq!(cookie_value("a=1", CSRF_COOKIE), None);
        assert_eq!(cookie_value("", CSRF_COOKIE), None);
    }

    fn app() -> Router {
        Router::new()
            .route("/f", get(|| async { "form" }).post(|| async { "done" }))
            .layer(from_fn_with_state(st(), csrf_mw))
    }

    async fn call(method: &str, headers: &[(&str, &str)]) -> Response {
        let mut b = axum::http::Request::builder().method(method).uri("/f");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        app().oneshot(b.body(Body::empty()).unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn double_submit_flow() {
        let resp = call("GET", &[]).await;
        let set = resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(set.ends_with("; Path=/; SameSite=Lax"));
        let token = cookie_value(set.split(';').next().unwrap(), CSRF_COOKIE)
            .unwrap()
            .to_owned();
        let cookie = format!("{CSRF_COOKIE}={token}");

        // A GET that already has a valid cookie gets no new one.
        assert!(
            call("GET", &[("cookie", &cookie)])
                .await
                .headers()
                .get(header::SET_COOKIE)
                .is_none()
        );
        // Cookie + matching header: admitted.
        assert_eq!(
            call("POST", &[("cookie", &cookie), (CSRF_HEADER, &token)])
                .await
                .status(),
            StatusCode::OK
        );
        // Cookie alone (what a cross-site form sends): refused.
        assert_eq!(
            call("POST", &[("cookie", &cookie)]).await.status(),
            StatusCode::FORBIDDEN
        );
        // Header alone, or mismatching: refused.
        assert_eq!(
            call("POST", &[(CSRF_HEADER, &token)]).await.status(),
            StatusCode::FORBIDDEN
        );
        let other = st().issue().unwrap();
        assert_eq!(
            call("POST", &[("cookie", &cookie), (CSRF_HEADER, &other)])
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        // Matching but forged (no valid MAC): refused.
        let forged = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fc = format!("{CSRF_COOKIE}={forged}");
        assert_eq!(
            call("POST", &[("cookie", &fc), (CSRF_HEADER, forged)])
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}
