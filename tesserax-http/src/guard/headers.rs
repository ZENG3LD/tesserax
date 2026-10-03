//! [`SecurityHeaders`]: baseline security response headers.
//!
//! Defaults (OWASP secure-headers baseline): `Strict-Transport-Security:
//! max-age=31536000; includeSubDomains`, `X-Content-Type-Options: nosniff`,
//! `X-Frame-Options: DENY`, `Referrer-Policy:
//! strict-origin-when-cross-origin`, an empty `Permissions-Policy`,
//! `X-XSS-Protection: 0`; `Content-Security-Policy` is opt-in. Each header
//! overrides one set by a handler.

use axum::Router;
use axum::http::HeaderValue;
use axum::http::header::{self, HeaderName};
use tower_http::set_header::SetResponseHeaderLayer;

/// Which security headers to set (`None` leaves one out).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityHeaders {
    /// `Strict-Transport-Security`.
    pub hsts: Option<String>,
    /// `X-Frame-Options`.
    pub frame_options: Option<String>,
    /// `X-Content-Type-Options`.
    pub content_type_options: Option<String>,
    /// `Referrer-Policy`.
    pub referrer_policy: Option<String>,
    /// `Permissions-Policy`.
    pub permissions_policy: Option<String>,
    /// `X-XSS-Protection`.
    pub xss_protection: Option<String>,
    /// `Content-Security-Policy`.
    pub content_security_policy: Option<String>,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            hsts: Some("max-age=31536000; includeSubDomains".into()),
            frame_options: Some("DENY".into()),
            content_type_options: Some("nosniff".into()),
            referrer_policy: Some("strict-origin-when-cross-origin".into()),
            permissions_policy: Some(String::new()),
            xss_protection: Some("0".into()),
            content_security_policy: None,
        }
    }
}

impl SecurityHeaders {
    /// Drops HSTS (plain-HTTP loopback services).
    pub fn without_hsts(mut self) -> Self {
        self.hsts = None;
        self
    }

    /// `X-Frame-Options: SAMEORIGIN`.
    pub fn allow_same_origin_frame(mut self) -> Self {
        self.frame_options = Some("SAMEORIGIN".into());
        self
    }

    /// Sets `Content-Security-Policy`.
    pub fn with_content_security_policy(mut self, csp: impl Into<String>) -> Self {
        self.content_security_policy = Some(csp.into());
        self
    }

    /// One layer per configured header; values that are not valid header
    /// values are skipped.
    pub fn layers(&self) -> Vec<SetResponseHeaderLayer<HeaderValue>> {
        let pairs: [(HeaderName, &Option<String>); 7] = [
            (header::STRICT_TRANSPORT_SECURITY, &self.hsts),
            (header::X_FRAME_OPTIONS, &self.frame_options),
            (header::X_CONTENT_TYPE_OPTIONS, &self.content_type_options),
            (header::REFERRER_POLICY, &self.referrer_policy),
            (
                HeaderName::from_static("permissions-policy"),
                &self.permissions_policy,
            ),
            (header::X_XSS_PROTECTION, &self.xss_protection),
            (
                header::CONTENT_SECURITY_POLICY,
                &self.content_security_policy,
            ),
        ];
        pairs
            .into_iter()
            .filter_map(|(name, v)| {
                let hv = HeaderValue::from_str(v.as_deref()?).ok()?;
                Some(SetResponseHeaderLayer::overriding(name, hv))
            })
            .collect()
    }

    /// Applies every layer to `router`.
    pub fn apply(&self, router: Router) -> Router {
        self.layers().into_iter().fold(router, |r, l| r.layer(l))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt;

    #[test]
    fn layer_counts() {
        assert_eq!(SecurityHeaders::default().layers().len(), 6);
        assert_eq!(SecurityHeaders::default().without_hsts().layers().len(), 5);
        assert_eq!(
            SecurityHeaders::default()
                .with_content_security_policy("default-src 'self'")
                .layers()
                .len(),
            7
        );
    }

    #[tokio::test]
    async fn headers_are_set() {
        let app = SecurityHeaders::default()
            .allow_same_origin_frame()
            .apply(Router::new().route("/", get(|| async { "x" })));
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let h = resp.headers();
        assert_eq!(h["x-frame-options"], "SAMEORIGIN");
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["permissions-policy"], "");
        assert!(h.contains_key("strict-transport-security"));
    }
}
