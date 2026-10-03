//! [`WebhookVerifier`]: HMAC-SHA256 signed webhook receipt with a replay
//! window.
//!
//! ```text
//! X-Webhook-Signature: sha256=<hex>        (the prefix is optional)
//! X-Webhook-Timestamp: <unix seconds>      (required unless body_only)
//! ```
//!
//! The MAC is `HMAC-SHA256(secret, timestamp || "." || body)`, and the
//! timestamp must be within `max_skew_secs` (default 300) of now; with
//! [`WebhookVerifier::body_only`] it is `HMAC-SHA256(secret, body)` and a
//! captured delivery can be replayed forever, so use that only for
//! publishers that cannot sign a timestamp. Verification is an explicit
//! handler step over the buffered body (`Bytes` extractor), not a layer, so
//! body limits and streaming handlers stay intact.
//!
//! ```
//! use axum::{body::Bytes, http::{HeaderMap, StatusCode}};
//! use tesserax_http::guard::WebhookVerifier;
//!
//! async fn receive(headers: HeaderMap, body: Bytes) -> StatusCode {
//!     let v = WebhookVerifier::new(b"shared-secret".to_vec());
//!     match v.verify(&headers, &body) {
//!         Ok(()) => StatusCode::NO_CONTENT,
//!         Err(status) => status,
//!     }
//! }
//! ```

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use tesserax::ct::{ct_eq, hmac_sha256};

use super::unix_now;

/// Signature header.
pub const WEBHOOK_SIGNATURE: &str = "x-webhook-signature";
/// Timestamp header.
pub const WEBHOOK_TIMESTAMP: &str = "x-webhook-timestamp";

/// Verifies signed webhook deliveries. Cheap to clone.
#[derive(Clone)]
pub struct WebhookVerifier {
    secret: Arc<[u8]>,
    body_only: bool,
    max_skew_secs: u64,
}

impl std::fmt::Debug for WebhookVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookVerifier")
            .field("secret", &"<redacted>")
            .field("body_only", &self.body_only)
            .field("max_skew_secs", &self.max_skew_secs)
            .finish()
    }
}

impl WebhookVerifier {
    /// Timestamped mode, 300 s window.
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: Arc::from(secret.into().into_boxed_slice()),
            body_only: false,
            max_skew_secs: 300,
        }
    }

    /// Signs the body only (no replay protection).
    pub fn body_only(mut self, on: bool) -> Self {
        self.body_only = on;
        self
    }

    /// Replay window in seconds.
    pub fn max_skew_secs(mut self, secs: u64) -> Self {
        self.max_skew_secs = secs;
        self
    }

    /// The expected MAC for `body` delivered at `timestamp` (the header
    /// text), for tests and senders.
    pub fn mac(&self, timestamp: Option<&str>, body: &[u8]) -> [u8; 32] {
        match timestamp {
            Some(ts) if !self.body_only => {
                let mut msg = Vec::with_capacity(ts.len() + 1 + body.len());
                msg.extend_from_slice(ts.as_bytes());
                msg.push(b'.');
                msg.extend_from_slice(body);
                hmac_sha256(&self.secret, &msg)
            }
            _ => hmac_sha256(&self.secret, body),
        }
    }

    /// `Ok` if the delivery is authentic and fresh; otherwise the status to
    /// answer (always 401).
    pub fn verify(&self, headers: &HeaderMap, body: &[u8]) -> Result<(), StatusCode> {
        self.verify_at(headers, body, unix_now())
    }

    fn verify_at(&self, headers: &HeaderMap, body: &[u8], now: u64) -> Result<(), StatusCode> {
        let presented = headers
            .get(WEBHOOK_SIGNATURE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_signature)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let ts = if self.body_only {
            None
        } else {
            let raw = headers
                .get(WEBHOOK_TIMESTAMP)
                .and_then(|v| v.to_str().ok())
                .ok_or(StatusCode::UNAUTHORIZED)?;
            let t: u64 = raw.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;
            if now.abs_diff(t) > self.max_skew_secs {
                tracing::warn!(ts = t, now, "webhook timestamp outside the replay window");
                return Err(StatusCode::UNAUTHORIZED);
            }
            Some(raw)
        };
        if ct_eq(&self.mac(ts, body), &presented) {
            Ok(())
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// `sha256=<hex>` or bare `<hex>` into bytes.
fn parse_signature(s: &str) -> Option<Vec<u8>> {
    let hex = s.strip_prefix("sha256=").unwrap_or(s).as_bytes();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.chunks(2)
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const SECRET: &[u8] = b"s3cret";
    const NOW: u64 = 1_700_000_000;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn headers(sig: &str, ts: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(WEBHOOK_SIGNATURE, HeaderValue::from_str(sig).unwrap());
        if let Some(ts) = ts {
            h.insert(WEBHOOK_TIMESTAMP, HeaderValue::from_str(ts).unwrap());
        }
        h
    }

    /// RFC 4231 case 1 through the verifier's MAC path (body-only mode is
    /// exactly `HMAC-SHA256(secret, body)`).
    #[test]
    fn body_only_mac_is_rfc4231() {
        let v = WebhookVerifier::new(vec![0x0b; 20]).body_only(true);
        assert_eq!(
            hex(&v.mac(None, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let h = headers(
            "sha256=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            None,
        );
        assert!(v.verify_at(&h, b"Hi There", NOW).is_ok());
    }

    #[test]
    fn timestamped_signature() {
        let v = WebhookVerifier::new(SECRET.to_vec());
        let ts = NOW.to_string();
        let sig = format!("sha256={}", hex(&v.mac(Some(&ts), b"{\"x\":1}")));
        assert!(
            v.verify_at(&headers(&sig, Some(&ts)), b"{\"x\":1}", NOW)
                .is_ok()
        );
        // Bare hex accepted too.
        let bare = hex(&v.mac(Some(&ts), b"{\"x\":1}"));
        assert!(
            v.verify_at(&headers(&bare, Some(&ts)), b"{\"x\":1}", NOW)
                .is_ok()
        );
        // Body tampered.
        assert_eq!(
            v.verify_at(&headers(&sig, Some(&ts)), b"{\"x\":2}", NOW),
            Err(StatusCode::UNAUTHORIZED)
        );
        // Outside the window.
        assert_eq!(
            v.verify_at(&headers(&sig, Some(&ts)), b"{\"x\":1}", NOW + 3600),
            Err(StatusCode::UNAUTHORIZED)
        );
        // Timestamp required in the default mode.
        assert_eq!(
            v.verify_at(&headers(&sig, None), b"{\"x\":1}", NOW),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn refusals() {
        let v = WebhookVerifier::new(SECRET.to_vec());
        assert_eq!(
            v.verify_at(&HeaderMap::new(), b"x", NOW),
            Err(StatusCode::UNAUTHORIZED)
        );
        let ts = NOW.to_string();
        let zero = format!("sha256={}", "00".repeat(32));
        assert_eq!(
            v.verify_at(&headers(&zero, Some(&ts)), b"x", NOW),
            Err(StatusCode::UNAUTHORIZED)
        );
        // Short signature: refused, no panic.
        assert_eq!(
            v.verify_at(&headers("sha256=ab", Some(&ts)), b"x", NOW),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn signature_parsing() {
        assert_eq!(parse_signature("sha256=ab"), Some(vec![0xab]));
        assert_eq!(parse_signature("AB"), Some(vec![0xab]));
        assert_eq!(parse_signature("sha256=zz"), None);
        assert_eq!(parse_signature("a"), None);
    }
}
