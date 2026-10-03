//! Signed responses: the state and canonical bytes behind a response
//! signing middleware (the middleware itself belongs to the HTTP crate).
//!
//! A service signs selected responses with its [`DaemonIdentity`] so a
//! caller can detect a body swapped between the two ends even when TLS
//! is terminated elsewhere. Canonical bytes (frozen wire format):
//!
//! ```text
//! "tesserax-resp-v1" || '\n' || unix_seconds || '\n' || status || '\n' || path || '\n' || body_blake3_b64url
//! ```
//!
//! Headers: [`HEADER_SIG`] (ed25519, URL-safe base64 without padding),
//! [`HEADER_SIG_TIME`] (the signed `unix_seconds`) and [`HEADER_SIG_FP`]
//! (the identity's `pubkey_fingerprint`). The signer does not police clock
//! skew; the verifier decides (see `opctl::verify_response_signature`).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::identity::DaemonIdentity;

const CANONICAL_PREFIX: &[u8] = b"tesserax-resp-v1";

/// Signature header name.
pub const HEADER_SIG: &str = "x-tesserax-sig";
/// Signed-time header name.
pub const HEADER_SIG_TIME: &str = "x-tesserax-sig-time";
/// Signer-fingerprint header name.
pub const HEADER_SIG_FP: &str = "x-tesserax-sig-fingerprint";

/// Bodies above this size are not signed (they would have to be buffered).
pub const MAX_SIGNED_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Which responses get signed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SigningScope {
    /// Every response.
    AllRoutes,
    /// Paths under `/admin/` and `/manifest`.
    #[default]
    AdminRoutes,
    /// Paths starting with any of these prefixes.
    PrefixList(Vec<String>),
}

impl SigningScope {
    /// True if responses for `path` are signed.
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::AllRoutes => true,
            Self::AdminRoutes => path.starts_with("/admin/") || path == "/manifest",
            Self::PrefixList(prefixes) => prefixes.iter().any(|p| path.starts_with(p.as_str())),
        }
    }
}

/// Response-signing configuration.
#[derive(Debug, Clone, Default)]
pub struct SignedResponseConfig {
    /// Which responses are signed.
    pub scope: SigningScope,
}

/// Header values for one signed response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseSignature {
    /// Value of [`HEADER_SIG`].
    pub signature_b64: String,
    /// Value of [`HEADER_SIG_TIME`].
    pub unix_seconds: u64,
    /// Value of [`HEADER_SIG_FP`].
    pub fingerprint: String,
}

/// Identity + scope shared by a signing middleware.
#[derive(Clone, Debug)]
pub struct ResponseSigningState {
    identity: DaemonIdentity,
    scope: SigningScope,
}

impl ResponseSigningState {
    /// New state.
    pub fn new(identity: DaemonIdentity, cfg: SignedResponseConfig) -> Self {
        Self {
            identity,
            scope: cfg.scope,
        }
    }

    /// True if a response for `path` must be signed.
    pub fn applies_to(&self, path: &str) -> bool {
        self.scope.matches(path)
    }

    /// The identity.
    pub fn identity(&self) -> &DaemonIdentity {
        &self.identity
    }

    /// Signs one response.
    pub fn sign(
        &self,
        unix_seconds: u64,
        status: u16,
        path: &str,
        body: &[u8],
    ) -> ResponseSignature {
        let canonical = canonical_signing_bytes(unix_seconds, status, path, &body_hash_b64(body));
        ResponseSignature {
            signature_b64: B64.encode(self.identity.sign(&canonical).to_bytes()),
            unix_seconds,
            fingerprint: self.identity.pubkey_fingerprint().to_owned(),
        }
    }
}

/// URL-safe base64 (no padding) of BLAKE3(`body`).
pub fn body_hash_b64(body: &[u8]) -> String {
    B64.encode(blake3::hash(body).as_bytes())
}

/// The bytes a response signature covers.
pub fn canonical_signing_bytes(
    unix_seconds: u64,
    status_code: u16,
    path: &str,
    body_hash_b64: &str,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(CANONICAL_PREFIX.len() + 28 + path.len() + body_hash_b64.len());
    out.extend_from_slice(CANONICAL_PREFIX);
    out.push(b'\n');
    out.extend_from_slice(unix_seconds.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(status_code.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(body_hash_b64.as_bytes());
    out
}

/// Verifies a response signature against `pubkey`.
pub fn verify_response(
    pubkey: &VerifyingKey,
    unix_seconds: u64,
    status: u16,
    path: &str,
    body: &[u8],
    signature_b64: &str,
) -> bool {
    let Ok(raw) = B64.decode(signature_b64.as_bytes()) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&raw) else {
        return false;
    };
    let canonical = canonical_signing_bytes(unix_seconds, status, path, &body_hash_b64(body));
    pubkey.verify(&canonical, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_are_byte_locked() {
        let bytes = canonical_signing_bytes(1_700_000_000, 200, "/admin/info", "abc123");
        assert_eq!(
            bytes,
            b"tesserax-resp-v1\n1700000000\n200\n/admin/info\nabc123"
        );
    }

    #[test]
    fn scopes() {
        assert!(SigningScope::AdminRoutes.matches("/admin/x"));
        assert!(SigningScope::AdminRoutes.matches("/manifest"));
        assert!(!SigningScope::AdminRoutes.matches("/health"));
        assert!(SigningScope::AllRoutes.matches("/health"));
        let p = SigningScope::PrefixList(vec!["/api/secure/".into()]);
        assert!(p.matches("/api/secure/a"));
        assert!(!p.matches("/api/open/a"));
    }

    #[test]
    fn sign_then_verify_and_tamper() {
        let id = DaemonIdentity::generate().unwrap();
        let st = ResponseSigningState::new(id.clone(), SignedResponseConfig::default());
        let s = st.sign(10, 200, "/admin/info", b"{\"ok\":true}");
        assert_eq!(s.fingerprint, id.pubkey_fingerprint());
        assert!(verify_response(
            id.verifying_key(),
            10,
            200,
            "/admin/info",
            b"{\"ok\":true}",
            &s.signature_b64
        ));
        assert!(!verify_response(
            id.verifying_key(),
            10,
            200,
            "/admin/info",
            b"tampered",
            &s.signature_b64
        ));
        assert!(!verify_response(
            id.verifying_key(),
            11,
            200,
            "/admin/info",
            b"{\"ok\":true}",
            &s.signature_b64
        ));
        assert!(!verify_response(
            id.verifying_key(),
            10,
            200,
            "/admin/info",
            b"{\"ok\":true}",
            "!!"
        ));
    }
}
