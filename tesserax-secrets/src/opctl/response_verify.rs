//! Verify a signed response (headers `x-tesserax-sig`, `x-tesserax-sig-time`,
//! `x-tesserax-sig-fingerprint`; canonical bytes in [`crate::signing`]) on a
//! `reqwest::Response`, returning the consumed body with the result.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verification failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ResponseVerifyError {
    #[error("response missing x-tesserax-sig header (signing not enabled for this path?)")]
    MissingSigHeader,
    #[error("response missing X-Stk-Sig-Time header")]
    MissingTimeHeader,
    #[error("response missing X-Stk-Sig-Fingerprint header")]
    MissingFpHeader,
    #[error("fingerprint mismatch — expected {expected}, daemon advertised {got}")]
    FingerprintMismatch { expected: String, got: String },
    #[error("base64 decode signature: {0}")]
    SigBase64(String),
    #[error("signature wrong length: expected 64 bytes, got {0}")]
    SigLen(usize),
    #[error("ed25519 verify failed: {0}")]
    Ed25519(String),
    #[error(
        "clock skew too large: daemon-stamp {daemon_unix}, local now {local_unix}, |delta|={delta}s (cap {max_skew}s)"
    )]
    Skew {
        daemon_unix: u64,
        local_unix: u64,
        delta: u64,
        max_skew: u64,
    },
    #[error("response body read: {0}")]
    Body(String),
    #[error("parse: {0}")]
    Parse(String),
}

/// A response whose signature verified.
#[derive(Debug, Clone)]
pub struct VerifiedResponse {
    /// HTTP status.
    pub status: u16,
    /// Body.
    pub body: Vec<u8>,
    /// Signer fingerprint.
    pub fingerprint: String,
    /// Signed time (Unix seconds).
    pub daemon_stamped_unix: u64,
}

/// Verify a `reqwest::Response`. Consumes the body to read it once.
///
/// Arguments:
/// - `resp` — what we got back from the daemon.
/// - `path` — the path WE requested (`/admin/op-cmd`, etc.).
///   Required because the daemon's middleware doesn't echo it.
/// - `pubkey` — caller-pinned daemon pubkey (32 bytes).
/// - `expected_fingerprint` — caller-pinned fingerprint, MUST match
///   the `X-Stk-Sig-Fingerprint` header (extra defence: if the daemon's
///   identity rotated unexpectedly the operator sees it instantly).
/// - `max_skew_secs` — refuse to verify if `|daemon_unix - now| > N`.
///   Typical 300s. Pass `u64::MAX` to disable.
pub async fn verify_response_signature(
    resp: reqwest::Response,
    path: &str,
    pubkey: &VerifyingKey,
    expected_fingerprint: &str,
    max_skew_secs: u64,
) -> Result<VerifiedResponse, ResponseVerifyError> {
    let status_code = resp.status().as_u16();

    let header = |name: &str| -> Option<String> {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    let sig_b64 = header("x-tesserax-sig").ok_or(ResponseVerifyError::MissingSigHeader)?;
    let time_str = header("x-tesserax-sig-time").ok_or(ResponseVerifyError::MissingTimeHeader)?;
    let fp = header("x-tesserax-sig-fingerprint").ok_or(ResponseVerifyError::MissingFpHeader)?;

    if !tesserax::ct::ct_eq_str(&fp, expected_fingerprint) {
        return Err(ResponseVerifyError::FingerprintMismatch {
            expected: expected_fingerprint.to_string(),
            got: fp,
        });
    }

    let daemon_unix: u64 = time_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ResponseVerifyError::Parse(format!("time: {e}")))?;
    if max_skew_secs != u64::MAX {
        let local_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let delta = local_unix.abs_diff(daemon_unix);
        if delta > max_skew_secs {
            return Err(ResponseVerifyError::Skew {
                daemon_unix,
                local_unix,
                delta,
                max_skew: max_skew_secs,
            });
        }
    }

    let sig_bytes = B64
        .decode(sig_b64.as_bytes())
        .map_err(|e| ResponseVerifyError::SigBase64(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(ResponseVerifyError::SigLen(sig_bytes.len()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let body = resp
        .bytes()
        .await
        .map_err(|e| ResponseVerifyError::Body(e.to_string()))?
        .to_vec();

    let body_hash = blake3::hash(&body);
    let body_hash_b64 = B64.encode(body_hash.as_bytes());

    let canonical =
        crate::signing::canonical_signing_bytes(daemon_unix, status_code, path, &body_hash_b64);

    pubkey
        .verify(&canonical, &signature)
        .map_err(|e| ResponseVerifyError::Ed25519(e.to_string()))?;

    Ok(VerifiedResponse {
        status: status_code,
        body,
        fingerprint: fp,
        daemon_stamped_unix: daemon_unix,
    })
}
