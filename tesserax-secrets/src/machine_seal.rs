//! [`MachineSeal`]: machine-bound AES-256-GCM seal.
//!
//! Key = `SHA-256([ "dmi=" || product_uuid ] || machine_id || label)`; the
//! `dmi=` part is present in the `DmiV2` variant (used when DMI is
//! readable) and absent in `LegacyV1`. Format (frozen):
//! `base64(nonce_12 || ciphertext || tag_16)`; the variant is recovered on
//! unseal by trying both keys (the GCM tag rejects the wrong one).
//!
//! Weaker than [`SealedSecret`](crate::SealedSecret) (two factors, no
//! fingerprint prefix), for callers that want a seal that survives a user
//! or NIC change. The label separates two services on one host; the
//! default is `tesserax-machine-seal-v1`.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use sha2::{Digest, Sha256};

use crate::host::HostFactors;

/// Why sealing or unsealing failed.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum MachineSealError {
    #[error("machine id lookup: {0}")]
    MachineId(String),
    #[error("aes init: {0}")]
    AesInit(String),
    #[error("encrypt: {0}")]
    Encrypt(String),
    #[error("decrypt: {0}")]
    Decrypt(String),
    #[error("base64: {0}")]
    Base64(String),
    #[error("rng: {0}")]
    Rng(String),
    #[error("payload too short")]
    TooShort,
}

/// Machine-bound seal with a static label.
pub struct MachineSeal {
    info_label: &'static [u8],
}

impl MachineSeal {
    /// Seal with a caller-chosen label.
    pub const fn new(info_label: &'static [u8]) -> Self {
        Self { info_label }
    }

    /// The default label `tesserax-machine-seal-v1`.
    pub const fn default_label() -> Self {
        Self::new(b"tesserax-machine-seal-v1")
    }

    /// Seals against the live host.
    pub fn seal(&self, plaintext: &[u8]) -> Result<String, MachineSealError> {
        self.seal_with(&read_factors()?, plaintext)
    }

    /// Seals against explicit factors (`DmiV2` when a product UUID is
    /// present, `LegacyV1` otherwise).
    pub fn seal_with(
        &self,
        host: &HostFactors,
        plaintext: &[u8],
    ) -> Result<String, MachineSealError> {
        let variant = if host.product_uuid.is_some() {
            Variant::DmiV2
        } else {
            Variant::LegacyV1
        };
        let key = zeroize::Zeroizing::new(self.derive_key(host, variant)?);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| MachineSealError::AesInit(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes).map_err(|e| MachineSealError::Rng(e.to_string()))?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| MachineSealError::Encrypt(e.to_string()))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(B64.encode(out))
    }

    /// Unseals against the live host.
    pub fn unseal(&self, sealed_b64: &str) -> Result<Vec<u8>, MachineSealError> {
        self.unseal_with(&read_factors()?, sealed_b64)
    }

    /// Unseals against explicit factors, trying `DmiV2` then `LegacyV1`.
    pub fn unseal_with(
        &self,
        host: &HostFactors,
        sealed_b64: &str,
    ) -> Result<Vec<u8>, MachineSealError> {
        let bytes = B64
            .decode(sealed_b64.trim())
            .map_err(|e| MachineSealError::Base64(e.to_string()))?;
        if bytes.len() < 12 + 16 {
            return Err(MachineSealError::TooShort);
        }
        let (nonce_bytes, ct) = bytes.split_at(12);
        let variants: &[Variant] = if host.product_uuid.is_some() {
            &[Variant::DmiV2, Variant::LegacyV1]
        } else {
            &[Variant::LegacyV1]
        };
        for &variant in variants {
            let key = zeroize::Zeroizing::new(self.derive_key(host, variant)?);
            let cipher = Aes256Gcm::new_from_slice(key.as_ref())
                .map_err(|e| MachineSealError::AesInit(e.to_string()))?;
            if let Ok(pt) = cipher.decrypt(Nonce::from_slice(nonce_bytes), ct) {
                return Ok(pt);
            }
        }
        Err(MachineSealError::Decrypt(
            "no fingerprint variant opens this blob; sealed on a different host".into(),
        ))
    }

    fn derive_key(
        &self,
        host: &HostFactors,
        variant: Variant,
    ) -> Result<[u8; 32], MachineSealError> {
        let mut h = Sha256::new();
        if variant == Variant::DmiV2 {
            let uuid = host
                .product_uuid
                .as_deref()
                .ok_or_else(|| MachineSealError::MachineId("product_uuid unavailable".into()))?;
            h.update(b"dmi=");
            h.update(uuid.as_bytes());
        }
        h.update(host.machine_id.as_bytes());
        h.update(self.info_label);
        Ok(h.finalize().into())
    }
}

fn read_factors() -> Result<HostFactors, MachineSealError> {
    HostFactors::read().map_err(|e| MachineSealError::MachineId(e.to_string()))
}

/// Fingerprint variant for [`MachineSeal`]. See [`crate::sealed_secret`]
/// for the same DmiV2/LegacyV1 migration scheme.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    DmiV2,
    LegacyV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip() {
        let s = MachineSeal::default_label();
        let pt = b"hello server";
        let sealed = s.seal(pt).expect("seal");
        let back = s.unseal(&sealed).expect("unseal");
        assert_eq!(back, pt);
    }

    #[test]
    fn different_labels_yield_different_keys() {
        let a = MachineSeal::new(b"label-a");
        let b = MachineSeal::new(b"label-b");
        let pt = b"x";
        let sealed_a = a.seal(pt).unwrap();
        assert!(b.unseal(&sealed_a).is_err());
    }

    #[test]
    fn unseal_too_short_errors() {
        let s = MachineSeal::default_label();
        assert!(matches!(
            s.unseal("aGVsbG8="),
            Err(MachineSealError::TooShort)
        ));
    }

    /// A blob sealed under the pre-rebase LegacyV1 key (machine_id only,
    /// no product_uuid) must still open via the unseal fallback.
    #[test]
    fn legacy_v1_blob_still_unseals() {
        let s = MachineSeal::default_label();
        // Hand-seal under LegacyV1 exactly as the pre-rebase code did.
        let host = read_factors().expect("host");
        let key = s.derive_key(&host, Variant::LegacyV1).expect("legacy key");
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = [3u8; 12];
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), b"legacy data".as_ref())
            .unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        let b64 = B64.encode(blob);

        let back = s.unseal(&b64).expect("legacy fallback unseal");
        assert_eq!(back, b"legacy data");
    }
}
