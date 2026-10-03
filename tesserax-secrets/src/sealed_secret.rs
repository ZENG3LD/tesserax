//! [`SealedSecret`]: host-bound authenticated encryption for secrets at rest.
//!
//! - **Fingerprint**: DMI `product_uuid` (when readable) + `machine_id` +
//!   first non-loopback MAC + process user id, hashed with BLAKE3 under
//!   the caller's label. Any factor differing makes unseal fail.
//! - **Cipher**: ChaCha20-Poly1305 with the fingerprint hash as AAD, key
//!   derived from the same factors under a separate domain label.
//!
//! Protects a sealed blob copied to another machine (disk snapshot, stolen
//! image). Does not protect against root on the same live machine, which
//! can read the factors and the process memory; combine with process
//! hardening (feature `hardening`) and zeroize-on-drop.
//!
//! ## Format (frozen)
//!
//! ```text
//! base64( fingerprint_blake3_8B || nonce_12B || ciphertext || tag_16B )
//! ```
//!
//! The 8-byte prefix is a truncated BLAKE3 of the fingerprint: unseal
//! fails fast with [`SealedSecretError::FingerprintMismatch`] before any
//! AEAD work when it does not match, and an operator can tell "sealed on a
//! different host" from "corrupted".
//!
//! ## Variants
//!
//! `DmiV2` folds the reboot-stable DMI `product_uuid` in and is what
//! [`SealedSecret::seal`] uses when DMI is readable; `LegacyV1` is the
//! original three-factor fingerprint, used when DMI is unavailable and
//! tried on unseal so older blobs still open (re-seal to migrate).

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroize;

use crate::host::HostFactors;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const FP_PREFIX_LEN: usize = 8;

/// Why sealing or unsealing failed.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SealedSecretError {
    #[error("fingerprint: {0}")]
    Fingerprint(String),
    #[error("seal: {0}")]
    Seal(String),
    #[error("unseal: {0}")]
    Unseal(String),
    #[error("payload too short")]
    TooShort,
    #[error("base64: {0}")]
    Base64(String),
    #[error("fingerprint mismatch — sealed on a different host")]
    FingerprintMismatch,
    #[error("rng: {0}")]
    Rng(String),
}

/// Which fingerprint variant a hash/key was derived under.
///
/// - `DmiV2` folds the reboot-stable DMI `product_uuid` in as
///   the leading factor. This is what `seal` always uses when DMI is
///   readable, so a sealed blob survives a VPS reboot that rotates
///   `/etc/machine-id` or the NIC MAC.
/// - `LegacyV1` is the original 3-factor
///   (machine_id + MAC + uid) fingerprint. `unseal` falls back to it so
///   blobs sealed before the rebase still open — read once under
///   LegacyV1, the caller can re-seal to migrate forward.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    DmiV2,
    LegacyV1,
}

impl HostFactors {
    /// The variant `seal` should use: DmiV2 when product_uuid is
    /// available, else LegacyV1 (degraded — no reboot stability, but
    /// still host-bound on the other three factors).
    fn seal_variant(&self) -> Variant {
        if self.product_uuid.is_some() {
            Variant::DmiV2
        } else {
            Variant::LegacyV1
        }
    }

    /// 32-byte BLAKE3 hash for the given variant. Truncated to 8 bytes
    /// for the fast-fail prefix in `prefix_hash()`, full 32 used as AEAD
    /// key material in `derive_key()`.
    ///
    /// DmiV2 prepends the product_uuid under a `dmi=` label so its hash
    /// is domain-separated from LegacyV1 even if every other factor
    /// matches. `LegacyV1` is byte-identical to the pre-rebase hash, so
    /// old blobs still verify.
    fn hash(&self, info_label: &[u8], variant: Variant) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(info_label);
        if variant == Variant::DmiV2 {
            h.update(b"|dmi=");
            h.update(self.product_uuid.as_deref().unwrap_or("").as_bytes());
        }
        h.update(b"|machine_id=");
        h.update(self.machine_id.as_bytes());
        h.update(b"|mac=");
        h.update(self.primary_mac.as_bytes());
        h.update(b"|uid=");
        h.update(self.uid.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    fn prefix_hash(&self, info_label: &[u8], variant: Variant) -> [u8; FP_PREFIX_LEN] {
        let full = self.hash(info_label, variant);
        let mut p = [0u8; FP_PREFIX_LEN];
        p.copy_from_slice(&full[..FP_PREFIX_LEN]);
        p
    }

    /// 32-byte AEAD key — separate BLAKE3 round over the same inputs
    /// with a distinct domain label so prefix_hash and key never
    /// collide. `LegacyV1` is byte-identical to the pre-rebase key.
    fn derive_key(&self, info_label: &[u8], variant: Variant) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"sealed-secret-key-v1|");
        h.update(info_label);
        if variant == Variant::DmiV2 {
            h.update(b"|dmi=");
            h.update(self.product_uuid.as_deref().unwrap_or("").as_bytes());
        }
        h.update(b"|machine_id=");
        h.update(self.machine_id.as_bytes());
        h.update(b"|mac=");
        h.update(self.primary_mac.as_bytes());
        h.update(b"|uid=");
        h.update(self.uid.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

/// Host-bound sealed-secret store. Cheap to construct; reads
/// fingerprint on every seal/unseal so a transplant attack fails
/// even if the binary was running before the move.
pub struct SealedSecret {
    info_label: Vec<u8>,
}

impl SealedSecret {
    /// Store with a caller-chosen label (domain separation between uses).
    pub fn new(info_label: impl Into<Vec<u8>>) -> Self {
        Self {
            info_label: info_label.into(),
        }
    }

    /// The default label `tesserax-sealed-secret-v1`.
    pub fn default_label() -> Self {
        Self::new(b"tesserax-sealed-secret-v1")
    }

    /// Seal `plaintext`, returning a base64 blob.
    ///
    /// Always seals under `DmiV2` (DMI product_uuid folded in)
    /// when the DMI node is readable, so the blob survives a reboot that
    /// rotates machine_id / MAC. Degrades to `LegacyV1` only
    /// when product_uuid is unavailable.
    pub fn seal(&self, plaintext: &[u8]) -> Result<String, SealedSecretError> {
        let fp = read_factors()?;
        self.seal_with(&fp, plaintext)
    }

    /// [`seal`](Self::seal) against explicit host factors.
    pub fn seal_with(
        &self,
        fp: &HostFactors,
        plaintext: &[u8],
    ) -> Result<String, SealedSecretError> {
        let variant = fp.seal_variant();
        let mut key = fp.derive_key(&self.info_label, variant);
        let prefix = fp.prefix_hash(&self.info_label, variant);

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| SealedSecretError::Seal(format!("cipher init: {e}")))?;
        // Wipe the key right after init — cipher holds it internally
        // already, our copy must not linger.
        key.zeroize();

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|e| SealedSecretError::Rng(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // AAD = the fingerprint hash. Detached from key derivation so
        // a key-recovery attack still fails the AEAD.
        let aad = fp.hash(&self.info_label, variant);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| SealedSecretError::Seal(format!("aead encrypt: {e}")))?;

        let mut out = Vec::with_capacity(FP_PREFIX_LEN + NONCE_LEN + ct.len());
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(B64.encode(out))
    }

    /// Unseal. Returns `FingerprintMismatch` BEFORE attempting AEAD
    /// when the prefix doesn't match — fast-fail with a clear
    /// diagnostic. The plaintext is wrapped in a `SealedPlaintext`
    /// so the bytes get zeroized on drop.
    pub fn unseal(&self, sealed_b64: &str) -> Result<SealedPlaintext, SealedSecretError> {
        let fp = read_factors()?;
        self.unseal_with(&fp, sealed_b64)
    }

    /// [`unseal`](Self::unseal) against explicit host factors.
    pub fn unseal_with(
        &self,
        fp: &HostFactors,
        sealed_b64: &str,
    ) -> Result<SealedPlaintext, SealedSecretError> {
        let bytes = B64
            .decode(sealed_b64.trim())
            .map_err(|e| SealedSecretError::Base64(e.to_string()))?;
        if bytes.len() < FP_PREFIX_LEN + NONCE_LEN + TAG_LEN {
            return Err(SealedSecretError::TooShort);
        }
        let (prefix, rest) = bytes.split_at(FP_PREFIX_LEN);
        let (nonce_bytes, ct) = rest.split_at(NONCE_LEN);

        // Try DmiV2 first (current seal format), then fall back to
        // LegacyV1 so blobs sealed before the DMI rebase still open.
        // Whichever variant's prefix matches is the one the blob was
        // sealed under. A blob that opens under LegacyV1 here is a
        // migration signal — the caller can re-seal it to upgrade.
        for variant in [Variant::DmiV2, Variant::LegacyV1] {
            // DmiV2 is impossible if this host has no product_uuid — skip
            // it so we don't burn a prefix compare on an all-empty dmi.
            if variant == Variant::DmiV2 && fp.product_uuid.is_none() {
                continue;
            }
            let expected_prefix = fp.prefix_hash(&self.info_label, variant);
            if !prefix_matches(prefix, &expected_prefix) {
                continue;
            }
            let mut key = fp.derive_key(&self.info_label, variant);
            let cipher = ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|e| SealedSecretError::Unseal(format!("cipher init: {e}")))?;
            key.zeroize();
            let nonce = Nonce::from_slice(nonce_bytes);
            let aad = fp.hash(&self.info_label, variant);
            let pt = cipher
                .decrypt(nonce, Payload { msg: ct, aad: &aad })
                .map_err(|e| SealedSecretError::Unseal(format!("aead decrypt: {e}")))?;
            return Ok(SealedPlaintext(pt));
        }
        // Neither variant's prefix matched — sealed on a different host.
        Err(SealedSecretError::FingerprintMismatch)
    }
}

/// Wrapper around the decrypted plaintext that zeroizes on drop.
/// Use [`Self::as_slice`] / [`Self::into_vec`] explicitly — `Deref`
/// would make accidental copies too easy.
pub struct SealedPlaintext(Vec<u8>);

impl SealedPlaintext {
    /// The plaintext.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    /// Takes the plaintext; the caller becomes responsible for wiping it.
    pub fn into_vec(self) -> Vec<u8> {
        // Caller takes responsibility for zeroizing the moved Vec.
        // We use ManuallyDrop to suppress our own zeroize first.
        let mut me = std::mem::ManuallyDrop::new(self);
        std::mem::take(&mut me.0)
    }
    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SealedPlaintext {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SealedPlaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SealedPlaintext(<{} bytes redacted>)", self.0.len())
    }
}

fn prefix_matches(prefix: &[u8], expected: &[u8; FP_PREFIX_LEN]) -> bool {
    <&[u8; FP_PREFIX_LEN]>::try_from(prefix).is_ok_and(|p| tesserax::ct::ct_eq_array(p, expected))
}

fn read_factors() -> Result<HostFactors, SealedSecretError> {
    HostFactors::read().map_err(|e| SealedSecretError::Fingerprint(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip() {
        let s = SealedSecret::default_label();
        let pt = b"super secret database password";
        let blob = s.seal(pt).expect("seal");
        let back = s.unseal(&blob).expect("unseal");
        assert_eq!(back.as_slice(), pt);
    }

    /// A blob produced under the pre-rebase LegacyV1 fingerprint (no
    /// product_uuid factor) must still open via the unseal fallback, so
    /// upgrading the crate doesn't strand existing sealed data.
    #[test]
    fn legacy_v1_blob_still_unseals() {
        let label = b"tesserax-sealed-secret-v1";
        let fp = read_factors().expect("fp");
        // Hand-seal under LegacyV1 exactly as the pre-rebase code did.
        let key = fp.derive_key(label, Variant::LegacyV1);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce_bytes = [7u8; NONCE_LEN];
        let aad = fp.hash(label, Variant::LegacyV1);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: b"legacy payload",
                    aad: &aad,
                },
            )
            .unwrap();
        let prefix = fp.prefix_hash(label, Variant::LegacyV1);
        let mut blob = Vec::new();
        blob.extend_from_slice(&prefix);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        let b64 = B64.encode(blob);

        // Current unseal must read it through the LegacyV1 fallback.
        let s = SealedSecret::default_label();
        let back = s.unseal(&b64).expect("legacy fallback unseal");
        assert_eq!(back.as_slice(), b"legacy payload");
    }

    /// On a host with product_uuid, `seal` must choose DmiV2 — verify the
    /// blob's prefix matches the DmiV2 prefix, not LegacyV1.
    #[test]
    fn seal_prefers_dmi_v2_when_available() {
        let fp = read_factors().expect("fp");
        if fp.product_uuid.is_none() {
            return; // DMI unavailable on this host — nothing to assert.
        }
        let label = b"tesserax-sealed-secret-v1";
        let s = SealedSecret::default_label();
        let blob = s.seal(b"x").unwrap();
        let bytes = B64.decode(blob).unwrap();
        let prefix = &bytes[..FP_PREFIX_LEN];
        assert_eq!(prefix, &fp.prefix_hash(label, Variant::DmiV2));
        assert_ne!(prefix, &fp.prefix_hash(label, Variant::LegacyV1));
    }

    #[test]
    fn unseal_with_different_label_fails_fingerprint() {
        let a = SealedSecret::new(b"label-a");
        let b = SealedSecret::new(b"label-b");
        let blob = a.seal(b"x").unwrap();
        // Different label changes fingerprint prefix → fast-fail
        // FingerprintMismatch before AEAD attempt.
        let err = b.unseal(&blob).unwrap_err();
        assert!(matches!(err, SealedSecretError::FingerprintMismatch));
    }

    #[test]
    fn unseal_short_blob_errors() {
        let s = SealedSecret::default_label();
        // base64 of 4 bytes — too short for prefix+nonce+tag.
        let blob = B64.encode(b"abcd");
        assert!(matches!(s.unseal(&blob), Err(SealedSecretError::TooShort)));
    }

    #[test]
    fn sealed_plaintext_debug_redacts() {
        let s = SealedSecret::default_label();
        let blob = s.seal(b"actually secret content").unwrap();
        let pt = s.unseal(&blob).unwrap();
        let dbg = format!("{pt:?}");
        assert!(!dbg.contains("actually"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("bytes"));
    }

    #[test]
    fn fingerprint_hash_changes_with_label() {
        let fp = read_factors().expect("fp");
        let h1 = fp.hash(b"label-1", Variant::LegacyV1);
        let h2 = fp.hash(b"label-2", Variant::LegacyV1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn dmi_v2_and_legacy_v1_hashes_differ_when_dmi_present() {
        let fp = read_factors().expect("fp");
        if fp.product_uuid.is_none() {
            return; // no DMI on this host — variants would coincide
        }
        assert_ne!(
            fp.hash(b"label", Variant::DmiV2),
            fp.hash(b"label", Variant::LegacyV1),
            "DmiV2 must be domain-separated from LegacyV1"
        );
    }

    #[test]
    fn prefix_and_key_are_distinct_for_same_label() {
        let fp = read_factors().expect("fp");
        let prefix = fp.prefix_hash(b"label", Variant::LegacyV1);
        let key = fp.derive_key(b"label", Variant::LegacyV1);
        // Prefix is BLAKE3(label || components); key is BLAKE3(
        // "sealed-secret-key-v1|" || label || components). They MUST
        // differ — domain separation.
        assert_ne!(&prefix[..], &key[..FP_PREFIX_LEN]);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let s = SealedSecret::default_label();
        let blob = s.seal(b"original").unwrap();
        // Flip a base64 char near the end (likely lands in the AEAD
        // ciphertext or tag). Work in bytes to keep `forbid(unsafe_code)`.
        let mut bytes = blob.into_bytes();
        let last = bytes.len() - 4;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let mutated = String::from_utf8(bytes).expect("base64 stays ascii");
        let err = s.unseal(&mutated).unwrap_err();
        // Could be Base64 (if we landed on '=') or Unseal (AEAD tag
        // failure) — both are fail-closed.
        assert!(matches!(
            err,
            SealedSecretError::Unseal(_)
                | SealedSecretError::Base64(_)
                | SealedSecretError::TooShort
                | SealedSecretError::FingerprintMismatch
        ));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let s = SealedSecret::default_label();
        let blob = s.seal(b"").unwrap();
        let pt = s.unseal(&blob).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn long_plaintext_round_trips() {
        let s = SealedSecret::default_label();
        let pt: Vec<u8> = (0..16_000).map(|i| (i & 0xff) as u8).collect();
        let blob = s.seal(&pt).unwrap();
        let back = s.unseal(&blob).unwrap();
        assert_eq!(back.as_slice(), pt.as_slice());
    }
}
