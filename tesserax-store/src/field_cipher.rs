//! [`FieldCipher`] — XChaCha20-Poly1305 app-level field encryption.
//!
//! ## Wire format (per value)
//!
//! ```text
//! [1B version=0x01][24B random nonce][ciphertext || 16B AEAD tag]
//! ```
//!
//! ## Per-context subkey
//!
//! A subkey is derived per `aad` (the "table.column" context) so that
//! ciphertexts from column `auth_tokens.token` cannot be transplanted into
//! `sync_items.content` even if the attacker has the master key:
//!
//! ```text
//! subkey = BLAKE3("tesserax-field-cipher-v1|" || aad || "|" || master_key)  → 32 bytes
//! ```
//!
//! The same `aad` bytes are also passed as the AEAD `Payload.aad`, giving a
//! second domain-binding layer through the authentication tag.
//!
//! The domain label `tesserax-field-cipher-v1|` and the version byte `0x01`
//! are part of the on-disk format (golden test in `tests/golden.rs`).
//!
//! ## Feature gate
//!
//! This module is only compiled under `cipher-applite`.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use tesserax_secrets::keysource::{KeySource, KeySourceError};
use zeroize::{Zeroize, Zeroizing};

const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 24; // XChaCha20 uses a 192-bit nonce
const TAG_LEN: usize = 16;
const OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN; // version + nonce + tag

// ── Error ─────────────────────────────────────────────────────────────────────

/// Field cipher failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CipherError {
    /// The blob is shorter than version + nonce + tag.
    #[error("blob too short (need at least {OVERHEAD} bytes, got {0})")]
    TooShort(usize),
    /// Unknown format version.
    #[error("unsupported version byte 0x{0:02x} (expected 0x01)")]
    BadVersion(u8),
    /// Authentication failed (wrong key, wrong context, or tampered blob).
    #[error("AEAD authentication failed")]
    Aead,
    /// The OS random source failed.
    #[error("random source unavailable")]
    Random,
    /// The key source failed.
    #[error("key source: {0}")]
    KeySource(#[from] KeySourceError),
    /// Decrypted bytes are not UTF-8.
    #[error("UTF-8 decode failed: {0}")]
    Utf8(String),
}

// ── FieldCipher ───────────────────────────────────────────────────────────────

/// App-level field cipher using XChaCha20-Poly1305 with 24-byte random nonces.
///
/// The master key is held in memory and zeroized on drop. The struct itself
/// derives no `Debug` / `Display` impl to avoid accidental key leakage.
pub struct FieldCipher {
    master: Zeroizing<[u8; 32]>,
}

impl Drop for FieldCipher {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}

impl FieldCipher {
    /// Construct from a [`KeySource`] (production path).
    pub fn from_source(src: &dyn KeySource) -> Result<Self, CipherError> {
        let master = src.master_key()?;
        Ok(Self { master })
    }

    /// Construct directly from key bytes (tests / benchmarks).
    pub fn from_key_bytes(key: [u8; 32]) -> Self {
        Self {
            master: Zeroizing::new(key),
        }
    }

    // ── Subkey derivation ────────────────────────────────────────────────────

    /// Derive a per-context 32-byte subkey.
    ///
    /// `subkey = BLAKE3("tesserax-field-cipher-v1|" || aad || "|" || master)`
    ///
    /// The domain prefix + aad binding ensures ciphertexts from one column
    /// cannot be transplanted to another.
    fn subkey(&self, aad: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut h = blake3::Hasher::new();
        h.update(b"tesserax-field-cipher-v1|");
        h.update(aad);
        h.update(b"|");
        h.update(self.master.as_ref());
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    // ── Core encrypt / decrypt ───────────────────────────────────────────────

    /// Encrypt `plaintext` with `aad` as the context binding.
    ///
    /// `aad` is typically `b"table.column"`. It is domain-bound into the
    /// subkey AND passed as AEAD `Payload.aad`.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        let subkey = self.subkey(aad);
        let cipher =
            XChaCha20Poly1305::new_from_slice(subkey.as_ref()).expect("subkey is always 32 bytes");

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|_| CipherError::Random)?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CipherError::Aead)?;

        // Wire: [version 1B][nonce 24B][ct || tag]
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a blob produced by [`Self::encrypt`].
    pub fn decrypt(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        if blob.len() < OVERHEAD {
            return Err(CipherError::TooShort(blob.len()));
        }
        let version = blob[0];
        if version != VERSION {
            return Err(CipherError::BadVersion(version));
        }
        let nonce = XNonce::from_slice(&blob[1..1 + NONCE_LEN]);
        let ct = &blob[1 + NONCE_LEN..];

        let subkey = self.subkey(aad);
        let cipher =
            XChaCha20Poly1305::new_from_slice(subkey.as_ref()).expect("subkey is always 32 bytes");

        cipher
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|_| CipherError::Aead)
    }

    // ── String helpers ───────────────────────────────────────────────────────

    /// Encrypt a `&str`.
    pub fn encrypt_str(&self, s: &str, aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.encrypt(s.as_bytes(), aad)
    }

    /// Decrypt and decode as UTF-8.
    pub fn decrypt_str(&self, blob: &[u8], aad: &[u8]) -> Result<String, CipherError> {
        let pt = self.decrypt(blob, aad)?;
        String::from_utf8(pt).map_err(|e| CipherError::Utf8(e.to_string()))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn cipher() -> FieldCipher {
        FieldCipher::from_key_bytes([0x42u8; 32])
    }

    // ── Basic roundtrip ──

    #[test]
    fn roundtrip_bytes() {
        let c = cipher();
        let pt = b"hello, world!";
        let blob = c.encrypt(pt, b"test.col").unwrap();
        let back = c.decrypt(&blob, b"test.col").unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn roundtrip_str() {
        let c = cipher();
        let s = "héllo, wörld ✓ multi-byte";
        let blob = c.encrypt_str(s, b"users.name").unwrap();
        let back = c.decrypt_str(&blob, b"users.name").unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let c = cipher();
        let blob = c.encrypt(b"", b"t.c").unwrap();
        let back = c.decrypt(&blob, b"t.c").unwrap();
        assert!(back.is_empty());
    }

    // ── AAD mismatch ──

    #[test]
    fn wrong_aad_fails_aead() {
        let c = cipher();
        let blob = c.encrypt(b"secret", b"a.b").unwrap();
        let err = c.decrypt(&blob, b"a.c").unwrap_err();
        assert!(matches!(err, CipherError::Aead));
    }

    // ── Tamper detection ──

    #[test]
    fn tampered_ciphertext_fails() {
        let c = cipher();
        let mut blob = c.encrypt(b"original data", b"t.col").unwrap();
        // Flip a byte in the ciphertext portion (after version + nonce).
        let len = blob.len();
        blob[len - 4] ^= 0xFF;
        let err = c.decrypt(&blob, b"t.col").unwrap_err();
        assert!(matches!(err, CipherError::Aead));
    }

    // ── Structural checks ──

    #[test]
    fn bad_version_byte_rejected() {
        let c = cipher();
        let mut blob = c.encrypt(b"x", b"t.c").unwrap();
        blob[0] = 0x99; // overwrite version byte
        let err = c.decrypt(&blob, b"t.c").unwrap_err();
        assert!(matches!(err, CipherError::BadVersion(0x99)));
    }

    #[test]
    fn too_short_blob_rejected() {
        let c = cipher();
        let short = vec![0u8; OVERHEAD - 1];
        let err = c.decrypt(&short, b"t.c").unwrap_err();
        assert!(matches!(err, CipherError::TooShort(_)));
    }

    #[test]
    fn exact_overhead_size_with_empty_payload() {
        let c = cipher();
        let blob = c.encrypt(b"", b"t.c").unwrap();
        // version(1) + nonce(24) + tag(16) = 41 for empty plaintext
        assert_eq!(blob.len(), OVERHEAD);
    }

    // ── Random nonces ──

    #[test]
    fn two_encrypts_same_plaintext_produce_different_blobs() {
        let c = cipher();
        let b1 = c.encrypt(b"same", b"t.c").unwrap();
        let b2 = c.encrypt(b"same", b"t.c").unwrap();
        assert_ne!(b1, b2, "nonces must differ");
    }

    // ── Stress: 100_000 encrypt/decrypt + nonce uniqueness ──

    #[test]
    fn stress_roundtrip_and_unique_nonces() {
        let c = cipher();
        let n = 100_000usize;
        let mut nonces: HashSet<[u8; NONCE_LEN]> = HashSet::with_capacity(n);

        let start = std::time::Instant::now();
        for i in 0..n {
            let pt = format!("plaintext-{i}");
            let blob = c.encrypt_str(&pt, b"stress.col").unwrap();
            assert_eq!(blob.len(), OVERHEAD + pt.len());

            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&blob[1..1 + NONCE_LEN]);
            nonces.insert(nonce);

            let back = c.decrypt_str(&blob, b"stress.col").unwrap();
            assert_eq!(back, pt);
        }
        assert_eq!(nonces.len(), n, "all nonces must be distinct");

        // Loose wall-time bound: 100k encrypt+decrypt should complete in < 30s
        // on any reasonable dev box.
        let elapsed = start.elapsed();
        assert!(elapsed.as_secs() < 30, "stress took too long: {elapsed:?}");
    }
}
