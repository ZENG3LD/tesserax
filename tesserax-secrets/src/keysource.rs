//! [`KeySource`]: where a 32-byte master key (database or field encryption)
//! comes from at run time.
//!
//! Two implementations are provided:
//!
//! - [`DmiKeySource`] — derives a 32-byte master key from the host's DMI
//!   `product_uuid` and `machine_id` via `HKDF-SHA256`. The key is
//!   recomputed on every call; nothing is written to disk.
//! - [`RemoteKeySource`] — delegates to a caller-supplied closure that
//!   delivers the key over any transport the consumer chooses.
//!
//! Both are orthogonal to the coverage axis (`cipher-native` vs
//! `cipher-applite`). The same trait is used whether the key ends up in a
//! `PRAGMA key` statement (SQLCipher) or as a `FieldCipher` master key.

use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::Arc;
use zeroize::Zeroizing;

// ── Error ────────────────────────────────────────────────────────────────────

/// Key delivery failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum KeySourceError {
    #[error("DMI read failed: {0}")]
    Dmi(String),
    #[error("remote key fetch failed: {0}")]
    Remote(String),
    #[error("HKDF expansion failed")]
    Hkdf,
}

// ── Trait ────────────────────────────────────────────────────────────────────

/// Produces a 32-byte master key on demand. Called once at DB open; the
/// result is held in RAM for the process lifetime and zeroized on drop.
pub trait KeySource: Send + Sync {
    /// The key.
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, KeySourceError>;
}

// ── DmiKeySource ─────────────────────────────────────────────────────────────

/// HKDF-SHA256 key derived from host DMI.
///
/// `IKM = product_uuid || 0x00 || machine_id`
/// `salt = self.salt`
/// `info = self.info.as_bytes()`
///
/// Reads `product_uuid` via the platform-native mechanism and `machine_id`
/// from the same path. Never writes to disk; derives on every call.
pub struct DmiKeySource {
    /// HKDF salt — e.g. operator public key or a local install secret.
    pub salt: Vec<u8>,
    /// HKDF info label, e.g. `"example-db.v1"`.
    pub info: String,
}

impl DmiKeySource {
    /// Derive a key from explicit `product_uuid` and `machine_id` strings.
    ///
    /// Factored out so unit tests can verify the HKDF math without requiring
    /// real DMI access.
    pub fn derive_from(
        product_uuid: &[u8],
        machine_id: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KeySourceError> {
        let mut ikm = Vec::with_capacity(product_uuid.len() + 1 + machine_id.len());
        ikm.extend_from_slice(product_uuid);
        ikm.push(0u8); // separator (mirrors seal.rs)
        ikm.extend_from_slice(machine_id);

        let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(info, out.as_mut())
            .map_err(|_| KeySourceError::Hkdf)?;
        Ok(out)
    }
}

impl KeySource for DmiKeySource {
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, KeySourceError> {
        // Canonical host-identity readers: see `crate::platform`.
        // product_uuid is the reboot-stable DMI identifier; machine_id is
        // the historical per-install factor folded in alongside it.
        let product_uuid =
            crate::platform::product_uuid().map_err(|e| KeySourceError::Dmi(e.to_string()))?;
        let machine_id =
            crate::platform::machine_id().map_err(|e| KeySourceError::Dmi(e.to_string()))?;
        Self::derive_from(
            product_uuid.as_bytes(),
            machine_id.as_bytes(),
            &self.salt,
            self.info.as_bytes(),
        )
    }
}

// ── RemoteKeySource ──────────────────────────────────────────────────────────

/// Key delivered by the caller's closure — no transport baked in.
///
/// The closure may read a KMS, a secrets manager, or an operator-signed
/// channel.
pub struct RemoteKeySource {
    /// The closure.
    pub fetch: Arc<dyn Fn() -> Result<Zeroizing<[u8; 32]>, KeySourceError> + Send + Sync>,
}

impl RemoteKeySource {
    /// Wraps a closure.
    pub fn new(
        f: impl Fn() -> Result<Zeroizing<[u8; 32]>, KeySourceError> + Send + Sync + 'static,
    ) -> Self {
        Self { fetch: Arc::new(f) }
    }
}

impl KeySource for RemoteKeySource {
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, KeySourceError> {
        (self.fetch)()
    }
}

// ── StaticKeySource ──────────────────────────────────────────────────────────

/// Fixed key (tests, or a key already delivered by other means).
pub struct StaticKeySource(pub [u8; 32]);

impl KeySource for StaticKeySource {
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, KeySourceError> {
        Ok(Zeroizing::new(self.0))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── StaticKeySource ──

    #[test]
    fn static_key_source_returns_verbatim() {
        let key = [42u8; 32];
        let src = StaticKeySource(key);
        let got = src.master_key().expect("static key source");
        assert_eq!(*got, key);
    }

    // ── RemoteKeySource ──

    #[test]
    fn remote_key_source_calls_closure() {
        let expected = [0xABu8; 32];
        let src = RemoteKeySource::new(move || Ok(Zeroizing::new(expected)));
        let got = src.master_key().expect("remote");
        assert_eq!(*got, expected);
    }

    #[test]
    fn remote_key_source_propagates_error() {
        let src = RemoteKeySource::new(|| Err(KeySourceError::Remote("test error".into())));
        let err = src.master_key().expect_err("should fail");
        assert!(matches!(err, KeySourceError::Remote(_)));
    }

    // ── DmiKeySource::derive_from (unit-testable HKDF math) ──

    #[test]
    fn derive_from_is_deterministic() {
        let a = DmiKeySource::derive_from(b"uuid-xyz", b"machine-abc", b"salt-op", b"info-v1")
            .expect("a");
        let b = DmiKeySource::derive_from(b"uuid-xyz", b"machine-abc", b"salt-op", b"info-v1")
            .expect("b");
        assert_eq!(*a, *b);
    }

    #[test]
    fn derive_from_different_salt_gives_different_key() {
        let a = DmiKeySource::derive_from(b"uuid", b"machine", b"salt1", b"info").expect("a");
        let b = DmiKeySource::derive_from(b"uuid", b"machine", b"salt2", b"info").expect("b");
        assert_ne!(*a, *b);
    }

    #[test]
    fn derive_from_different_info_gives_different_key() {
        let a = DmiKeySource::derive_from(b"uuid", b"machine", b"salt", b"info-v1").expect("a");
        let b = DmiKeySource::derive_from(b"uuid", b"machine", b"salt", b"info-v2").expect("b");
        assert_ne!(*a, *b);
    }

    #[test]
    fn derive_from_different_uuid_gives_different_key() {
        let a = DmiKeySource::derive_from(b"uuid-A", b"machine", b"salt", b"info").expect("a");
        let b = DmiKeySource::derive_from(b"uuid-B", b"machine", b"salt", b"info").expect("b");
        assert_ne!(*a, *b);
    }

    // ── DmiKeySource real-device determinism ──

    #[test]
    fn dmi_key_source_determinism_on_this_host() {
        let src = DmiKeySource {
            salt: b"test-salt".to_vec(),
            info: "test-info-v1".into(),
        };
        match (src.master_key(), src.master_key()) {
            (Ok(k1), Ok(k2)) => {
                assert_eq!(*k1, *k2, "two calls must return identical key on same host");
            }
            (Err(KeySourceError::Dmi(_)), _) | (_, Err(KeySourceError::Dmi(_))) => {
                // DMI unavailable on this platform/CI — test still ran cleanly
            }
            (Err(e), _) | (_, Err(e)) => panic!("unexpected error: {e}"),
        }
    }
}
