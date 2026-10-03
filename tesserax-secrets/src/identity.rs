//! [`DaemonIdentity`]: a service instance's own ed25519 identity.
//!
//! A service has a name and runs on a host with a fingerprint; neither
//! identifies the *instance* cryptographically. `DaemonIdentity` does: an
//! ed25519 keypair generated on first boot, sealed at rest with
//! [`SealedSecret`] (moving the file to another host fails closed), and
//! shown as a `pubkey_fingerprint` (URL-safe base64 of the first 16 bytes
//! of BLAKE3(pubkey)) that operators pin. Signed responses and signed
//! outbound commands use the same key.
//!
//! No hot rotation: rotate by [`wipe_identity`] and restart.
//!
//! Does not protect against root on the same live host (it can read the
//! key from memory while in use) or against a host that is already
//! compromised at first boot.
//!
//! On disk: the 32 secret-key bytes sealed by [`SealedSecret`], base64,
//! written atomically (temp file + rename).

use std::fs;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroize;

use crate::host::HostFactors;
use crate::sealed_secret::{SealedSecret, SealedSecretError};

const PUBKEY_FP_LEN: usize = 16;

/// Identity load / save failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum DaemonIdentityError {
    #[error("io: {0}")]
    Io(String),
    #[error("seal: {0}")]
    Seal(#[from] SealedSecretError),
    #[error("rng: {0}")]
    Rng(String),
    #[error("malformed sealed identity: expected 32 secret-key bytes, got {0}")]
    Malformed(usize),
    #[error("signature: {0}")]
    Signature(String),
    #[error("pubkey: {0}")]
    PubKey(String),
}

/// A daemon's cryptographic identity. Cheap to clone; the signing
/// key is held by `Arc<SigningKey>` internally so that signing from
/// many tasks doesn't require locking. Drop zeroizes intermediate
/// secret-byte buffers (the dalek `SigningKey` itself does not
/// zeroize on drop in v2, so we hold the raw bytes only transiently
/// during load/save).
#[derive(Clone)]
pub struct DaemonIdentity {
    inner: std::sync::Arc<DaemonIdentityInner>,
}

struct DaemonIdentityInner {
    signing: SigningKey,
    verifying: VerifyingKey,
    pubkey_fp: String,
}

impl DaemonIdentity {
    /// Load a sealed identity from `path`. If `path` doesn't exist,
    /// mint a fresh keypair, seal it, write it, then return.
    ///
    /// Idempotent on repeated boots: same path + same host fingerprint
    /// = same identity. Moving the sealed file to another host = unseal
    /// fails with `Seal(FingerprintMismatch)`.
    pub fn load_or_generate(
        path: impl AsRef<Path>,
        seal: &SealedSecret,
    ) -> Result<Self, DaemonIdentityError> {
        let path = path.as_ref();
        if path.exists() {
            Self::load(path, seal)
        } else {
            let id = Self::generate()?;
            id.save(path, seal)?;
            Ok(id)
        }
    }

    /// Mint a fresh keypair from system entropy. Caller is responsible
    /// for sealing + persisting.
    pub fn generate() -> Result<Self, DaemonIdentityError> {
        let mut sk_bytes = [0u8; 32];
        getrandom::fill(&mut sk_bytes).map_err(|e| DaemonIdentityError::Rng(e.to_string()))?;
        let signing = SigningKey::from_bytes(&sk_bytes);
        sk_bytes.zeroize();
        let verifying = signing.verifying_key();
        let pubkey_fp = compute_pubkey_fingerprint(&verifying);
        Ok(Self {
            inner: std::sync::Arc::new(DaemonIdentityInner {
                signing,
                verifying,
                pubkey_fp,
            }),
        })
    }

    /// Unseal an identity from `path`.
    pub fn load(path: &Path, seal: &SealedSecret) -> Result<Self, DaemonIdentityError> {
        let blob = fs::read_to_string(path)
            .map_err(|e| DaemonIdentityError::Io(format!("read {}: {e}", path.display())))?;
        Self::from_sealed(&seal.unseal(blob.trim())?)
    }

    /// [`load`](Self::load) against explicit host factors.
    pub fn load_with(
        path: &Path,
        seal: &SealedSecret,
        host: &HostFactors,
    ) -> Result<Self, DaemonIdentityError> {
        let blob = fs::read_to_string(path)
            .map_err(|e| DaemonIdentityError::Io(format!("read {}: {e}", path.display())))?;
        Self::from_sealed(&seal.unseal_with(host, blob.trim())?)
    }

    fn from_sealed(
        sealed_pt: &crate::sealed_secret::SealedPlaintext,
    ) -> Result<Self, DaemonIdentityError> {
        let bytes = sealed_pt.as_slice();
        if bytes.len() != 32 {
            return Err(DaemonIdentityError::Malformed(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let signing = SigningKey::from_bytes(&arr);
        arr.zeroize();
        let verifying = signing.verifying_key();
        let pubkey_fp = compute_pubkey_fingerprint(&verifying);
        Ok(Self {
            inner: std::sync::Arc::new(DaemonIdentityInner {
                signing,
                verifying,
                pubkey_fp,
            }),
        })
    }

    /// Seal + persist this identity to `path`. Writes atomically via
    /// rename-from-tempfile so a crash mid-write can't leave a partial
    /// blob.
    pub fn save(&self, path: &Path, seal: &SealedSecret) -> Result<(), DaemonIdentityError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|e| DaemonIdentityError::Io(format!("mkdir {}: {e}", parent.display())))?;
        }
        let mut sk_bytes = self.inner.signing.to_bytes();
        let blob = seal.seal(&sk_bytes)?;
        sk_bytes.zeroize();

        let tmp: PathBuf = {
            let mut p = path.to_path_buf();
            let mut name = p
                .file_name()
                .map(|s| s.to_os_string())
                .unwrap_or_else(|| std::ffi::OsString::from("daemon-identity"));
            name.push(".tmp");
            p.set_file_name(name);
            p
        };
        fs::write(&tmp, blob.as_bytes())
            .map_err(|e| DaemonIdentityError::Io(format!("write {}: {e}", tmp.display())))?;
        fs::rename(&tmp, path).map_err(|e| {
            DaemonIdentityError::Io(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                path.display()
            ))
        })?;
        Ok(())
    }

    /// The operator-visible identity string. Stable across restarts
    /// (same keypair); changes only if the identity is regenerated
    /// (wipe + relaunch).
    pub fn pubkey_fingerprint(&self) -> &str {
        &self.inner.pubkey_fp
    }

    /// 32-byte raw pubkey. Use when handing to a peer trust store.
    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.inner.verifying.to_bytes()
    }

    /// Public key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.inner.verifying
    }

    /// Signs `msg` with the identity's key (signed responses and outbound
    /// commands use the same key, so a peer verifies both against one
    /// `pubkey_fingerprint`).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.inner.signing.sign(msg)
    }

    /// Convenience: verify a signature against this daemon's own
    /// pubkey. Most consumers verify against a PEER's pubkey instead;
    /// this helper exists for round-trip tests and for daemons that
    /// occasionally need to recognise their own past output.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), DaemonIdentityError> {
        self.inner
            .verifying
            .verify(msg, sig)
            .map_err(|e| DaemonIdentityError::Signature(e.to_string()))
    }
}

impl std::fmt::Debug for DaemonIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonIdentity")
            .field("pubkey_fingerprint", &self.inner.pubkey_fp)
            .finish_non_exhaustive()
    }
}

fn compute_pubkey_fingerprint(vk: &VerifyingKey) -> String {
    let h = blake3::hash(vk.as_bytes());
    let prefix = &h.as_bytes()[..PUBKEY_FP_LEN];
    B64.encode(prefix)
}

/// Delete the sealed identity file. Use as the "rotate by redeploy"
/// step — call this, restart the daemon, first boot regenerates.
///
/// Intentionally NOT exposed via the builder. Operators run it
/// explicitly (`rm` would do the same, but this gives a typed
/// surface for tooling).
pub fn wipe_identity(path: impl AsRef<Path>) -> Result<(), DaemonIdentityError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(path)
        .map_err(|e| DaemonIdentityError::Io(format!("remove {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp_path(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("tesserax-daemon-identity-{label}-{pid}-{n}.seal"))
    }

    #[test]
    fn generate_then_pubkey_is_stable() {
        let id = DaemonIdentity::generate().expect("generate");
        let fp1 = id.pubkey_fingerprint().to_string();
        let fp2 = id.pubkey_fingerprint().to_string();
        assert_eq!(fp1, fp2);
        assert!(!fp1.is_empty());
    }

    #[test]
    fn two_generates_yield_distinct_identities() {
        let a = DaemonIdentity::generate().expect("a");
        let b = DaemonIdentity::generate().expect("b");
        assert_ne!(
            a.pubkey_fingerprint(),
            b.pubkey_fingerprint(),
            "two fresh identities must differ"
        );
        assert_ne!(a.pubkey_bytes(), b.pubkey_bytes());
    }

    #[test]
    fn sign_then_verify_self_roundtrip() {
        let id = DaemonIdentity::generate().expect("generate");
        let msg = b"hello peer";
        let sig = id.sign(msg);
        id.verify(msg, &sig).expect("self-verify");
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let id = DaemonIdentity::generate().expect("generate");
        let sig = id.sign(b"original");
        assert!(id.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn load_or_generate_then_reload_returns_same_pubkey() {
        let path = tmp_path("roundtrip");
        let seal = SealedSecret::new(b"tesserax-daemon-identity-v1-test-roundtrip");

        let id1 = DaemonIdentity::load_or_generate(&path, &seal).expect("first boot");
        let fp1 = id1.pubkey_fingerprint().to_string();

        let id2 = DaemonIdentity::load_or_generate(&path, &seal).expect("second boot");
        let fp2 = id2.pubkey_fingerprint().to_string();

        assert_eq!(fp1, fp2, "reload must yield same identity");
        assert_eq!(id1.pubkey_bytes(), id2.pubkey_bytes());

        let sig = id1.sign(b"msg");
        id2.verify(b"msg", &sig).expect("cross-instance verify");

        wipe_identity(&path).ok();
    }

    #[test]
    fn wipe_then_reload_yields_fresh_identity() {
        let path = tmp_path("wipe");
        let seal = SealedSecret::new(b"tesserax-daemon-identity-v1-test-wipe");

        let id1 = DaemonIdentity::load_or_generate(&path, &seal).expect("boot 1");
        let fp1 = id1.pubkey_fingerprint().to_string();

        wipe_identity(&path).expect("wipe");
        assert!(!path.exists());

        let id2 = DaemonIdentity::load_or_generate(&path, &seal).expect("boot 2");
        let fp2 = id2.pubkey_fingerprint().to_string();

        assert_ne!(fp1, fp2, "wipe + reboot must regenerate");

        wipe_identity(&path).ok();
    }

    #[test]
    fn pubkey_fingerprint_is_base64_url_safe() {
        let id = DaemonIdentity::generate().expect("generate");
        let fp = id.pubkey_fingerprint();
        for c in fp.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "fingerprint must be url-safe base64 (no pad), got {c:?}"
            );
        }
        let decoded = B64.decode(fp).expect("decode");
        assert_eq!(decoded.len(), PUBKEY_FP_LEN);
    }

    #[test]
    fn malformed_seal_blob_fails_cleanly() {
        let path = tmp_path("malformed");
        fs::write(&path, "not a sealed blob").expect("write garbage");

        let seal = SealedSecret::new(b"tesserax-daemon-identity-v1-test-malformed");
        let res = DaemonIdentity::load_or_generate(&path, &seal);
        assert!(res.is_err(), "must reject malformed blob");
        fs::remove_file(&path).ok();
    }

    #[test]
    fn save_is_atomic_via_tempfile_rename() {
        // Indirect check: after save() the temp sibling must NOT remain.
        let path = tmp_path("atomic");
        let seal = SealedSecret::new(b"tesserax-daemon-identity-v1-test-atomic");

        let id = DaemonIdentity::generate().expect("generate");
        id.save(&path, &seal).expect("save");

        let tmp_sibling = {
            let mut p = path.clone();
            let mut name = p.file_name().unwrap().to_os_string();
            name.push(".tmp");
            p.set_file_name(name);
            p
        };
        assert!(!tmp_sibling.exists(), "tempfile must be renamed away");
        assert!(path.exists(), "final file must exist");

        wipe_identity(&path).ok();
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let id = DaemonIdentity::generate().expect("generate");
        let debug = format!("{id:?}");
        assert!(debug.contains("DaemonIdentity"));
        assert!(debug.contains("pubkey_fingerprint"));
        // Secret key bytes never appear in Debug — only pubkey fingerprint.
        let secret_bytes = id.inner.signing.to_bytes();
        let secret_hex = secret_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(
            !debug.contains(&secret_hex),
            "Debug output must not contain raw secret-key bytes"
        );
    }
}
