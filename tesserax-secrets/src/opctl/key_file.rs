//! Plain ed25519 secret-key file management.
//!
//! Format: raw 32 bytes on disk. NOT armoured (no PEM/JSON/base64) —
//! the file IS the key. `chmod 0600` is the only access control.
//!
//! ## Why not sealed?
//!
//! On the dev box the operator's secret is the trust root — there is
//! nothing higher to seal it against. `SealedSecret`'s host-binding
//! would mean the key dies on every laptop reinstall, which is the
//! opposite of what an operator wants. Daemon-side identity (which
//! IS sealed to its host) plus operator pubkey pinning gives the
//! defence-in-depth — operator's box compromise is a known catastrophic
//! mode for ALL ed25519 admin schemes.
//!
//! ## Path convention
//!
//! Callers typically pick `~/.config/<service>/operator.key`. This module doesn't enforce a
//! location — just reads/writes whatever path you hand it.

use std::fs;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::SigningKey;

/// Key-file failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum KeyFileError {
    #[error("io {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("rng: {0}")]
    Rng(String),
    #[error("expected 32 bytes, got {0}")]
    BadLength(usize),
}

/// Generate a fresh ed25519 keypair from system entropy. Returns the
/// signing half; pubkey is derived via `key.verifying_key()`.
pub fn generate() -> Result<SigningKey, KeyFileError> {
    let mut buf = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(buf.as_mut()).map_err(|e| KeyFileError::Rng(e.to_string()))?;
    let sk = SigningKey::from_bytes(&buf);
    Ok(sk)
}

/// Write the secret bytes to `path` with mode 0600 on Unix. The file
/// is replaced atomically (write-temp + rename).
pub fn save_secret(path: impl AsRef<Path>, key: &SigningKey) -> Result<(), KeyFileError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| KeyFileError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    let tmp = path.with_extension("key.tmp");
    // Remove any leftover temp file from a crashed run before create_new.
    let _ = fs::remove_file(&tmp);
    {
        let mut f = fs::OpenOptions::new();
        f.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            f.mode(0o600);
        }
        let mut file = f.open(&tmp).map_err(|e| KeyFileError::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
        file.write_all(zeroize::Zeroizing::new(key.to_bytes()).as_ref())
            .map_err(|e| KeyFileError::Io {
                path: tmp.display().to_string(),
                source: e,
            })?;
        file.sync_all().map_err(|e| KeyFileError::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| KeyFileError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

/// Load the secret from `path` (raw 32 bytes).
pub fn load_secret(path: impl AsRef<Path>) -> Result<SigningKey, KeyFileError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|e| KeyFileError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    if bytes.len() != 32 {
        return Err(KeyFileError::BadLength(bytes.len()));
    }
    let mut arr = zeroize::Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&bytes);
    let mut bytes = bytes;
    zeroize::Zeroize::zeroize(&mut bytes);
    Ok(SigningKey::from_bytes(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn tmp_path(label: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tesserax-opctl-{label}-{}-{}.key",
            std::process::id(),
            n
        ))
    }

    #[test]
    fn generate_then_save_load_roundtrip() {
        let path = tmp_path("roundtrip");
        let sk = generate().expect("gen");
        save_secret(&path, &sk).expect("save");
        let sk2 = load_secret(&path).expect("load");
        assert_eq!(sk.to_bytes(), sk2.to_bytes());

        // verify sig works after roundtrip
        let msg = b"hello";
        let sig = sk2.sign(msg);
        sk.verifying_key().verify_strict(msg, &sig).expect("verify");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_bad_length() {
        let path = tmp_path("badlen");
        std::fs::write(&path, b"too short").unwrap();
        let err = load_secret(&path).unwrap_err();
        assert!(matches!(err, KeyFileError::BadLength(_)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn two_generates_distinct() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }
}
