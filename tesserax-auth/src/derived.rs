//! [`DerivedTokens`]: per-subject tokens derived from one server secret.
//!
//! `token = hex(HMAC-SHA256(secret, "<purpose>:<subject>"))`. The server
//! keeps one 32-byte secret and can hand out a token that is valid for one
//! purpose and one subject only (for example "may register the entry named
//! X") without storing a key per subject.

use std::io::{Read, Write};
use std::path::Path;

use zeroize::Zeroizing;

use crate::ct::{ct_eq_str, from_hex_32, hmac_sha256, to_hex};
use crate::error::AuthError;

/// Token deriver over one secret.
pub struct DerivedTokens {
    secret: Zeroizing<[u8; 32]>,
}

impl DerivedTokens {
    /// Uses `secret` directly.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            secret: Zeroizing::new(secret),
        }
    }

    /// Fresh secret from the OS random number generator.
    pub fn generate() -> Result<Self, AuthError> {
        let mut s = Zeroizing::new([0u8; 32]);
        getrandom::fill(s.as_mut()).map_err(|e| AuthError::Rng(e.to_string()))?;
        Ok(Self { secret: s })
    }

    /// Loads the secret (64 hex digits) from `path`, or creates the file
    /// with a fresh secret. On Unix a new file is created with mode 0600 and
    /// an existing file readable by group or others is refused.
    pub fn load_or_create(path: &Path) -> Result<Self, AuthError> {
        match std::fs::File::open(path) {
            Ok(mut f) => {
                check_private(&f)?;
                let mut text = Zeroizing::new(String::new());
                f.read_to_string(&mut text)?;
                let secret = from_hex_32(text.trim()).ok_or_else(|| {
                    AuthError::KeyFile(format!("{} does not hold 64 hex digits", path.display()))
                })?;
                Ok(Self::from_secret(secret))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let me = Self::generate()?;
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                let mut f = opts.open(path)?;
                let text = Zeroizing::new(to_hex(me.secret.as_ref()));
                f.write_all(text.as_bytes())?;
                f.sync_all()?;
                Ok(me)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Token for `subject` under `purpose`.
    pub fn derive(&self, purpose: &str, subject: &str) -> String {
        let msg = format!("{purpose}:{subject}");
        to_hex(&hmac_sha256(self.secret.as_ref(), msg.as_bytes()))
    }

    /// True if `presented` is the token for `subject` under `purpose`
    /// (constant-time).
    pub fn verify(&self, purpose: &str, subject: &str, presented: &str) -> bool {
        let expected = Zeroizing::new(self.derive(purpose, subject));
        ct_eq_str(&expected, presented)
    }
}

impl std::fmt::Debug for DerivedTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedTokens(..)")
    }
}

#[cfg(unix)]
fn check_private(f: &std::fs::File) -> Result<(), AuthError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = f.metadata()?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(AuthError::KeyFile(format!(
            "secret file mode {:o} is readable by others",
            mode & 0o777
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_f: &std::fs::File) -> Result<(), AuthError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_verify_is_scoped() {
        let d = DerivedTokens::from_secret([7; 32]);
        let t = d.derive("register", "alpha");
        assert_eq!(t.len(), 64);
        assert!(d.verify("register", "alpha", &t));
        assert!(!d.verify("register", "beta", &t));
        assert!(!d.verify("other", "alpha", &t));
        assert!(!DerivedTokens::from_secret([8; 32]).verify("register", "alpha", &t));
    }

    #[test]
    fn load_or_create_persists_and_is_private() {
        let dir =
            std::env::temp_dir().join(format!("tesserax-auth-derived-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        let _ = std::fs::remove_file(&path);
        let a = DerivedTokens::load_or_create(&path).unwrap();
        let b = DerivedTokens::load_or_create(&path).unwrap();
        assert!(b.verify("p", "s", &a.derive("p", "s")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                DerivedTokens::load_or_create(&path),
                Err(AuthError::KeyFile(_))
            ));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
