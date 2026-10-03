//! Errors of this crate.

use thiserror::Error;

/// Failure loading keys, generating keys or handling a secret file.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Filesystem error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Malformed key material or configuration.
    #[error("malformed: {0}")]
    Malformed(String),
    /// The OS random number generator failed.
    #[error("os rng: {0}")]
    Rng(String),
    /// A secret file exists but is unusable.
    #[error("key file: {0}")]
    KeyFile(String),
}
