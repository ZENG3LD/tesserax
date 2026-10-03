//! [`SecretsError`]: any error of this crate, for callers that want one type.

use thiserror::Error;

/// Union of the per-module errors.
#[derive(Debug, Error)]
pub enum SecretsError {
    /// Machine seal.
    #[error(transparent)]
    MachineSeal(#[from] crate::machine_seal::MachineSealError),
    /// Sealed secret.
    #[error(transparent)]
    Seal(#[from] crate::sealed_secret::SealedSecretError),
    /// Daemon identity.
    #[error(transparent)]
    Identity(#[from] crate::identity::DaemonIdentityError),
    /// Shamir.
    #[error(transparent)]
    Shamir(#[from] crate::shamir::ShamirError),
    /// Host identifiers.
    #[error(transparent)]
    Platform(#[from] crate::platform::PlatformIdError),
    /// Tripwire.
    #[error(transparent)]
    Tripwire(#[from] crate::tripwire::TripwireError),
    /// Operator command.
    #[error(transparent)]
    OperatorCommand(#[from] crate::opcmd::OperatorCommandError),
    /// Key source.
    #[error(transparent)]
    KeySource(#[from] crate::keysource::KeySourceError),
}
