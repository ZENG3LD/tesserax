//! `tesserax-secrets` — secrets at rest and signing for `tesserax` services.
//!
//! - [`SealedSecret`] (ChaCha20-Poly1305, four-factor host fingerprint)
//!   and [`MachineSeal`] (AES-256-GCM, machine id) bind data to a host;
//!   [`HostFactors`] are the inputs, read from the host by [`platform`] or
//!   supplied explicitly.
//! - [`DaemonIdentity`]: a service instance's ed25519 key, sealed at rest.
//! - [`signing`]: canonical bytes and state for signed responses.
//! - [`opcmd`]: ed25519-signed operator commands, trust store, replay
//!   cache, outbound signer.
//! - [`shamir`]: k-of-n secret sharing; [`tripwire`]: host-move detection;
//!   [`keysource`]: where a master key comes from.
//! - Features: `hardening` (process lockdown, the only `unsafe`), `opctl`
//!   (operator HTTP tooling and the `tesserax-opctl` binary), `peer-trust`
//!   (signed trust gossip between services).
//!
//! Wire and storage domain labels: `tesserax-sealed-secret-v1`,
//! `tesserax-machine-seal-v1`, `tesserax-tripwire-v1`,
//! `tesserax-op-command-v2`, `tesserax-resp-v1`,
//! `tesserax-mesh-trust-entry-v1`, and the `x-tesserax-sig*` header names.
//! Golden vectors in `tests/golden.rs` lock those bytes.
//!
//! Constant-time comparison comes from `tesserax::ct` (the family's single
//! implementation); this crate has no compare of its own.
//!
//! # Contract
//!
//! ```text
//! Role:      engine (crypto-at-rest logic); features `opctl`, `peer-trust` add client shells
//! Owns:      nothing stateful except files it is told to seal (identity, sealed blobs, tripwire pin)
//! Exports:   MachineSeal, SealedSecret, SealedPlaintext, HostFactors, BindingStrength, DaemonIdentity, wipe_identity,
//!            shamir::{split, reconstruct, Share}, tripwire::{check_or_pin, TripwirePolicy},
//!            keysource::{KeySource, DmiKeySource, RemoteKeySource, StaticKeySource},
//!            platform::{machine_id, product_uuid, primary_mac, uid},
//!            opcmd::{OperatorCommand, OperatorTrustStore, ReplayCache, OperatorCommandClient},
//!            signing::{ResponseSigningState, SignedResponseConfig, SigningScope, canonical_signing_bytes},
//!            hardening::harden_process (feature), opctl (feature), peer_trust (feature), SecretsError.
//! Imports:   tesserax (no default features), sha2, blake3, chacha20poly1305, aes-gcm, hkdf, ed25519-dalek,
//!            zeroize, getrandom, base64, serde, serde_json, thiserror, tracing;
//!            feature hardening: libc; feature opctl: reqwest, tokio, clap.
//! Forbidden: axum, rusqlite, tesserax-auth/-http/-store/-framework; `unsafe` outside module `hardening`;
//!            a constant-time compare of its own; any product, host or consumer name.
//! ```
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
#[cfg(feature = "hardening")]
pub mod hardening;
mod host;
mod identity;
pub mod keysource;
mod machine_seal;
pub mod opcmd;
#[cfg(feature = "opctl")]
pub mod opctl;
#[cfg(feature = "peer-trust")]
pub mod peer_trust;
#[cfg(all(feature = "peer-trust", feature = "opctl"))]
pub mod peer_trust_push;
pub mod platform;
mod sealed_secret;
pub mod shamir;
pub mod signing;
pub mod tripwire;

pub use error::SecretsError;
pub use host::{BindingStrength, HostFactors};
pub use identity::{DaemonIdentity, DaemonIdentityError, wipe_identity};
pub use machine_seal::{MachineSeal, MachineSealError};
pub use sealed_secret::{SealedPlaintext, SealedSecret, SealedSecretError};
