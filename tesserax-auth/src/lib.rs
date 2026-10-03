//! `tesserax-auth` — authentication for `tesserax` servers.
//!
//! Callers present a key; the key's SHA-256 is looked up in a [`KeyRing`]
//! (constant-time, every record compared); the matching [`KeyRecord`]'s
//! [`Grant`]s say which [`Door`]s it may use at which tier and scopes; a
//! door's [`Policy`] says which route templates it serves. [`AuthGate`]
//! makes that decision per request (the step list is in [`gate`]),
//! [`AuthExt::with_auth`] installs it on a `ServerBuilder`, [`AuthBan`]
//! bans addresses after repeated failures, [`DerivedTokens`] issues
//! per-subject tokens from one secret, and [`ct`] holds the only
//! constant-time compare and HMAC-SHA256 of the family (re-exported from
//! `tesserax::ct`).
//!
//! Closed by default: an empty ring refuses every credential, a door's
//! default policy admits nothing, query-string keys are off unless a door
//! allows them, and serving without keys needs an explicit
//! [`Door::open_loopback_only`].
//!
//! # Contract
//!
//! ```text
//! Role:      shell (axum middleware over the Tier / Principal / RouteTable types of the root)
//! Owns:      key rings (hashes only), failure ledger (AuthBan). No persistent state
//!            except a DerivedTokens secret file it is told to create.
//! Exports:   ct_eq, ct_eq_str, hmac_sha256, generate_key, KeyHash, KeyRecord, KeyRing, Grant, Door, Policy,
//!            PathTemplate, AuthGate, Denial, AuthLayer, AuthOutcome, AuthChain, AuthChainMode, AuthExt,
//!            DerivedTokens, AuthBan, AuthBanConfig, AuthError.
//! Imports:   tesserax (incl. tesserax::ct, the single constant-time compare), axum types, zeroize, getrandom,
//!            thiserror, tracing;
//!            feature toml: serde, toml.
//! Forbidden: any domain crate; tesserax-http / -transport / -mcp / -framework; `==` / `!=` on secret
//!            material outside ct.rs; open-by-default behaviour; any product, host or consumer name.
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod ban;
pub mod ct;
mod derived;
mod door;
mod error;
mod ext;
pub mod gate;
mod key;
mod layer;

pub use ban::{AuthBan, AuthBanConfig};
pub use ct::{ct_eq, ct_eq_str, hmac_sha256};
pub use derived::DerivedTokens;
pub use door::{Door, PathTemplate, Policy};
pub use error::AuthError;
pub use ext::AuthExt;
pub use gate::{AuthGate, Denial};
pub use key::{Grant, KeyHash, KeyRecord, KeyRing, generate_key};
pub use layer::{AuthChain, AuthChainMode, AuthLayer, AuthOutcome, BoxFuture};
