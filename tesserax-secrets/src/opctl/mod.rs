//! Operator-side tooling (feature `opctl`): key files, service discovery,
//! response-signature verification and a signed-call session. The binary
//! `tesserax-opctl` is built on this module.

pub mod discover;
pub mod key_file;
pub mod response_verify;
pub mod session;

pub use discover::{DISCOVERY_PATHS, DaemonInfo, DiscoverError, discover_daemon};
pub use key_file::{KeyFileError, generate, load_secret, save_secret};
pub use response_verify::{ResponseVerifyError, VerifiedResponse, verify_response_signature};
pub use session::{Session, SessionError};
