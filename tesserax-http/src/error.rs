//! [`HttpError`]: failures of this crate's fallible constructors and calls.

use thiserror::Error;

/// Why a call of this crate failed.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum HttpError {
    /// A payload could not be serialized.
    #[error("serialize: {0}")]
    Serialize(String),
    /// An SSE id did not increase.
    #[error("event id {offered} does not follow {last}")]
    IdNotIncreasing {
        /// Last published id.
        last: u64,
        /// Offered id.
        offered: u64,
    },
    /// The operating system's random source failed.
    #[error("random source unavailable")]
    Random,
    /// A configuration value is not usable.
    #[error("invalid configuration: {0}")]
    Config(String),
}
