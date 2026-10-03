//! Crate-level error of the pure helpers ([`Endpoint`](crate::Endpoint),
//! [`proof`](crate::proof)). IO-bound modules return `std::io::Error` or
//! their own enum.

use thiserror::Error;

/// Why an endpoint string, a nonce or a proof domain could not be made.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum TransportError {
    /// The operating system's random source failed.
    #[error("random source failed: {0}")]
    Random(String),
    /// The endpoint string is not a local path, pipe name or http(s) /
    /// ws(s) URL.
    #[error("endpoint {input:?} is not usable: {reason}")]
    Endpoint {
        /// What was offered.
        input: String,
        /// What is wrong.
        reason: &'static str,
    },
    /// A proof-domain label is longer than its 16-bit length prefix allows.
    #[error("proof domain label is {len} bytes, the limit is 65535")]
    LabelTooLong {
        /// Offered length in bytes.
        len: usize,
    },
}
