//! [`FrameworkError`]: the failure surface of the framework in one enum,
//! and [`ShellError`], what a transport shell or a remote handle reports.

use tesserax::swc::{DispatchError, SubscribeError};

use crate::kernel::CoreError;
use crate::runtime::RuntimeError;

/// Anything the framework can fail with, by layer. Later layers (jobs)
/// add variants. NCP and the process plugin host add theirs behind
/// their features.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameworkError {
    /// The kernel could not do something in a step.
    #[error(transparent)]
    Kernel(#[from] CoreError),
    /// The runtime could not start or stop cleanly.
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    /// A transport shell or a remote handle failed.
    #[error(transparent)]
    Shell(#[from] ShellError),
    /// The NCP tier scaffolding failed.
    #[cfg(feature = "ncp-shared")]
    #[error(transparent)]
    Ncp(#[from] crate::ncp::NcpError),
    /// The process plugin host failed.
    #[cfg(feature = "plugins")]
    #[error(transparent)]
    Plugin(#[from] crate::plugins::PluginError),
}

/// Why a shell or a [`RemoteHandle`](crate::shell::RemoteHandle) call
/// failed.
///
/// The port's own refusals keep their type: [`Dispatch`](Self::Dispatch)
/// and [`Subscribe`](Self::Subscribe) carry exactly what the serving port
/// answered, so a remote `Full` is the kernel's `Full`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ShellError {
    /// The serving port refused the command.
    #[error("dispatch refused: {0}")]
    Dispatch(DispatchError),
    /// The serving port refused the subscriber.
    #[error("subscribe refused: {0}")]
    Subscribe(SubscribeError),
    /// The caller's credential does not open the door this call needs
    /// (HTTP 401 / 403, or a local link whose door does not serve it).
    #[error("not admitted through the {door} door")]
    Unauthorized {
        /// `control` or `observe`.
        door: &'static str,
    },
    /// The link handshake failed (unknown door, proof mismatch, peer
    /// refused).
    #[error("link handshake failed: {0}")]
    Handshake(String),
    /// The peer answered something the protocol does not allow.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// The peer answered with an unexpected HTTP status.
    #[error("unexpected status {status}: {message}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// Error code or body excerpt.
        message: String,
    },
    /// No answer within the configured timeout.
    #[error("timed out")]
    Timeout,
    /// A frame could not be encoded or decoded.
    #[error("codec: {0}")]
    Codec(String),
    /// Socket, pipe or runtime IO failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A blocking remote call was made on a thread that drives an async
    /// runtime (it would stall that runtime); call it from a plain thread
    /// or through `spawn_blocking`.
    #[error("blocking remote call from inside an async runtime")]
    InsideRuntime,
    /// A shell was started outside a tokio runtime.
    #[error("no tokio runtime to run the shell on")]
    NoRuntime,
    /// The shell or handle was configured in a way that cannot work.
    #[error("invalid configuration: {0}")]
    Config(String),
}
