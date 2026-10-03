//! Listener drivers: the hook through which another crate supplies the
//! accept loop of a [`Transport`] (feature `server`).
//!
//! The root serves the TCP transports (`local`, `public`, `addr`, `dual`)
//! itself. [`Transport::Tls`] and [`Transport::Ipc`] are declared here but
//! need code the root must not depend on (a TLS stack, owner-only sockets
//! and pipes), so a transport crate implements [`ListenerDriver`] and
//! registers it with
//! [`ServerBuilder::listener_driver`](crate::builder::ServerBuilder::listener_driver),
//! usually through its own extension trait.
//!
//! Contract of a driver:
//!
//! - [`ServerBuilder::build`](crate::builder::ServerBuilder::build) picks the
//!   last registered driver whose [`kind`](ListenerDriver::kind) equals
//!   [`Transport::kind`]. Without one, `tls` and `ipc` fail with
//!   [`BuildError::TransportNotWired`](crate::error::BuildError::TransportNotWired)
//!   as before, and the TCP kinds use the root's own loop.
//! - [`Server::start`](crate::server::Server::start) calls
//!   [`start`](ListenerDriver::start) once, after `on_start`, with the fully
//!   assembled router and a shutdown signal. The driver binds before its
//!   future resolves, so a bind failure fails `start` (as a `RunError::Io`).
//! - The returned [`DriverListener`] carries the bound address and the serve
//!   future. The root spawns that future and awaits it on shutdown, bounded
//!   by the shutdown timeout. The serve future must stop accepting when the
//!   shutdown signal resolves and end once in-flight connections finished.
//! - The router is served without `ConnectInfo`; a driver inserts
//!   `axum::extract::ConnectInfo<SocketAddr>` into each request's extensions
//!   itself when it has a peer address to report.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;

use crate::config::Transport;
use crate::lifecycle::BoxFuture;

/// Resolves once when the server shuts down.
pub type ShutdownSignal = BoxFuture<'static, ()>;

/// Where a driver's listener is bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListenerAddr {
    /// A socket address (actual port).
    Socket(SocketAddr),
    /// A filesystem socket path or a pipe name.
    Path(PathBuf),
}

/// A bound listener handed back by [`ListenerDriver::start`].
pub struct DriverListener {
    local: ListenerAddr,
    serve: BoxFuture<'static, ()>,
}

impl DriverListener {
    /// `local` is where the listener is bound; `serve` accepts and serves
    /// connections until the shutdown signal resolved and in-flight
    /// connections finished.
    pub fn new(local: ListenerAddr, serve: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            local,
            serve: Box::pin(serve),
        }
    }

    /// Where the listener is bound.
    pub fn local(&self) -> &ListenerAddr {
        &self.local
    }

    pub(crate) fn into_parts(self) -> (ListenerAddr, BoxFuture<'static, ()>) {
        (self.local, self.serve)
    }
}

impl std::fmt::Debug for DriverListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriverListener")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

/// Supplies the accept loop of one transport kind. See the module docs for
/// the contract.
pub trait ListenerDriver: Send + Sync + 'static {
    /// The [`Transport::kind`] this driver serves (`"tls"`, `"ipc"`, …).
    fn kind(&self) -> &'static str;

    /// Binds a listener for `transport` and returns it with its serve
    /// future. `transport` always has this driver's kind. Called once per
    /// server start.
    fn start(
        &self,
        transport: &Transport,
        router: Router,
        shutdown: ShutdownSignal,
    ) -> BoxFuture<'static, io::Result<DriverListener>>;
}
