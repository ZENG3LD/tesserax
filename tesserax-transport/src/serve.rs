//! Accept loops of a tesserax server over transports the root does not
//! serve itself (feature `server`), wired through the root's
//! [`ListenerDriver`](tesserax::ListenerDriver) hook.
//!
//! One connection loop serves both [`serve_ipc`] and (feature `tls`)
//! [`serve_tls`](crate::tls::serve_tls): every accepted connection is served
//! by hyper's HTTP/1.1 + HTTP/2 auto builder (with upgrades, so WebSocket
//! routes work), each request carries `ConnectInfo<SocketAddr>`, and on
//! shutdown the loop stops accepting, asks every live connection to finish
//! gracefully, and returns once all of them ended.
//!
//! Over IPC the `ConnectInfo` address is `127.0.0.1:0`: the peer passed the
//! owner-only check (same user or root), so middleware that reasons about
//! client addresses treats it as a loopback caller.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tesserax::lifecycle::BoxFuture;
use tesserax::{
    DriverListener, ListenerAddr, ListenerDriver, ServerBuilder, ShutdownSignal, Transport,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};
use tower_service::Service;

use crate::local::OwnerOnlyListener;

/// Pause after a failed `accept` (for example out of descriptors) so the
/// loop does not spin.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// The address IPC requests report as their peer.
const IPC_PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

/// Live connections of one listener: a stop flag they watch and a channel
/// whose senders they hold, so draining waits for the last one.
pub(crate) struct Connections {
    stop: watch::Sender<bool>,
    alive_tx: mpsc::Sender<()>,
    alive_rx: mpsc::Receiver<()>,
}

impl Connections {
    pub(crate) fn new() -> Self {
        let (stop, _) = watch::channel(false);
        let (alive_tx, alive_rx) = mpsc::channel(1);
        Self {
            stop,
            alive_tx,
            alive_rx,
        }
    }

    /// Serves one connection. `io` finishes the connection setup (a TLS
    /// handshake, or nothing); it is abandoned if shutdown starts first.
    pub(crate) fn spawn<F, S>(&self, io: F, router: Router, peer: SocketAddr)
    where
        F: Future<Output = io::Result<S>> + Send + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut stop = self.stop.subscribe();
        let alive = self.alive_tx.clone();
        tokio::spawn(async move {
            let _alive = alive;
            let stream = tokio::select! {
                r = io => match r {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(%peer, "connection setup failed: {e}");
                        return;
                    }
                },
                () = stopped(&mut stop) => return,
            };
            let service = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                let mut router = router.clone();
                async move { Ok::<_, Infallible>(router.call(req).await.unwrap_or_else(|e| match e {})) }
            });
            let builder = auto::Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
            tokio::pin!(conn);
            tokio::select! {
                r = conn.as_mut() => {
                    if let Err(e) = r {
                        tracing::debug!(%peer, "connection ended with an error: {e}");
                    }
                }
                () = stopped(&mut stop) => {
                    conn.as_mut().graceful_shutdown();
                    if let Err(e) = conn.await {
                        tracing::debug!(%peer, "connection ended with an error during drain: {e}");
                    }
                }
            }
        });
    }

    /// Tells every connection to finish and waits until all have.
    pub(crate) async fn drain(self) {
        self.stop.send_replace(true);
        drop(self.alive_tx);
        let mut rx = self.alive_rx;
        let _ = rx.recv().await;
    }
}

/// Resolves once the stop flag is set (or its sender is gone).
async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await;
}

/// Serves `router` on an owner-only local listener until `shutdown`
/// resolves, then drains in-flight connections.
pub async fn serve_ipc(
    mut listener: OwnerOnlyListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send,
) {
    let conns = Connections::new();
    let endpoint = listener.endpoint().to_path_buf();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(stream) => conns.spawn(std::future::ready(Ok(stream)), router.clone(), IPC_PEER),
                Err(e) => {
                    tracing::warn!(endpoint = %endpoint.display(), "ipc accept failed: {e}");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                }
            },
        }
    }
    // Stop accepting (and remove the socket) before waiting for the drain.
    drop(listener);
    conns.drain().await;
}

/// [`ListenerDriver`] of kind `ipc`: binds `Transport::Ipc { socket_path }`
/// with [`OwnerOnlyListener`] and serves it with [`serve_ipc`].
#[derive(Clone, Copy, Debug, Default)]
pub struct IpcDriver;

impl ListenerDriver for IpcDriver {
    fn kind(&self) -> &'static str {
        "ipc"
    }

    fn start(
        &self,
        transport: &Transport,
        router: Router,
        shutdown: ShutdownSignal,
    ) -> BoxFuture<'static, io::Result<DriverListener>> {
        let path = match transport {
            Transport::Ipc { socket_path } => Ok(socket_path.clone()),
            other => Err(wrong_transport("ipc", other)),
        };
        Box::pin(async move {
            let listener = OwnerOnlyListener::bind(path?).await?;
            let local = ListenerAddr::Path(listener.endpoint().to_path_buf());
            Ok(DriverListener::new(
                local,
                serve_ipc(listener, router, shutdown),
            ))
        })
    }
}

pub(crate) fn wrong_transport(expected: &str, got: &Transport) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{expected} driver started for a {} transport", got.kind()),
    )
}

/// Wires the transports of this crate into a `tesserax::ServerBuilder`.
pub trait TransportExt: Sized {
    /// Serves on an owner-only local socket (Unix) or pipe (Windows) at
    /// `path`: sets `Transport::Ipc` and registers [`IpcDriver`].
    fn with_ipc(self, path: impl Into<PathBuf>) -> Self;

    /// Serves HTTPS on `bind_addr`: sets `Transport::Tls` and registers
    /// [`TlsDriver`](crate::tls::TlsDriver).
    #[cfg(feature = "tls")]
    fn with_tls(self, bind_addr: SocketAddr, tls: tesserax::TlsConfig) -> Self;
}

impl TransportExt for ServerBuilder {
    fn with_ipc(self, path: impl Into<PathBuf>) -> Self {
        self.transport(Transport::Ipc {
            socket_path: path.into(),
        })
        .listener_driver(IpcDriver)
    }

    #[cfg(feature = "tls")]
    fn with_tls(self, bind_addr: SocketAddr, tls: tesserax::TlsConfig) -> Self {
        self.transport(Transport::Tls { bind_addr, tls })
            .listener_driver(crate::tls::TlsDriver)
    }
}
