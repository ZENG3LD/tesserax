//! Owner-only local links: the transport for a peer on the same host.
//!
//! - Unix: [`OwnerOnlyListener`] binds a Unix domain socket whose parent
//!   directory must be owned by the effective user and have mode `0700`;
//!   the socket gets mode `0600`, a per-endpoint lock file
//!   (`.<name>.lock`, taken with a non-blocking exclusive lock) makes a
//!   second listener on the same path fail with `AddrInUse` instead of
//!   stealing it, a stale socket left by a dead listener is probed and
//!   replaced, a live one is never touched, and on drop the socket is
//!   removed only if it is still the inode this listener created. Both
//!   `accept` and [`connect_local`] check the peer's uid (the owner or
//!   root) before a single byte moves.
//! - Windows: a named pipe whose DACL grants access to the current user
//!   and LocalSystem only, protected from inheritance, first instance
//!   claimed exclusively, remote clients rejected.
//!
//! [`connect_local`] retries 100 × 20 ms while the endpoint does not exist
//! yet or refuses (a listener that is still starting).
//! [`connect_loopback`] is the TCP fallback for hosts without local
//! sockets: it refuses anything but a loopback address with a non-zero
//! port before any IO.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

#[cfg(unix)]
mod unix_socket;
#[cfg(unix)]
pub use unix_socket::{LocalClientStream, LocalServerStream, OwnerOnlyListener, connect_local};

#[cfg(windows)]
mod windows_pipe;
#[cfg(windows)]
pub use windows_pipe::{LocalClientStream, LocalServerStream, OwnerOnlyListener, connect_local};

/// Connect attempts of [`connect_local`].
pub const CONNECT_RETRIES: usize = 100;
/// Delay between [`connect_local`] attempts.
pub const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(20);

/// Connects to a loopback TCP endpoint. A non-loopback address or port 0
/// is refused with `InvalidInput` before any IO.
pub async fn connect_loopback(addr: SocketAddr) -> io::Result<TcpStream> {
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local TCP endpoint must be loopback with a non-zero port",
        ));
    }
    TcpStream::connect(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn loopback_connect_refuses_other_addresses_before_io() {
        for addr in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
        ] {
            let err = connect_loopback(addr).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{addr}");
        }
    }

    #[tokio::test]
    async fn loopback_connect_reaches_a_loopback_listener() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (c, s) = tokio::join!(connect_loopback(addr), l.accept());
        assert!(c.is_ok());
        assert!(s.unwrap().1.ip().is_loopback());
    }
}
