//! Listener profiles and small server settings (feature `server`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Where a server listens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transport {
    /// One listener on `127.0.0.1:port`.
    Local {
        /// Port; 0 lets the OS pick.
        port: u16,
    },
    /// One listener on `0.0.0.0:port`.
    Public {
        /// Port; 0 lets the OS pick.
        port: u16,
    },
    /// One listener on exactly `addr`.
    Addr {
        /// Listener address.
        addr: SocketAddr,
    },
    /// Two listeners sharing one router: `public_addr` and
    /// `127.0.0.1:admin_port`. Gates apply on both; the loopback port is a
    /// convenience, not authentication.
    Dual {
        /// Public listener address.
        public_addr: SocketAddr,
        /// Loopback admin port; 0 lets the OS pick.
        admin_port: u16,
    },
    /// HTTPS on `bind_addr`. Declared here; the accept loop comes from a
    /// [`ListenerDriver`](crate::listener::ListenerDriver) of kind `tls`
    /// (a transport extension); without one the build is refused.
    Tls {
        /// Listener address.
        bind_addr: SocketAddr,
        /// Certificate material.
        tls: TlsConfig,
    },
    /// Owner-only local socket or pipe. Declared here; the accept loop comes
    /// from a [`ListenerDriver`](crate::listener::ListenerDriver) of kind
    /// `ipc` (a transport extension); without one the build is refused.
    Ipc {
        /// Socket path or pipe name.
        socket_path: PathBuf,
    },
}

impl Transport {
    /// `127.0.0.1:port`.
    pub fn local(port: u16) -> Self {
        Self::Local { port }
    }

    /// `0.0.0.0:port`.
    pub fn public(port: u16) -> Self {
        Self::Public { port }
    }

    /// Exactly `addr`.
    pub fn addr(addr: SocketAddr) -> Self {
        Self::Addr { addr }
    }

    /// `0.0.0.0:public_port` plus `127.0.0.1:admin_port`.
    pub fn dual(public_port: u16, admin_port: u16) -> Self {
        Self::Dual {
            public_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), public_port),
            admin_port,
        }
    }

    /// Primary listener address; `None` for `Ipc`.
    pub fn primary_addr(&self) -> Option<SocketAddr> {
        match self {
            Transport::Local { port } => {
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *port))
            }
            Transport::Public { port } => {
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), *port))
            }
            Transport::Addr { addr } => Some(*addr),
            Transport::Dual { public_addr, .. } => Some(*public_addr),
            Transport::Tls { bind_addr, .. } => Some(*bind_addr),
            Transport::Ipc { .. } => None,
        }
    }

    /// Loopback admin listener address of `Dual`.
    pub fn admin_addr(&self) -> Option<SocketAddr> {
        match self {
            Transport::Dual { admin_port, .. } => Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                *admin_port,
            )),
            _ => None,
        }
    }

    /// True when no listener is reachable from another host: a loopback
    /// address, or an owner-only local socket.
    pub fn is_local_only(&self) -> bool {
        match self {
            Transport::Ipc { .. } => true,
            Transport::Dual { public_addr, .. } => public_addr.ip().is_loopback(),
            other => other.primary_addr().is_some_and(|a| a.ip().is_loopback()),
        }
    }

    /// Short kind name for messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Transport::Local { .. } => "local",
            Transport::Public { .. } => "public",
            Transport::Addr { .. } => "addr",
            Transport::Dual { .. } => "dual",
            Transport::Tls { .. } => "tls",
            Transport::Ipc { .. } => "ipc",
        }
    }
}

/// Certificate material for [`Transport::Tls`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsConfig {
    /// PEM certificate chain.
    pub cert_path: PathBuf,
    /// PEM private key.
    pub key_path: PathBuf,
    /// Client-certificate SPKI pins (hex digests); empty = no client auth.
    pub client_spki_pins: Vec<String>,
}

impl TlsConfig {
    /// Certificate and key paths, no client pins.
    pub fn from_paths(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            cert_path: cert.into(),
            key_path: key.into(),
            client_spki_pins: Vec::new(),
        }
    }

    /// Adds a client SPKI pin.
    pub fn with_client_spki_pin(mut self, hex: impl Into<String>) -> Self {
        self.client_spki_pins.push(hex.into());
        self
    }
}

/// `POST /reload` settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadConfig {
    /// Serve `POST /reload` (tier `Admin`), which runs the `on_reload` hook.
    pub endpoint: bool,
}

impl Default for ReloadConfig {
    fn default() -> Self {
        Self { endpoint: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_only_classification() {
        assert!(Transport::local(0).is_local_only());
        assert!(!Transport::public(0).is_local_only());
        assert!(Transport::addr("127.0.0.1:0".parse().unwrap()).is_local_only());
        assert!(!Transport::addr("10.0.0.1:0".parse().unwrap()).is_local_only());
        assert!(!Transport::dual(0, 0).is_local_only());
        assert!(
            Transport::Dual {
                public_addr: "127.0.0.1:0".parse().unwrap(),
                admin_port: 0
            }
            .is_local_only()
        );
        assert!(
            Transport::Ipc {
                socket_path: "/tmp/x.sock".into()
            }
            .is_local_only()
        );
        assert_eq!(
            Transport::Ipc {
                socket_path: "x".into()
            }
            .primary_addr(),
            None
        );
    }
}
