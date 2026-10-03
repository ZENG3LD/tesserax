//! The rustls half of [`crate::tls`] (feature `tls`).

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig,
    SignatureScheme,
};
use tesserax::lifecycle::{BindRetryPolicy, BoxFuture, bind_with_retry};
use tesserax::{
    DriverListener, ListenerAddr, ListenerDriver, ShutdownSignal, TlsConfig, Transport,
};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::{PinError, SpkiPin, hex};
use crate::serve::{Connections, wrong_transport};
use tesserax::ct::sha256;

/// Deadline of one TLS handshake; a peer that opens a socket and stalls is
/// dropped after it.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Why a TLS configuration could not be built.
#[derive(Debug, Error)]
pub enum TlsError {
    /// The certificate file could not be read.
    #[error("read cert {path}: {source}")]
    ReadCert {
        /// File.
        path: String,
        /// Cause.
        source: io::Error,
    },
    /// The key file could not be read.
    #[error("read key {path}: {source}")]
    ReadKey {
        /// File.
        path: String,
        /// Cause.
        source: io::Error,
    },
    /// No certificate, or a malformed one, in the PEM.
    #[error("parse cert: {0}")]
    ParseCert(String),
    /// No private key, or a malformed one, in the PEM.
    #[error("parse key: {0}")]
    ParseKey(String),
    /// A configured pin is not a SHA-256 hex digest.
    #[error(transparent)]
    Pin(#[from] PinError),
    /// rustls refused the configuration.
    #[error("rustls config: {0}")]
    Config(#[from] rustls::Error),
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Reads the PEM chain and key of `cfg` (synchronously: call at boot) and
/// builds the server config; see the module docs for ALPN and client pins.
pub fn load_server_config(cfg: &TlsConfig) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_pem = std::fs::read(&cfg.cert_path).map_err(|source| TlsError::ReadCert {
        path: cfg.cert_path.display().to_string(),
        source,
    })?;
    let key_pem = std::fs::read(&cfg.key_path).map_err(|source| TlsError::ReadKey {
        path: cfg.key_path.display().to_string(),
        source,
    })?;
    let pins = SpkiPin::from_hex(&cfg.client_spki_pins)?;
    server_config_from_pem(&cert_pem, &key_pem, &pins)
}

/// [`load_server_config`] from PEM bytes. An empty `client_pins` means no
/// client authentication.
pub fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
    client_pins: &SpkiPin,
) -> Result<Arc<ServerConfig>, TlsError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::ParseCert(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::ParseCert("no certificates in PEM".into()));
    }
    let key =
        PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| TlsError::ParseKey(e.to_string()))?;

    let provider = provider();
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?;
    let builder = if client_pins.is_empty() {
        builder.with_no_client_auth()
    } else {
        builder.with_client_cert_verifier(Arc::new(ClientPinVerifier {
            pins: client_pins.clone(),
            algorithms: provider.signature_verification_algorithms,
        }))
    };
    let mut config = builder.with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A client config that accepts exactly the servers whose certificate
/// matches one of `pins` (host name and chain are not checked: the pin is
/// the trust). No client certificate is sent.
pub fn pinned_client_config(pins: SpkiPin) -> Result<Arc<ClientConfig>, TlsError> {
    let provider = provider();
    let algorithms = provider.signature_verification_algorithms;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ServerPinVerifier { pins, algorithms }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn check_pin(
    pins: &SpkiPin,
    end_entity: &CertificateDer<'_>,
    side: &str,
) -> Result<(), rustls::Error> {
    if pins.matches_certificate(end_entity.as_ref()) {
        Ok(())
    } else {
        tracing::warn!(presented = %hex(&sha256(end_entity.as_ref())), "{side} certificate matches no pin");
        Err(rustls::Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }
}

/// Admits a client whose leaf certificate matches a pin.
#[derive(Debug)]
struct ClientPinVerifier {
    pins: SpkiPin,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for ClientPinVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        check_pin(&self.pins, end_entity, "client").map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

/// Accepts a server whose leaf certificate matches a pin.
#[derive(Debug)]
struct ServerPinVerifier {
    pins: SpkiPin,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ServerPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        check_pin(&self.pins, end_entity, "server").map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Serves `router` over TLS on `listener` until `shutdown` resolves, then
/// drains in-flight connections. Handshakes run off the accept path with
/// [`HANDSHAKE_TIMEOUT`]; a failed handshake (wrong pin, plaintext probe)
/// is logged at debug and dropped.
pub async fn serve_tls(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    router: Router,
    shutdown: impl Future<Output = ()> + Send,
) {
    let acceptor = TlsAcceptor::from(config);
    let conns = Connections::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok((tcp, peer)) => {
                    let _ = tcp.set_nodelay(true);
                    let acceptor = acceptor.clone();
                    let handshake = async move {
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
                            .await
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out"))?
                    };
                    conns.spawn(handshake, router.clone(), peer);
                }
                Err(e) => {
                    tracing::warn!("tls accept failed: {e}");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                }
            },
        }
    }
    drop(listener);
    conns.drain().await;
}

/// [`ListenerDriver`] of kind `tls`: loads the certificate of
/// `Transport::Tls`, binds `bind_addr` (with the root's bind retry) and
/// serves with [`serve_tls`].
#[derive(Clone, Copy, Debug, Default)]
pub struct TlsDriver;

impl ListenerDriver for TlsDriver {
    fn kind(&self) -> &'static str {
        "tls"
    }

    fn start(
        &self,
        transport: &Transport,
        router: Router,
        shutdown: ShutdownSignal,
    ) -> BoxFuture<'static, io::Result<DriverListener>> {
        let target = match transport {
            Transport::Tls { bind_addr, tls } => Ok((*bind_addr, tls.clone())),
            other => Err(wrong_transport("tls", other)),
        };
        Box::pin(async move {
            let (addr, tls) = target?;
            let config = load_server_config(&tls)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let listener = bind_with_retry(addr, &BindRetryPolicy::default())
                .await
                .map_err(|e| io::Error::new(e.source.kind(), e.to_string()))?;
            let local = listener.local_addr()?;
            tracing::info!(addr = %local, "tls listening");
            Ok(DriverListener::new(
                ListenerAddr::Socket(local),
                serve_tls(listener, config, router, shutdown),
            ))
        })
    }
}
