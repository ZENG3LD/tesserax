//! `Transport::Tls` end to end through the root's listener-driver hook, with
//! certificates generated in the test.
#![cfg(feature = "tls")]

use std::fs::{self, Permissions};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::routing::get;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tesserax::{BuildError, RunError, ServerBuilder, Tier, TlsConfig};
use tesserax_transport::TransportExt;
use tesserax_transport::tls::{
    SpkiPin, compute_spki_pin, pinned_client_config, spki_of_certificate,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Pki {
    dir: PathBuf,
    ca_pem: String,
    leaf_der: Vec<u8>,
    client_der: Vec<u8>,
    client_key: Vec<u8>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A CA, a `localhost` server leaf signed by it, and a client certificate.
fn pki() -> Pki {
    let dir = std::env::temp_dir().join(format!(
        "txt-{:x}-{:x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = Permissions::clone;

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client = CertificateParams::new(vec!["client".to_string()])
        .unwrap()
        .signed_by(&client_key, &ca, &ca_key)
        .unwrap();

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    fs::write(&cert_path, leaf.pem()).unwrap();
    fs::write(&key_path, leaf_key.serialize_pem()).unwrap();
    Pki {
        ca_pem: ca.pem(),
        leaf_der: leaf.der().to_vec(),
        client_der: client.der().to_vec(),
        client_key: client_key.serialize_der(),
        cert_path,
        key_path,
        dir,
    }
}

fn server(tls: TlsConfig) -> ServerBuilder {
    ServerBuilder::new("tls-e2e")
        .with_tls("127.0.0.1:0".parse().unwrap(), tls)
        .get_tier("/ping", get(|| async { "pong" }), Tier::Public)
        .get_tier(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
            Tier::Public,
        )
        .get_tier(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                "done"
            }),
            Tier::Public,
        )
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// HTTP/1.1 GET over a TLS stream made with `config`; `Err` if the
/// handshake or the exchange fails.
async fn get_over(
    config: Arc<rustls::ClientConfig>,
    addr: SocketAddr,
    path: &str,
) -> Result<String, String> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let mut tls = TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .map_err(|e| e.to_string())?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    if !text.starts_with("HTTP/1.1 200") {
        return Err(text);
    }
    Ok(text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default())
}

#[tokio::test]
async fn tls_transport_serves_https_through_the_driver_hook() {
    let pki = pki();
    let running = server(TlsConfig::from_paths(&pki.cert_path, &pki.key_path))
        .build()
        .await
        .expect("Tls builds once the driver is registered")
        .start()
        .await
        .expect("start");
    let addr = running.local_addr();
    assert!(addr.ip().is_loopback());
    assert_ne!(addr.port(), 0, "actual bound port reported");
    assert!(running.local_path().is_none());

    // A standard client trusting the CA.
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap())
        .resolve("localhost", addr)
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{}/ping", addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "pong");
    let peer = client
        .get(format!("https://localhost:{}/peer", addr.port()))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(peer, "127.0.0.1", "handlers see the real peer address");

    // A pinned client: accepted by the server key's pin, h2 negotiated.
    let mut pins = SpkiPin::new();
    assert!(pins.push_certificate(&pki.leaf_der));
    let pinned = pinned_client_config(pins).unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = TlsConnector::from(Arc::clone(&pinned))
        .connect(ServerName::try_from("any-name.invalid").unwrap(), tcp)
        .await
        .expect("pin admits the server regardless of name");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    drop(tls);

    // A pin for another key refuses it.
    let other = SpkiPin::from_hex([compute_spki_pin(b"another key")]).unwrap();
    assert!(
        get_over(pinned_client_config(other).unwrap(), addr, "/ping")
            .await
            .is_err()
    );

    // A plaintext probe does not break the listener.
    let mut probe = tokio::net::TcpStream::connect(addr).await.unwrap();
    probe.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), probe.read_to_end(&mut sink)).await;
    assert_eq!(resp_status(&client, addr).await, 200);

    running.shutdown();
    running.wait().await.unwrap();
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "listener closed"
    );
}

async fn resp_status(client: &reqwest::Client, addr: SocketAddr) -> u16 {
    client
        .get(format!("https://localhost:{}/ping", addr.port()))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn client_certificate_pins_admit_only_the_pinned_client() {
    let pki = pki();
    let spki = spki_of_certificate(&pki.client_der).unwrap();
    let tls = TlsConfig::from_paths(&pki.cert_path, &pki.key_path)
        .with_client_spki_pin(compute_spki_pin(spki));
    let running = server(tls).build().await.unwrap().start().await.unwrap();
    let addr = running.local_addr();

    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(pki.ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let base = || {
        rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots.clone())
    };
    let with_cert = Arc::new(
        base()
            .with_client_auth_cert(
                vec![CertificateDer::from(pki.client_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.client_key.clone())),
            )
            .unwrap(),
    );
    assert_eq!(
        get_over(with_cert, addr, "/ping").await.as_deref(),
        Ok("pong")
    );

    let without = Arc::new(base().with_no_client_auth());
    assert!(
        get_over(without, addr, "/ping").await.is_err(),
        "no client certificate, no answer"
    );

    // A certificate from the same CA but another key is not pinned.
    let stranger_key = KeyPair::generate().unwrap();
    let stranger = CertificateParams::new(vec!["stranger".to_string()])
        .unwrap()
        .self_signed(&stranger_key)
        .unwrap();
    let wrong = Arc::new(
        base()
            .with_client_auth_cert(
                vec![stranger.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(stranger_key.serialize_der())),
            )
            .unwrap(),
    );
    assert!(get_over(wrong, addr, "/ping").await.is_err());

    running.shutdown();
    running.wait().await.unwrap();
}

#[tokio::test]
async fn in_flight_tls_requests_finish_during_shutdown() {
    let pki = pki();
    let running = server(TlsConfig::from_paths(&pki.cert_path, &pki.key_path))
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let addr = running.local_addr();
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(pki.ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let slow = tokio::spawn(get_over(cfg, addr, "/slow"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    running.shutdown();
    running.wait().await.unwrap();
    assert_eq!(slow.await.unwrap().as_deref(), Ok("done"));
}

#[tokio::test]
async fn bad_certificate_material_fails_start_and_bad_pins_too() {
    let pki = pki();
    let missing = TlsConfig::from_paths(pki.dir.join("absent.pem"), &pki.key_path);
    let err = server(missing)
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap_err();
    assert!(
        matches!(err, RunError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData),
        "{err}"
    );

    let bad_pin =
        TlsConfig::from_paths(&pki.cert_path, &pki.key_path).with_client_spki_pin("deadbeef");
    let err = server(bad_pin)
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap_err();
    assert!(err.to_string().contains("pin"), "{err}");
}

#[tokio::test]
async fn a_public_tls_listener_needs_a_gate_for_admin_routes() {
    let err = ServerBuilder::new("x")
        .with_tls(
            "0.0.0.0:0".parse().unwrap(),
            TlsConfig::from_paths("cert.pem", "key.pem"),
        )
        .build()
        .await
        .unwrap_err();
    assert!(
        matches!(err, BuildError::UnauthenticatedAdminRoute { .. }),
        "{err}"
    );
}

#[test]
fn load_server_config_advertises_h2_then_http11() {
    let pki = pki();
    let cfg = tesserax_transport::tls::load_server_config(&TlsConfig::from_paths(
        &pki.cert_path,
        &pki.key_path,
    ))
    .unwrap();
    assert_eq!(
        cfg.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    let err = tesserax_transport::tls::load_server_config(&TlsConfig::from_paths(
        "/nonexistent/c.pem",
        "/nonexistent/k.pem",
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        tesserax_transport::tls::TlsError::ReadCert { .. }
    ));
}
