//! `SmtpClient` against an in-test fake relay: plain, STARTTLS and implicit
//! TLS, AUTH PLAIN / LOGIN, refusals, dot-stuffing on the wire, deadlines.
#![cfg(feature = "egress")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tesserax_transport::egress::{
    EmailMessage, Mailer, SmtpAuth, SmtpClient, SmtpConfig, SmtpError, SmtpTls,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const USER: &str = "robot@example.com";
const PASS: &str = "app-password";

#[derive(Clone, Default)]
struct Relay {
    /// Advertise and honour STARTTLS on the plain leg.
    starttls: bool,
    /// TLS from the first byte.
    implicit: bool,
    /// AUTH mechanisms to advertise.
    auth: &'static [&'static str],
    /// Answer 550 to RCPT TO.
    reject_rcpt: bool,
    /// Say nothing at all after accepting.
    silent: bool,
}

#[derive(Default, Debug)]
struct Seen {
    commands: Vec<String>,
    data: Vec<u8>,
    authenticated: bool,
    tls_commands: usize,
}

struct Fixture {
    acceptor: TlsAcceptor,
    client_tls: Arc<rustls::ClientConfig>,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn fixture() -> Fixture {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    let server = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Fixture {
        acceptor: TlsAcceptor::from(Arc::new(server)),
        client_tls: Arc::new(client),
    }
}

enum End<S> {
    Done,
    Upgrade(S),
}

async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    relay: &Relay,
    seen: &Mutex<Seen>,
    tls: bool,
    greet: bool,
) -> End<S> {
    let mut r = BufReader::new(stream);
    macro_rules! say {
        ($s:expr) => {
            if r.get_mut().write_all($s.as_bytes()).await.is_err() {
                return End::Done;
            }
            let _ = r.get_mut().flush().await;
        };
    }
    if greet {
        say!("220 relay.example ESMTP ready\r\n");
    }
    loop {
        let mut line = String::new();
        match r.read_line(&mut line).await {
            Ok(0) | Err(_) => return End::Done,
            Ok(_) => {}
        }
        let line = line.trim_end_matches("\r\n").to_owned();
        {
            let mut s = seen.lock().unwrap();
            s.commands.push(line.clone());
            if tls {
                s.tls_commands += 1;
            }
        }
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("EHLO ") {
            let mut reply = String::from("250-relay.example greets you\r\n");
            if relay.starttls && !tls {
                reply.push_str("250-STARTTLS\r\n");
            }
            if !relay.auth.is_empty() {
                reply.push_str(&format!("250-AUTH {}\r\n", relay.auth.join(" ")));
            }
            reply.push_str("250 SIZE 1000000\r\n");
            say!(reply);
        } else if upper == "STARTTLS" && relay.starttls && !tls {
            say!("220 go ahead\r\n");
            assert!(r.buffer().is_empty(), "client pipelined past STARTTLS");
            return End::Upgrade(r.into_inner());
        } else if let Some(b64) = line.strip_prefix("AUTH PLAIN ") {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap();
            let ok = raw == format!("\0{USER}\0{PASS}").into_bytes();
            seen.lock().unwrap().authenticated = ok;
            say!(if ok {
                "235 ok\r\n"
            } else {
                "535 bad credentials\r\n"
            });
        } else if upper == "AUTH LOGIN" {
            say!("334 VXNlcm5hbWU6\r\n");
            let mut u = String::new();
            let _ = r.read_line(&mut u).await;
            say!("334 UGFzc3dvcmQ6\r\n");
            let mut p = String::new();
            let _ = r.read_line(&mut p).await;
            let dec = |s: &str| {
                base64::engine::general_purpose::STANDARD
                    .decode(s.trim_end())
                    .unwrap()
            };
            let ok = dec(&u) == USER.as_bytes() && dec(&p) == PASS.as_bytes();
            seen.lock().unwrap().authenticated = ok;
            say!(if ok {
                "235 ok\r\n"
            } else {
                "535 bad credentials\r\n"
            });
        } else if upper.starts_with("MAIL FROM:") {
            say!("250 ok\r\n");
        } else if upper.starts_with("RCPT TO:") {
            say!(if relay.reject_rcpt {
                "550 no such user\r\n"
            } else {
                "250 ok\r\n"
            });
        } else if upper == "DATA" {
            say!("354 end with .\r\n");
            let mut data = Vec::new();
            loop {
                let mut l = Vec::new();
                if r.read_until(b'\n', &mut l).await.unwrap_or(0) == 0 {
                    return End::Done;
                }
                if l == b".\r\n" {
                    break;
                }
                data.extend_from_slice(&l);
            }
            seen.lock().unwrap().data = data;
            say!("250 queued\r\n");
        } else if upper == "QUIT" {
            say!("221 bye\r\n");
            return End::Done;
        } else {
            say!("502 unknown\r\n");
        }
    }
}

/// Starts a relay for one connection; returns its port and what it saw.
async fn relay(relay: Relay, fx: &Fixture) -> (u16, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let acceptor = fx.acceptor.clone();
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        if relay.silent {
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(tcp);
            return;
        }
        if relay.implicit {
            let tls = acceptor.accept(tcp).await.unwrap();
            session(tls, &relay, &log, true, true).await;
            return;
        }
        if let End::Upgrade(tcp) = session(tcp, &relay, &log, false, true).await
            && let Ok(tls) = acceptor.accept(tcp).await
        {
            session(tls, &relay, &log, true, false).await;
        }
    });
    (port, seen)
}

fn client(port: u16, tls: SmtpTls) -> SmtpConfig {
    SmtpConfig::new("localhost", port, tls)
        .with_hello_name("sender.example")
        .with_timeout(Duration::from_secs(5))
}

fn message() -> EmailMessage {
    let mut m = EmailMessage::text(
        USER,
        "ops@example.com",
        "Отчёт",
        "line one\n.hidden dot line\nПривет\n",
    );
    m.cc = vec!["cc@example.com".into()];
    m.bcc = vec!["audit@example.com".into()];
    m
}

#[tokio::test]
async fn plain_relay_receives_envelope_headers_and_stuffed_body() {
    let fx = fixture();
    let (port, seen) = relay(Relay::default(), &fx).await;
    SmtpClient::new(client(port, SmtpTls::None))
        .send(&message())
        .await
        .unwrap();
    let s = seen.lock().unwrap();
    assert_eq!(
        s.commands,
        vec![
            "EHLO sender.example",
            "MAIL FROM:<robot@example.com>",
            "RCPT TO:<ops@example.com>",
            "RCPT TO:<cc@example.com>",
            "RCPT TO:<audit@example.com>",
            "DATA",
            "QUIT",
        ]
    );
    let data = String::from_utf8(s.data.clone()).unwrap();
    assert!(data.contains("To: ops@example.com\r\n"));
    assert!(data.contains("Cc: cc@example.com\r\n"));
    assert!(
        !data.contains("audit@example.com"),
        "bcc only in the envelope"
    );
    assert!(data.contains("Subject: =?UTF-8?B?"));
    assert!(
        data.contains("\r\n..hidden dot line\r\n"),
        "leading dot stuffed"
    );
    assert!(data.contains("Привет\r\n"), "UTF-8 body intact");
    assert!(
        !data.replace("\r\n", "").contains('\n'),
        "only CRLF line ends"
    );
}

#[tokio::test]
async fn starttls_then_auth_plain() {
    let fx = fixture();
    let (port, seen) = relay(
        Relay {
            starttls: true,
            auth: &["PLAIN", "LOGIN"],
            ..Relay::default()
        },
        &fx,
    )
    .await;
    SmtpClient::new(client(port, SmtpTls::Starttls).with_auth(SmtpAuth::plain(USER, PASS)))
        .with_tls_config(Arc::clone(&fx.client_tls))
        .send(&message())
        .await
        .unwrap();
    let s = seen.lock().unwrap();
    assert!(s.authenticated);
    assert_eq!(&s.commands[..2], &["EHLO sender.example", "STARTTLS"]);
    assert_eq!(
        s.commands[2], "EHLO sender.example",
        "EHLO again after the upgrade"
    );
    assert!(
        s.commands[3].starts_with("AUTH PLAIN "),
        "credentials only after TLS"
    );
    assert_eq!(s.tls_commands, s.commands.len() - 2);
}

#[tokio::test]
async fn implicit_tls_then_auth_login() {
    let fx = fixture();
    let (port, seen) = relay(
        Relay {
            implicit: true,
            auth: &["LOGIN"],
            ..Relay::default()
        },
        &fx,
    )
    .await;
    let mailer: Box<dyn Mailer> = Box::new(
        SmtpClient::new(client(port, SmtpTls::Implicit).with_auth(SmtpAuth::login(USER, PASS)))
            .with_tls_config(Arc::clone(&fx.client_tls)),
    );
    assert_eq!(mailer.name(), "smtp");
    mailer.send_message(&message()).await.unwrap();
    let s = seen.lock().unwrap();
    assert!(s.authenticated);
    assert_eq!(s.tls_commands, s.commands.len(), "every command inside TLS");
}

#[tokio::test]
async fn relay_without_starttls_is_not_a_silent_downgrade() {
    let fx = fixture();
    let (port, seen) = relay(Relay::default(), &fx).await;
    let err =
        SmtpClient::new(client(port, SmtpTls::Starttls).with_auth(SmtpAuth::plain(USER, PASS)))
            .send(&message())
            .await
            .unwrap_err();
    assert!(
        matches!(err, SmtpError::UnsupportedExt("STARTTLS")),
        "{err:?}"
    );
    let s = seen.lock().unwrap();
    assert!(
        !s.commands
            .iter()
            .any(|c| c.starts_with("AUTH") || c.starts_with("MAIL"))
    );
}

#[tokio::test]
async fn credentials_are_not_sent_in_clear_unless_allowed() {
    let fx = fixture();
    let cfg = |port| client(port, SmtpTls::None).with_auth(SmtpAuth::plain(USER, PASS));
    let (port, seen) = relay(
        Relay {
            auth: &["PLAIN"],
            ..Relay::default()
        },
        &fx,
    )
    .await;
    let err = SmtpClient::new(cfg(port))
        .send(&message())
        .await
        .unwrap_err();
    assert!(matches!(err, SmtpError::Auth(_)), "{err:?}");
    assert!(
        seen.lock().unwrap().commands.is_empty(),
        "refused before connecting"
    );

    let (port, seen) = relay(
        Relay {
            auth: &["PLAIN"],
            ..Relay::default()
        },
        &fx,
    )
    .await;
    SmtpClient::new(cfg(port).allow_plaintext_auth(true))
        .send(&message())
        .await
        .unwrap();
    assert!(seen.lock().unwrap().authenticated);
}

#[tokio::test]
async fn refusals_surface_as_errors() {
    let fx = fixture();
    let (port, _) = relay(
        Relay {
            reject_rcpt: true,
            ..Relay::default()
        },
        &fx,
    )
    .await;
    let err = SmtpClient::new(client(port, SmtpTls::None))
        .send(&message())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SmtpError::Protocol {
                expected_class: 2,
                code: 550,
                ..
            }
        ),
        "{err:?}"
    );

    let (port, _) = relay(
        Relay {
            starttls: true,
            auth: &["PLAIN"],
            ..Relay::default()
        },
        &fx,
    )
    .await;
    let err =
        SmtpClient::new(client(port, SmtpTls::Starttls).with_auth(SmtpAuth::plain(USER, "wrong")))
            .with_tls_config(Arc::clone(&fx.client_tls))
            .send(&message())
            .await
            .unwrap_err();
    assert!(matches!(err, SmtpError::Auth(_)), "{err:?}");

    let (port, _) = relay(
        Relay {
            starttls: true,
            auth: &["LOGIN"],
            ..Relay::default()
        },
        &fx,
    )
    .await;
    let err =
        SmtpClient::new(client(port, SmtpTls::Starttls).with_auth(SmtpAuth::plain(USER, PASS)))
            .with_tls_config(Arc::clone(&fx.client_tls))
            .send(&message())
            .await
            .unwrap_err();
    assert!(
        matches!(err, SmtpError::Auth(ref m) if m.contains("does not advertise")),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_untrusted_relay_certificate_fails_the_handshake() {
    let fx = fixture();
    let (port, seen) = relay(
        Relay {
            implicit: true,
            ..Relay::default()
        },
        &fx,
    )
    .await;
    // Default client: web PKI roots, which do not include the test CA.
    let err = SmtpClient::new(client(port, SmtpTls::Implicit))
        .send(&message())
        .await
        .unwrap_err();
    assert!(matches!(err, SmtpError::Tls(_)), "{err:?}");
    assert!(seen.lock().unwrap().commands.is_empty());
}

#[tokio::test]
async fn a_silent_relay_hits_the_deadline() {
    let fx = fixture();
    let (port, _) = relay(
        Relay {
            silent: true,
            ..Relay::default()
        },
        &fx,
    )
    .await;
    let err = SmtpClient::new(client(port, SmtpTls::None).with_timeout(Duration::from_millis(200)))
        .send(&message())
        .await
        .unwrap_err();
    assert!(matches!(err, SmtpError::Timeout(_)), "{err:?}");
}

#[tokio::test]
async fn injection_is_refused_before_any_io() {
    let mut m = message();
    m.to = vec!["ops@example.com>\r\nRCPT TO:<victim@example.com".into()];
    let err = SmtpClient::new(client(1, SmtpTls::None))
        .send(&m)
        .await
        .unwrap_err();
    assert!(matches!(err, SmtpError::InvalidMessage(_)), "{err:?}");
    let err = SmtpClient::new(client(1, SmtpTls::None).with_hello_name("a\r\nMAIL FROM:<x>"))
        .send(&message())
        .await
        .unwrap_err();
    assert!(matches!(err, SmtpError::InvalidMessage(_)), "{err:?}");
}

/// The TLS pieces of the fixture themselves work (guards the tests above).
#[tokio::test]
async fn fixture_tls_round_trip() {
    let fx = fixture();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let acc = fx.acceptor.clone();
    let srv = tokio::spawn(async move {
        let (t, _) = l.accept().await.unwrap();
        let mut s = acc.accept(t).await.unwrap();
        let mut b = [0u8; 2];
        s.read_exact(&mut b).await.unwrap();
        s.write_all(&b).await.unwrap();
        s.flush().await.unwrap();
    });
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut c = TlsConnector::from(Arc::clone(&fx.client_tls))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    c.write_all(b"hi").await.unwrap();
    let mut b = [0u8; 2];
    c.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"hi");
    srv.await.unwrap();
}
