//! [`SmtpClient`]: outbound ESMTP.
//!
//! Hand-written dialogue (RFC 5321, STARTTLS RFC 3207, AUTH RFC 4954) over
//! `tokio` TCP and `tokio-rustls`; no mail framework. Three transport modes:
//!
//! - [`SmtpTls::None`] — no TLS (port 25, in-LAN relays, tests). AUTH is
//!   refused in this mode unless [`SmtpConfig::allow_plaintext_auth`] is
//!   set, because the credentials would cross the network in clear.
//! - [`SmtpTls::Starttls`] — connect plain, EHLO, `STARTTLS`, upgrade, EHLO
//!   again (port 587). A server that does not advertise STARTTLS is an
//!   error, never a silent downgrade.
//! - [`SmtpTls::Implicit`] — TLS from the first byte (port 465).
//!
//! AUTH PLAIN and LOGIN. The whole send (connect, dialogue, DATA) runs
//! under [`SmtpConfig::timeout`]. One connection per message.
//!
//! ```no_run
//! use tesserax_transport::egress::{EmailMessage, Mailer, SmtpAuth, SmtpClient, SmtpConfig, SmtpTls};
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let client = SmtpClient::new(
//!     SmtpConfig::new("smtp.example.com", 587, SmtpTls::Starttls)
//!         .with_auth(SmtpAuth::plain("robot@example.com", "app-password"))
//!         .with_hello_name("host.example.com"),
//! );
//! let msg = EmailMessage::text("robot@example.com", "ops@example.com", "disk", "disk usage at 92%");
//! client.send(&msg).await?;
//! # Ok(()) }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::message::{EmailMessage, build_rfc2822};

/// Longest reply line accepted.
const MAX_LINE: usize = 8 * 1024;
/// Most lines of one multi-line reply accepted.
const MAX_REPLY_LINES: usize = 128;

/// Why a send failed.
#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    /// Stream failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// TLS setup or handshake failure.
    #[error("tls: {0}")]
    Tls(String),
    /// The host is not a valid TLS server name.
    #[error("invalid tls server name {host:?}")]
    ServerName {
        /// Configured host.
        host: String,
    },
    /// A reply of another class than the step expects.
    #[error("protocol: expected {expected_class}xx, got {code} \"{line}\"")]
    Protocol {
        /// Expected first digit.
        expected_class: u8,
        /// Received code.
        code: u16,
        /// First reply line.
        line: String,
    },
    /// AUTH failed or was refused.
    #[error("auth: {0}")]
    Auth(String),
    /// A required extension is not advertised.
    #[error("server does not advertise {0}")]
    UnsupportedExt(&'static str),
    /// A reply line that is not SMTP.
    #[error("invalid response line: {0}")]
    InvalidResponse(String),
    /// The message or configuration would inject commands or headers.
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    /// The overall deadline passed.
    #[error("timeout: {0}")]
    Timeout(&'static str),
}

/// Transport security of the connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmtpTls {
    /// No TLS.
    None,
    /// Plain connect, then `STARTTLS`.
    Starttls,
    /// TLS from the first byte.
    Implicit,
}

/// Credentials. `Debug` never shows the password.
#[derive(Clone)]
pub enum SmtpAuth {
    /// SASL PLAIN: `\0user\0password`, base64.
    Plain {
        /// User name.
        username: String,
        /// Password.
        password: String,
    },
    /// LOGIN: user and password in two base64 round trips.
    Login {
        /// User name.
        username: String,
        /// Password.
        password: String,
    },
}

impl SmtpAuth {
    /// SASL PLAIN.
    pub fn plain(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Plain {
            username: username.into(),
            password: password.into(),
        }
    }

    /// LOGIN.
    pub fn login(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Login {
            username: username.into(),
            password: password.into(),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            SmtpAuth::Plain { .. } => "PLAIN",
            SmtpAuth::Login { .. } => "LOGIN",
        }
    }
}

impl std::fmt::Debug for SmtpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, username) = match self {
            SmtpAuth::Plain { username, .. } => ("Plain", username),
            SmtpAuth::Login { username, .. } => ("Login", username),
        };
        f.debug_struct(kind)
            .field("username", username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Where and how to send.
#[derive(Clone, Debug)]
pub struct SmtpConfig {
    /// Relay host name (also the TLS server name).
    pub host: String,
    /// Relay port.
    pub port: u16,
    /// Transport security.
    pub tls: SmtpTls,
    /// Credentials, if the relay needs them.
    pub auth: Option<SmtpAuth>,
    /// Name sent in EHLO; some relays want a FQDN (default `localhost`).
    pub hello_name: String,
    /// Deadline of one whole send (default 30 s).
    pub timeout: Duration,
    /// Allow AUTH over [`SmtpTls::None`] (default false).
    pub allow_plaintext_auth: bool,
}

impl SmtpConfig {
    /// `host:port` with `tls`, no auth, EHLO `localhost`, 30 s.
    pub fn new(host: impl Into<String>, port: u16, tls: SmtpTls) -> Self {
        Self {
            host: host.into(),
            port,
            tls,
            auth: None,
            hello_name: "localhost".into(),
            timeout: Duration::from_secs(30),
            allow_plaintext_auth: false,
        }
    }

    /// Sets credentials.
    pub fn with_auth(mut self, auth: SmtpAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Sets the EHLO name.
    pub fn with_hello_name(mut self, n: impl Into<String>) -> Self {
        self.hello_name = n.into();
        self
    }

    /// Sets the per-send deadline.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Permits AUTH without TLS (in-LAN relays only).
    pub fn allow_plaintext_auth(mut self, allow: bool) -> Self {
        self.allow_plaintext_auth = allow;
        self
    }
}

/// Outbound SMTP mailer. Cheap to clone.
#[derive(Clone)]
pub struct SmtpClient {
    cfg: Arc<SmtpConfig>,
    tls: Result<Arc<ClientConfig>, String>,
}

impl SmtpClient {
    /// A client verifying relay certificates against the bundled web PKI
    /// roots.
    pub fn new(cfg: SmtpConfig) -> Self {
        Self {
            cfg: Arc::new(cfg),
            tls: default_tls_config()
                .map(Arc::new)
                .map_err(|e| e.to_string()),
        }
    }

    /// Replaces the TLS client configuration (a private CA, a pinned
    /// relay).
    pub fn with_tls_config(mut self, tls: Arc<ClientConfig>) -> Self {
        self.tls = Ok(tls);
        self
    }

    /// The configuration.
    pub fn config(&self) -> &SmtpConfig {
        &self.cfg
    }

    /// Sends one message over a fresh connection.
    pub async fn send(&self, msg: &EmailMessage) -> Result<(), SmtpError> {
        let raw = build_rfc2822(msg)?;
        let hello = &self.cfg.hello_name;
        if hello.is_empty() || hello.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(SmtpError::InvalidMessage(format!(
                "EHLO name {hello:?} is empty or contains a control or space"
            )));
        }
        if self.cfg.auth.is_some()
            && self.cfg.tls == SmtpTls::None
            && !self.cfg.allow_plaintext_auth
        {
            return Err(SmtpError::Auth(
                "refusing to send credentials without TLS (see SmtpConfig::allow_plaintext_auth)"
                    .into(),
            ));
        }
        tokio::time::timeout(self.cfg.timeout, self.dialogue(msg, &raw))
            .await
            .map_err(|_| SmtpError::Timeout("send overall deadline"))?
    }

    async fn dialogue(&self, msg: &EmailMessage, raw: &str) -> Result<(), SmtpError> {
        let tcp = TcpStream::connect((self.cfg.host.as_str(), self.cfg.port))
            .await
            .inspect_err(|e| {
                tracing::warn!(host = %self.cfg.host, port = self.cfg.port, "smtp connect: {e}");
            })?;
        let _ = tcp.set_nodelay(true);

        match self.cfg.tls {
            SmtpTls::None => {
                let mut s = Session(tcp);
                s.greeting().await?;
                self.transact(&mut s, msg, raw).await
            }
            SmtpTls::Implicit => {
                let mut s = Session(self.handshake(tcp).await?);
                s.greeting().await?;
                self.transact(&mut s, msg, raw).await
            }
            SmtpTls::Starttls => {
                let mut plain = Session(tcp);
                plain.greeting().await?;
                let exts = plain.ehlo(&self.cfg.hello_name).await?;
                if !exts.has("STARTTLS") {
                    return Err(SmtpError::UnsupportedExt("STARTTLS"));
                }
                plain.write_line("STARTTLS").await?;
                plain.read_response().await?.expect(2)?;
                let mut s = Session(self.handshake(plain.0).await?);
                self.transact(&mut s, msg, raw).await
            }
        }
    }

    /// EHLO, AUTH, envelope, DATA, QUIT on an established session.
    async fn transact<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        s: &mut Session<S>,
        msg: &EmailMessage,
        raw: &str,
    ) -> Result<(), SmtpError> {
        let exts = s.ehlo(&self.cfg.hello_name).await?;
        if let Some(auth) = &self.cfg.auth {
            s.auth(&exts, auth).await?;
        }
        s.write_line(&format!("MAIL FROM:<{}>", msg.from)).await?;
        s.read_response().await?.expect(2)?;
        for rcpt in msg.recipients() {
            s.write_line(&format!("RCPT TO:<{rcpt}>")).await?;
            s.read_response().await?.expect(2)?;
        }
        s.write_line("DATA").await?;
        s.read_response().await?.expect(3)?;
        let mut data = dot_stuff(raw.as_bytes());
        if !data.ends_with(b"\r\n") {
            data.extend_from_slice(b"\r\n");
        }
        data.extend_from_slice(b".\r\n");
        s.0.write_all(&data).await?;
        s.0.flush().await?;
        s.read_response().await?.expect(2)?;
        // QUIT is best-effort: the message is already accepted.
        let _ = s.write_line("QUIT").await;
        let _ = s.read_response().await;
        Ok(())
    }

    async fn handshake(
        &self,
        tcp: TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, SmtpError> {
        let config = self.tls.clone().map_err(SmtpError::Tls)?;
        let name =
            ServerName::try_from(self.cfg.host.clone()).map_err(|_| SmtpError::ServerName {
                host: self.cfg.host.clone(),
            })?;
        TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(|e| SmtpError::Tls(e.to_string()))
    }
}

impl std::fmt::Debug for SmtpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpClient")
            .field("cfg", &self.cfg)
            .finish()
    }
}

fn default_tls_config() -> Result<ClientConfig, rustls::Error> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// One SMTP connection, plain or TLS.
struct Session<S>(S);

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    async fn write_line(&mut self, line: &str) -> Result<(), SmtpError> {
        self.0.write_all(line.as_bytes()).await?;
        self.0.write_all(b"\r\n").await?;
        self.0.flush().await?;
        Ok(())
    }

    async fn read_response(&mut self) -> Result<SmtpResponse, SmtpError> {
        read_response_inner(&mut self.0).await
    }

    async fn greeting(&mut self) -> Result<(), SmtpError> {
        self.read_response().await?.expect(2)
    }

    async fn ehlo(&mut self, hello_name: &str) -> Result<SmtpExtensions, SmtpError> {
        self.write_line(&format!("EHLO {hello_name}")).await?;
        let resp = self.read_response().await?;
        resp.expect(2)?;
        Ok(SmtpExtensions::parse(&resp.lines))
    }

    async fn auth(&mut self, exts: &SmtpExtensions, auth: &SmtpAuth) -> Result<(), SmtpError> {
        let mech = auth.name();
        if !exts.advertises_auth(mech) {
            return Err(SmtpError::Auth(format!(
                "server does not advertise AUTH {mech} (offers: {})",
                exts.auth_mechanisms.join(",")
            )));
        }
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        match auth {
            SmtpAuth::Plain { username, password } => {
                let mut raw = Vec::with_capacity(2 + username.len() + password.len());
                raw.push(0u8);
                raw.extend_from_slice(username.as_bytes());
                raw.push(0u8);
                raw.extend_from_slice(password.as_bytes());
                self.write_line(&format!("AUTH PLAIN {}", b64(&raw)))
                    .await?;
                let r = self.read_response().await?;
                if r.code != 235 {
                    return Err(SmtpError::Auth(format!(
                        "AUTH PLAIN rejected: {} {}",
                        r.code, r.first_line
                    )));
                }
            }
            SmtpAuth::Login { username, password } => {
                self.write_line("AUTH LOGIN").await?;
                for (step, value) in [
                    ("start", None),
                    ("username", Some(username)),
                    ("password", Some(password)),
                ] {
                    if let Some(v) = value {
                        self.write_line(&b64(v.as_bytes())).await?;
                    }
                    let r = self.read_response().await?;
                    let want = if step == "password" { 235 } else { 334 };
                    if r.code != want {
                        return Err(SmtpError::Auth(format!(
                            "AUTH LOGIN {step}: {} {}",
                            r.code, r.first_line
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

async fn read_response_inner<R: AsyncRead + Unpin>(r: &mut R) -> Result<SmtpResponse, SmtpError> {
    // One or more lines "NNN-text", the last "NNN text".
    let mut lines: Vec<String> = Vec::with_capacity(2);
    let mut code: u16 = 0;
    loop {
        let line = read_crlf_line(r).await?;
        if line.len() < 4 || !line.is_char_boundary(3) {
            return Err(SmtpError::InvalidResponse(line));
        }
        let (digits, rest) = line.split_at(3);
        let c: u16 = digits
            .parse()
            .map_err(|_| SmtpError::InvalidResponse(format!("non-numeric code: {line}")))?;
        if code == 0 {
            code = c;
        } else if c != code {
            return Err(SmtpError::InvalidResponse(format!(
                "multi-line code mismatch: {code} then {c}"
            )));
        }
        let last = !rest.starts_with('-');
        lines.push(rest.get(1..).unwrap_or("").to_owned());
        if last {
            break;
        }
        if lines.len() >= MAX_REPLY_LINES {
            return Err(SmtpError::InvalidResponse(format!(
                "reply longer than {MAX_REPLY_LINES} lines"
            )));
        }
    }
    let first_line = lines.first().cloned().unwrap_or_default();
    Ok(SmtpResponse {
        code,
        first_line,
        lines,
    })
}

/// One CRLF-terminated line, read byte by byte so nothing past the line is
/// consumed (the plain stream is handed to TLS after STARTTLS).
async fn read_crlf_line<R: AsyncRead + Unpin>(r: &mut R) -> Result<String, SmtpError> {
    let mut out = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await?;
        if n == 0 {
            return Err(SmtpError::InvalidResponse(format!(
                "eof at byte {}",
                out.len()
            )));
        }
        out.push(byte[0]);
        if out.ends_with(b"\r\n") {
            out.truncate(out.len() - 2);
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        if out.len() > MAX_LINE {
            return Err(SmtpError::InvalidResponse("line > 8 KiB".into()));
        }
    }
}

/// One SMTP reply.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SmtpResponse {
    /// Reply code.
    pub code: u16,
    /// Text of the first line.
    pub first_line: String,
    /// Text of every line.
    pub lines: Vec<String>,
}

impl SmtpResponse {
    /// `Ok` if the code's first digit is `expected_class`.
    pub fn expect(&self, expected_class: u8) -> Result<(), SmtpError> {
        if self.code / 100 != u16::from(expected_class) {
            return Err(SmtpError::Protocol {
                expected_class,
                code: self.code,
                line: self.first_line.clone(),
            });
        }
        Ok(())
    }
}

/// The extensions an EHLO reply advertises.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct SmtpExtensions {
    /// Every reply line.
    pub raw: Vec<String>,
    /// Mechanisms of the `AUTH` line, upper-cased.
    pub auth_mechanisms: Vec<String>,
}

impl SmtpExtensions {
    fn parse(lines: &[String]) -> Self {
        let mut auth_mechanisms = Vec::new();
        for line in lines {
            let upper = line.to_ascii_uppercase();
            if let Some(rest) = upper.strip_prefix("AUTH ") {
                auth_mechanisms.extend(rest.split_whitespace().map(str::to_owned));
            }
        }
        Self {
            raw: lines.to_vec(),
            auth_mechanisms,
        }
    }

    /// True if a line starts with the keyword `ext` (any case).
    pub fn has(&self, ext: &str) -> bool {
        self.raw.iter().any(|l| {
            let kw = l.split_whitespace().next().unwrap_or("");
            kw.eq_ignore_ascii_case(ext)
        })
    }

    /// True if `AUTH` lists `mech` (any case).
    pub fn advertises_auth(&self, mech: &str) -> bool {
        self.auth_mechanisms
            .iter()
            .any(|m| m.eq_ignore_ascii_case(mech))
    }
}

/// DATA transparency (RFC 5321 §4.5.2): every line break (CRLF, bare LF or
/// bare CR) becomes CRLF and a line starting with `.` gets one more.
/// Works on bytes, so UTF-8 text passes unchanged.
fn dot_stuff(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + s.len() / 64 + 2);
    let mut at_line_start = true;
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b == b'\r' || b == b'\n' {
            out.extend_from_slice(b"\r\n");
            if b == b'\r' && s.get(i + 1) == Some(&b'\n') {
                i += 1;
            }
            at_line_start = true;
        } else {
            if at_line_start && b == b'.' {
                out.push(b'.');
            }
            out.push(b);
            at_line_start = false;
        }
        i += 1;
    }
    out
}

/// Boxed future of [`Mailer::send_message`].
pub type MailFuture<'a> = Pin<Box<dyn Future<Output = Result<(), MailError>> + Send + 'a>>;

/// One shape over mail backends, so a caller can hold a `Box<dyn Mailer>`
/// and swap the backend without touching call sites.
pub trait Mailer: Send + Sync {
    /// Sends `msg`.
    fn send_message<'a>(&'a self, msg: &'a EmailMessage) -> MailFuture<'a>;
    /// Backend name for logs.
    fn name(&self) -> &'static str;
}

/// Why a [`Mailer`] failed.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// The SMTP backend failed.
    #[error("smtp: {0}")]
    Smtp(#[from] SmtpError),
    /// Another backend failed.
    #[error("{backend}: {source}")]
    Backend {
        /// Backend name.
        backend: &'static str,
        /// Cause.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl Mailer for SmtpClient {
    fn send_message<'a>(&'a self, msg: &'a EmailMessage) -> MailFuture<'a> {
        Box::pin(async move { Ok(self.send(msg).await?) })
    }

    fn name(&self) -> &'static str {
        "smtp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stuffed(s: &str) -> String {
        String::from_utf8(dot_stuff(s.as_bytes())).unwrap()
    }

    #[test]
    fn dot_stuff_leading_dot() {
        let s = stuffed(".start\r\n.more\r\nplain\r\n");
        assert!(s.starts_with(".."));
        assert!(s.contains("\r\n..more"));
        assert!(s.contains("\r\nplain"));
    }

    #[test]
    fn dot_stuff_normalises_lf_and_cr() {
        let s = stuffed("line1\nline2\n");
        assert_eq!(s, "line1\r\nline2\r\n");
        assert_eq!(stuffed("a\rb\r\n.c"), "a\r\nb\r\n..c");
    }

    #[test]
    fn dot_stuff_preserves_clean_text_and_utf8() {
        assert_eq!(stuffed("hello\r\nworld\r\n"), "hello\r\nworld\r\n");
        assert_eq!(stuffed("Привет, мир\n.ü"), "Привет, мир\r\n..ü");
    }

    #[test]
    fn smtp_response_expect_class() {
        let r = SmtpResponse {
            code: 250,
            first_line: "ok".into(),
            lines: vec!["ok".into()],
        };
        assert!(r.expect(2).is_ok());
        assert!(r.expect(3).is_err());
    }

    #[test]
    fn extensions_parse_auth_list() {
        let lines = vec![
            "smtp.example.com Hello you".to_string(),
            "SIZE 35882577".to_string(),
            "AUTH PLAIN LOGIN XOAUTH2".to_string(),
            "STARTTLS".to_string(),
        ];
        let exts = SmtpExtensions::parse(&lines);
        assert!(exts.has("STARTTLS"));
        assert!(exts.has("SIZE"));
        assert!(exts.advertises_auth("PLAIN"));
        assert!(exts.advertises_auth("LOGIN"));
        assert!(exts.advertises_auth("XOAUTH2"));
        assert!(!exts.advertises_auth("CRAM-MD5"));
    }

    #[test]
    fn extensions_has_matches_whole_keywords_case_insensitive() {
        let exts = SmtpExtensions::parse(&["starttls".to_string(), "SIZEX 1".to_string()]);
        assert!(exts.has("STARTTLS"));
        assert!(exts.has("starttls"));
        assert!(
            !exts.has("SIZE"),
            "a prefix of another keyword is not the keyword"
        );
    }

    #[test]
    fn config_builder_chain() {
        let c = SmtpConfig::new("smtp.example.com", 587, SmtpTls::Starttls)
            .with_auth(SmtpAuth::plain("u", "p"))
            .with_hello_name("host.example.com")
            .with_timeout(Duration::from_secs(10));
        assert_eq!(c.host, "smtp.example.com");
        assert_eq!(c.port, 587);
        assert_eq!(c.tls, SmtpTls::Starttls);
        assert!(c.auth.is_some());
        assert_eq!(c.hello_name, "host.example.com");
        assert_eq!(c.timeout, Duration::from_secs(10));
        assert!(!c.allow_plaintext_auth);
    }

    #[test]
    fn auth_debug_redacts_password() {
        for a in [
            SmtpAuth::plain("user", "supersecret"),
            SmtpAuth::login("user", "supersecret"),
        ] {
            let s = format!("{a:?}");
            assert!(s.contains("user"));
            assert!(!s.contains("supersecret"));
            assert!(s.contains("redacted"));
        }
    }

    #[tokio::test]
    async fn read_response_single_line() {
        let raw = b"220 smtp.example.com ESMTP ready\r\n";
        let resp = read_response_inner(&mut &raw[..]).await.unwrap();
        assert_eq!(resp.code, 220);
        assert_eq!(resp.lines.len(), 1);
        assert!(resp.first_line.contains("ESMTP"));
    }

    #[tokio::test]
    async fn read_response_multi_line() {
        let raw = b"250-smtp.example.com Hello\r\n250-SIZE 35882577\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n";
        let resp = read_response_inner(&mut &raw[..]).await.unwrap();
        assert_eq!(resp.code, 250);
        assert_eq!(resp.lines.len(), 4);
        let exts = SmtpExtensions::parse(&resp.lines);
        assert!(exts.advertises_auth("PLAIN"));
        assert!(exts.has("STARTTLS"));
    }

    #[tokio::test]
    async fn read_response_errors() {
        for raw in [
            &b"55\r\n"[..],
            b"abc ok\r\n",
            b"220 no crlf",
            b"250-a\r\n251 b\r\n",
        ] {
            let err = read_response_inner(&mut &raw[..]).await.unwrap_err();
            assert!(
                matches!(err, SmtpError::InvalidResponse(_)),
                "{raw:?}: {err:?}"
            );
        }
        let endless = b"250-x\r\n".repeat(MAX_REPLY_LINES + 1);
        let err = read_response_inner(&mut endless.as_slice())
            .await
            .unwrap_err();
        assert!(matches!(err, SmtpError::InvalidResponse(_)));
    }

    #[test]
    fn client_constructs_without_panic() {
        let c = SmtpClient::new(SmtpConfig::new("smtp.example.com", 587, SmtpTls::Starttls));
        let s = format!("{c:?}");
        assert!(s.contains("smtp.example.com"));
        assert!(c.tls.is_ok());
    }
}
