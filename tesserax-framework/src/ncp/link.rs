//! The one client of the NCP module — [`DownLink`], and it only points
//! DOWN — plus the accepting half of a link ([`AttachListener`]) for
//! entries whose [`Reach`](crate::ncp::Reach) is `AcceptIn`.
//!
//! There is deliberately no other client constructor in `ncp`: nothing a
//! tier builds can address the tier above (NCP §11c — absence, not
//! policy).
//!
//! Wire notes: requests are plain HTTP/1.1 (over a network put TLS in
//! front; on one host prefer the owner-only local socket, which the same
//! HTTP bytes cross). Attach admission is a mutual
//! [`link_proof`](tesserax_transport::proof::link_proof) exchange; neither
//! side sends application data before its peer's proof matched.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::Stream;
use http_body_util::{BodyExt, Full};
/// The request method of [`DownLink::raw`], re-exported so callers and
/// the passthrough allow-list do not need their own dependency for it.
pub use hyper::Method;
use hyper::Request;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderValue};
use serde_json::Value;
use tesserax_transport::proof::{
    LinkContext, LinkRole, NONCE_BYTES, PROOF_BYTES, link_proof, proofs_match, random_nonce,
};
use tesserax_transport::{Endpoint, TransportError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use super::LinkSpec;
use super::roster::{EntryId, LinkTarget, Reach, Roster};

/// Default per-request timeout of a down link.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(8);
/// Default response body cap of a down link.
pub const DEFAULT_MAX_BODY: usize = 8 * 1024 * 1024;
/// Role byte bound into the attach proof: "I am a rostered entry of the
/// tier below" — the only role an attach link carries.
pub const ATTACH_ROLE: u8 = 1;

/// A raw response of a down link: status, content type, bounded body.
#[derive(Clone, Debug)]
pub struct RawResponse {
    /// HTTP status code.
    pub status: u16,
    /// The response's content type, if the peer sent one.
    pub content_type: Option<String>,
    /// The response body (capped at construction).
    pub body: Bytes,
}

/// Incarnation of a link to one entry: bumps when the entry is recreated,
/// so a cursor from before the recreation is known to be stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Incarnation(pub u64);

/// Where an event stream resumes: after this sequence, at this
/// incarnation (`None` = any).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkCursor {
    /// Last sequence the caller has durably seen.
    pub after_sequence: u64,
    /// The incarnation the cursor belongs to, if known.
    pub incarnation: Option<Incarnation>,
}

/// One item of a down-link event stream.
#[derive(Clone, Debug)]
pub struct LinkEvent {
    /// What this item is.
    pub kind: LinkEventKind,
}

/// The kinds a down-link event stream yields.
#[derive(Clone, Debug)]
pub enum LinkEventKind {
    /// A sequenced event from the entry.
    Event {
        /// The event's sequence (`id:` of the SSE frame).
        sequence: u64,
        /// The event payload (`data:` of the SSE frame).
        data: Bytes,
    },
    /// The peer asks consumers to resync (`event: resync`).
    ResyncNotice {
        /// The notice payload, if any.
        data: Bytes,
    },
    /// A gap in the sequence was observed: the caller should resync
    /// through the root `swc` (`ResyncReply`) instead of trusting the
    /// stream from here on.
    Gap {
        /// The sequence that should have come next.
        expected: u64,
        /// The sequence that actually arrived.
        got: u64,
    },
}

/// How using a down link fails.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LinkError {
    /// The endpoint scheme is not served by this client (https: terminate
    /// TLS in front; ws: no websocket client here).
    #[error("unsupported endpoint: {0}")]
    Unsupported(String),
    /// The endpoint URL could not be parsed for dialling.
    #[error("bad endpoint {endpoint}: {reason}")]
    BadEndpoint {
        /// The endpoint string.
        endpoint: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The credential source did not resolve.
    #[error("credential: {0}")]
    Credential(#[from] super::roster::RosterError),
    /// I/O on the link.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The HTTP layer failed.
    #[error("http: {0}")]
    Http(String),
    /// The peer answered past the per-request timeout.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    /// The body grew past the cap.
    #[error("body larger than {0} bytes")]
    BodyTooLarge(usize),
    /// The response was not the JSON the caller asked for.
    #[error("json: {0}")]
    Json(String),
}

/// The only client type in the module, and it only points DOWN.
///
/// One per roster entry: built from a [`LinkTarget`] (endpoint +
/// credential source), it carries the resolved token in a
/// [`Zeroizing`] and never logs it. Requests are one HTTP/1.1 exchange
/// per call over TCP ([`Endpoint::Http`]) or the owner-only local socket
/// ([`Endpoint::Local`], unix only for now — the Windows named-pipe
/// client half lands with the Windows team).
#[derive(Clone)]
pub struct DownLink {
    id: EntryId,
    endpoint: Endpoint,
    token: Arc<Zeroizing<String>>,
    timeout: Duration,
    max_body: usize,
}

impl std::fmt::Debug for DownLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownLink")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl DownLink {
    /// Builds the link for `target`, resolving its credential through the
    /// process environment.
    pub fn new(target: &impl LinkTarget) -> Result<Self, LinkError> {
        Self::resolve(target, &|name| std::env::var(name).ok())
    }

    /// Builds the link for `target` with the environment injected (the
    /// pure form; tests never touch the process environment).
    pub fn resolve(
        target: &impl LinkTarget,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, LinkError> {
        let token = target.credential().resolve(target.id(), env)?;
        Ok(Self::with_token(
            target.id().clone(),
            target.endpoint().clone(),
            token,
        ))
    }

    /// Builds the link with an explicit token — the constructor for
    /// [`CredentialSource::Derived`](super::roster::CredentialSource::Derived) entries, whose token the caller
    /// derives from the principal secret it holds.
    pub fn with_token(id: EntryId, endpoint: Endpoint, token: Zeroizing<String>) -> Self {
        Self {
            id,
            endpoint,
            token: Arc::new(token),
            timeout: DEFAULT_TIMEOUT,
            max_body: DEFAULT_MAX_BODY,
        }
    }

    /// Sets the per-request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the response body cap.
    pub fn max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    /// The roster id this link addresses.
    pub fn id(&self) -> &EntryId {
        &self.id
    }

    /// The endpoint this link dials.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// One HTTP exchange against the entry. `query` pairs are
    /// percent-encoded before joining — a value containing `&` or `=`
    /// can no longer inject parameters into the call (defect N1 of the
    /// moved code).
    pub async fn raw(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&[u8]>,
        ct: Option<&str>,
    ) -> Result<RawResponse, LinkError> {
        let mut target = self.request_target(path, query)?;
        let base = self.base_path()?;
        if !base.is_empty() {
            target = format!("{}{}", base.trim_end_matches('/'), target);
        }
        let body = Bytes::copy_from_slice(body.unwrap_or(&[]));
        let mut request = Request::builder().method(method).uri(target);
        request = request.header(header::HOST, self.host_header()?);
        let auth = HeaderValue::from_str(&format!("Bearer {}", self.token.as_str()))
            .map_err(|_| LinkError::Http("token is not a header value".into()))?;
        // auth is sensitive: never printed, never logged.
        request = request.header(header::AUTHORIZATION, auth);
        if let Some(ct) = ct {
            request = request.header(header::CONTENT_TYPE, ct);
        }
        let request = request
            .body(Full::new(body))
            .map_err(|e| LinkError::Http(e.to_string()))?;

        let exchange = async {
            let mut sender = self.connect().await?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|e| LinkError::Http(e.to_string()))?;
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|e| LinkError::Http(e.to_string()))?
                .to_bytes();
            if body.len() > self.max_body {
                return Err(LinkError::BodyTooLarge(self.max_body));
            }
            Ok(RawResponse {
                status,
                content_type,
                body,
            })
        };
        match tokio::time::timeout(self.timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(LinkError::Timeout(self.timeout)),
        }
    }

    /// GET expecting a JSON body; the status rides along so callers can
    /// tell "unreachable" from "answered an error".
    pub async fn get_json(&self, path: &str) -> Result<(u16, Value), LinkError> {
        let response = self.raw(Method::GET, path, &[], None, None).await?;
        let value: Value =
            serde_json::from_slice(&response.body).map_err(|e| LinkError::Json(e.to_string()))?;
        Ok((response.status, value))
    }

    /// POST a JSON body, expecting a JSON body back.
    pub async fn post_json(&self, path: &str, body: &Value) -> Result<(u16, Value), LinkError> {
        let bytes = serde_json::to_vec(body).map_err(|e| LinkError::Json(e.to_string()))?;
        let response = self
            .raw(
                Method::POST,
                path,
                &[],
                Some(&bytes),
                Some("application/json"),
            )
            .await?;
        let value: Value =
            serde_json::from_slice(&response.body).map_err(|e| LinkError::Json(e.to_string()))?;
        Ok((response.status, value))
    }

    /// The entry's health over the link this tier already holds — the
    /// only door supervision gets (NCP §11c: a second door for the same
    /// question is a second door).
    pub async fn health(&self) -> Result<Value, LinkError> {
        let (status, value) = self.get_json("/health").await?;
        if status != 200 {
            return Err(LinkError::Http(format!("/health answered {status}")));
        }
        Ok(value)
    }

    /// The event stream of the entry (`GET <base>/v1/events?after=N`,
    /// SSE with `id:` = sequence). A sequence gap surfaces as
    /// [`LinkEventKind::Gap`] — the caller resyncs through the root `swc`
    /// (`ResyncReply`); automatic resync inside the stream is the
    /// shell's `RemoteHandle` job (B8b), not this raw client's.
    pub fn events(&self, cursor: LinkCursor) -> impl Stream<Item = LinkEvent> + Send {
        let this = self.clone();
        futures_util::stream::unfold(
            (Vec::new(), cursor.after_sequence, false),
            move |(mut pending, mut next, mut started)| {
                let this = this.clone();
                async move {
                    if !started {
                        match this.open_event_stream(next).await {
                            Ok(items) => pending = items,
                            Err(_) => pending = Vec::new(),
                        }
                        started = true;
                    }
                    let mut rest = pending.into_iter();
                    match rest.next() {
                        Some(event) => {
                            if let LinkEventKind::Event { sequence, .. } = event.kind {
                                next = sequence;
                            }
                            let remaining: Vec<LinkEvent> = rest.collect();
                            Some((event, (remaining, next, started)))
                        }
                        None => None,
                    }
                }
            },
        )
    }

    /// Reads the event stream to its end (or the timeout) and parses the
    /// SSE frames. Kept eager: the oracle and the attach tests consume
    /// bounded streams; a live tail is the shell's job.
    async fn open_event_stream(&self, after: u64) -> Result<Vec<LinkEvent>, LinkError> {
        let path = format!("/v1/events?after={after}");
        let response = self.raw(Method::GET, &path, &[], None, None).await?;
        if response.status != 200 {
            return Err(LinkError::Http(format!(
                "/v1/events answered {}",
                response.status
            )));
        }
        Ok(parse_sse(&response.body))
    }

    fn request_target(&self, path: &str, query: &[(&str, &str)]) -> Result<String, LinkError> {
        if !path.starts_with('/') {
            return Err(LinkError::BadEndpoint {
                endpoint: path.to_owned(),
                reason: "request path must start with '/'".into(),
            });
        }
        let mut target = path.to_owned();
        if !query.is_empty() {
            target.push('?');
            for (i, (name, value)) in query.iter().enumerate() {
                if i > 0 {
                    target.push('&');
                }
                target.push_str(&pct_encode(name));
                target.push('=');
                target.push_str(&pct_encode(value));
            }
        }
        Ok(target)
    }

    fn base_path(&self) -> Result<String, LinkError> {
        match &self.endpoint {
            Endpoint::Http(url) | Endpoint::Ws(url) => {
                let (_, rest) = split_authority(url)?;
                Ok(rest)
            }
            Endpoint::Local(_) => Ok(String::new()),
        }
    }

    fn host_header(&self) -> Result<String, LinkError> {
        match &self.endpoint {
            Endpoint::Http(url) | Endpoint::Ws(url) => {
                let (authority, _) = split_authority(url)?;
                Ok(authority)
            }
            Endpoint::Local(_) => Ok("localhost".to_owned()),
        }
    }

    async fn connect(&self) -> Result<SendRequest<Full<Bytes>>, LinkError> {
        match &self.endpoint {
            Endpoint::Http(url) => {
                let (scheme_ok, authority) = match split_authority(url) {
                    Ok((authority, _)) => {
                        (!url.to_ascii_lowercase().starts_with("https://"), authority)
                    }
                    Err(e) => return Err(e),
                };
                if !scheme_ok {
                    return Err(LinkError::Unsupported(
                        "https: terminate TLS in front, or use the local link".into(),
                    ));
                }
                let addr = authority
                    .rsplit_once('@')
                    .map(|(_, a)| a)
                    .unwrap_or(authority.as_str());
                // A bare host means the scheme default; plain HTTP only.
                let addr = if addr.contains(':') {
                    addr.to_owned()
                } else {
                    format!("{addr}:80")
                };
                let tcp = TcpStream::connect(addr).await?;
                tcp.set_nodelay(true)?;
                let (sender, conn) =
                    hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp))
                        .await
                        .map_err(|e| LinkError::Http(e.to_string()))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok(sender)
            }
            Endpoint::Local(path) => local_connect(path.as_path()).await,
            Endpoint::Ws(url) => Err(LinkError::Unsupported(format!(
                "ws: no websocket client in ncp ({url})"
            ))),
        }
    }
}

/// Percent-encodes `text` for a query name or value: unreserved bytes
/// (RFC 3986) pass through, everything else is `%XX`.
fn pct_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Splits `scheme://authority/rest`; the scheme is only checked to be
/// present, the caller decides which schemes it serves.
fn split_authority(url: &str) -> Result<(String, String), LinkError> {
    let bad = |reason: &str| LinkError::BadEndpoint {
        endpoint: url.to_owned(),
        reason: reason.to_owned(),
    };
    let after_scheme = url
        .find("://")
        .map(|i| &url[i + 3..])
        .ok_or_else(|| bad("no scheme"))?;
    let (authority, rest) = match after_scheme.find(['/', '?', '#']) {
        Some(i) => (&after_scheme[..i], &after_scheme[i..]),
        None => (after_scheme, ""),
    };
    if authority.is_empty() {
        return Err(bad("URL has no host"));
    }
    Ok((authority.to_owned(), rest.to_owned()))
}

#[cfg(unix)]
async fn local_connect(path: &std::path::Path) -> Result<SendRequest<Full<Bytes>>, LinkError> {
    let stream = tesserax_transport::local::connect_local(path)
        .await
        .map_err(LinkError::Io)?;
    let (sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|e| LinkError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

#[cfg(windows)]
async fn local_connect(_path: &std::path::Path) -> Result<SendRequest<Full<Bytes>>, LinkError> {
    // The named-pipe client half lands with the Windows team (the server
    // half already lives in tesserax-transport).
    Err(LinkError::Unsupported(
        "local endpoint client on Windows: not yet implemented".into(),
    ))
}

/// Parses a bounded SSE body into link events, flagging sequence gaps.
fn parse_sse(body: &[u8]) -> Vec<LinkEvent> {
    let text = String::from_utf8_lossy(body);
    let mut events = Vec::new();
    let mut id: Option<u64> = None;
    let mut event_line: Option<String> = None;
    let mut data = String::new();
    let mut next_expected: Option<u64> = None;
    let flush = |id: &mut Option<u64>,
                 event_line: &mut Option<String>,
                 data: &mut String,
                 events: &mut Vec<LinkEvent>,
                 next_expected: &mut Option<u64>| {
        if data.is_empty() && event_line.is_none() {
            *id = None;
            return;
        }
        let payload = Bytes::copy_from_slice(data.trim_end_matches('\n').as_bytes());
        match event_line.as_deref() {
            Some("resync") => events.push(LinkEvent {
                kind: LinkEventKind::ResyncNotice { data: payload },
            }),
            _ => {
                if let Some(sequence) = *id {
                    if let Some(expected) = *next_expected
                        && sequence != expected
                    {
                        events.push(LinkEvent {
                            kind: LinkEventKind::Gap {
                                expected,
                                got: sequence,
                            },
                        });
                    }
                    *next_expected = Some(sequence + 1);
                    events.push(LinkEvent {
                        kind: LinkEventKind::Event {
                            sequence,
                            data: payload,
                        },
                    });
                }
            }
        }
        *id = None;
        *event_line = None;
        data.clear();
    };
    for line in text.lines() {
        if line.is_empty() {
            flush(
                &mut id,
                &mut event_line,
                &mut data,
                &mut events,
                &mut next_expected,
            );
        } else if let Some(value) = line.strip_prefix("id:") {
            id = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("event:") {
            event_line = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push_str(value.strip_prefix(' ').unwrap_or(value));
            data.push('\n');
        }
    }
    flush(
        &mut id,
        &mut event_line,
        &mut data,
        &mut events,
        &mut next_expected,
    );
    events
}

// ── attach (AcceptIn admission) ─────────────────────────────────────────

/// How attach admission fails.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttachError {
    /// The listener could not be set up.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A credential of an `AcceptIn` entry did not resolve at bind time.
    #[error("credential: {0}")]
    Credential(#[from] super::roster::RosterError),
    /// The accept / dial endpoint string could not be parsed.
    #[error("endpoint: {0}")]
    BadEndpoint(String),
    /// The dialling id is not on the roster — nothing is constructed for
    /// it, the link is dropped.
    #[error("not on roster: {0}")]
    NotOnRoster(EntryId),
    /// The proof exchange failed or the peer's proof did not match.
    #[error("proof: {0}")]
    Proof(String),
    /// The endpoint kind cannot accept.
    #[error("unsupported endpoint for accept: {0}")]
    Unsupported(String),
    /// The transport layer failed.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
}

/// A proved attach link: the roster id that dialled and the byte stream
/// the proof ran on.
pub enum LinkStream {
    /// An owner-only local connection.
    Local(tesserax_transport::local::LocalServerStream),
    /// A TCP connection (the byte stream an HTTP accept would ride on).
    Tcp(TcpStream),
}

impl std::fmt::Debug for LinkStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkStream::Local(_) => f.write_str("LinkStream::Local(..)"),
            LinkStream::Tcp(s) => f.debug_tuple("LinkStream::Tcp").field(s).finish(),
        }
    }
}

impl AsyncRead for LinkStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            LinkStream::Local(s) => Pin::new(s).poll_read(cx, buf),
            LinkStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LinkStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            LinkStream::Local(s) => Pin::new(s).poll_write(cx, buf),
            LinkStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            LinkStream::Local(s) => Pin::new(s).poll_flush(cx),
            LinkStream::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            LinkStream::Local(s) => Pin::new(s).poll_shutdown(cx),
            LinkStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

enum AcceptSide {
    #[cfg(unix)]
    Local(tesserax_transport::local::OwnerOnlyListener),
    Tcp(tokio::net::TcpListener),
}

/// The accepting half of `AcceptIn` links: binds one endpoint, admits
/// only ids already on the roster, and runs the mutual link proof with
/// the admitted entry's own token before any application byte crosses
/// (an unknown id is refused and nothing is constructed).
pub struct AttachListener {
    side: AcceptSide,
    tokens: BTreeMap<EntryId, Zeroizing<String>>,
    domain: Vec<u8>,
    binding: Vec<u8>,
}

impl std::fmt::Debug for AttachListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachListener")
            .field("entries", &self.tokens.len())
            .finish_non_exhaustive()
    }
}

impl AttachListener {
    /// Binds `endpoint` for the roster's `AcceptIn` entries, resolving
    /// their tokens now (a missing one is a named startup refusal).
    /// `domain` / `binding` become the proof's [`LinkContext`] — the
    /// domain is a constant of the product's protocol.
    ///
    /// [`Endpoint::Local`] binds an owner-only socket (unix). An
    /// [`Endpoint::Http`] host binds a TCP listener: the proof exchange
    /// runs on the byte stream, HTTP semantics belong to the protocol
    /// above. Port `0` picks a free port; read it back with
    /// [`AttachListener::local_addr`].
    pub async fn bind(
        endpoint: &Endpoint,
        roster: &Roster<LinkSpec>,
        env: &dyn Fn(&str) -> Option<String>,
        domain: impl Into<Vec<u8>>,
        binding: impl Into<Vec<u8>>,
    ) -> Result<Self, AttachError> {
        let mut tokens = BTreeMap::new();
        for entry in roster.iter() {
            if entry.reach != Reach::AcceptIn {
                continue;
            }
            let token = entry.credential.resolve(&entry.id, env)?;
            tokens.insert(entry.id.clone(), token);
        }
        Self::bind_with_tokens(endpoint, tokens, domain, binding).await
    }

    /// As [`AttachListener::bind`] with pre-resolved tokens (derived
    /// credentials; tests).
    pub async fn bind_with_tokens(
        endpoint: &Endpoint,
        tokens: BTreeMap<EntryId, Zeroizing<String>>,
        domain: impl Into<Vec<u8>>,
        binding: impl Into<Vec<u8>>,
    ) -> Result<Self, AttachError> {
        let side = match endpoint {
            Endpoint::Local(path) => {
                #[cfg(unix)]
                {
                    AcceptSide::Local(
                        tesserax_transport::local::OwnerOnlyListener::bind(path).await?,
                    )
                }
                #[cfg(windows)]
                {
                    let _ = path;
                    return Err(AttachError::Unsupported(
                        "local accept on Windows via ncp: not yet implemented".into(),
                    ));
                }
            }
            Endpoint::Http(url) => {
                let (authority, _) =
                    split_authority(url).map_err(|e| AttachError::BadEndpoint(e.to_string()))?;
                let addr = if authority.contains(':') {
                    authority
                } else {
                    format!("{authority}:80")
                };
                AcceptSide::Tcp(tokio::net::TcpListener::bind(addr).await?)
            }
            Endpoint::Ws(url) => {
                return Err(AttachError::Unsupported(format!(
                    "ws accept is not an attach endpoint ({url})"
                )));
            }
        };
        Ok(Self {
            side,
            tokens,
            domain: domain.into(),
            binding: binding.into(),
        })
    }

    /// The address a TCP accept side bound (for port `0`).
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        match &self.side {
            AcceptSide::Tcp(l) => l.local_addr().ok(),
            #[cfg(unix)]
            AcceptSide::Local(_) => None,
        }
    }

    /// Waits for the next dialling entry, admits it (roster id + mutual
    /// proof) and returns its id with the proved stream. A dialler whose
    /// id is not on the roster gets [`AttachError::NotOnRoster`] on its
    /// side and is dropped here unread — the listener stays up.
    pub async fn accept(&mut self) -> Result<(EntryId, LinkStream), AttachError> {
        loop {
            let mut stream = match &mut self.side {
                #[cfg(unix)]
                AcceptSide::Local(l) => LinkStream::Local(l.accept().await?),
                AcceptSide::Tcp(l) => {
                    let (stream, _) = l.accept().await?;
                    stream.set_nodelay(true)?;
                    LinkStream::Tcp(stream)
                }
            };
            match self.admit(&mut stream).await {
                Ok(id) => return Ok((id, stream)),
                Err(
                    e @ (AttachError::NotOnRoster(_) | AttachError::Proof(_) | AttachError::Io(_)),
                ) => {
                    // Unknown, unproved or vanished mid-handshake: dropped,
                    // the listener keeps serving the rostered entries. A
                    // dead dialler must never take the listener down.
                    let _ = e;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn admit(&self, stream: &mut LinkStream) -> Result<EntryId, AttachError> {
        // client → server: u16 BE id len | id | client nonce
        let id_len = stream.read_u16().await? as usize;
        if id_len == 0 || id_len > 256 {
            return Err(AttachError::Proof(format!("bad id length {id_len}")));
        }
        let mut id_bytes = vec![0u8; id_len];
        stream.read_exact(&mut id_bytes).await?;
        let id_text = String::from_utf8(id_bytes)
            .map_err(|_| AttachError::Proof("id is not utf-8".into()))?;
        let id = EntryId::new(id_text);
        let mut client_nonce = [0u8; NONCE_BYTES];
        stream.read_exact(&mut client_nonce).await?;

        let Some(token) = self.tokens.get(&id) else {
            stream.write_all(&[1u8]).await?; // not on roster
            let _ = stream.flush().await;
            return Err(AttachError::NotOnRoster(id));
        };
        let server_nonce = random_nonce()?;
        let cx = LinkContext::new(&self.domain, &self.binding);
        let server_proof = link_proof(
            token.as_bytes(),
            ATTACH_ROLE,
            LinkRole::Server,
            &client_nonce,
            &server_nonce,
            &cx,
        );
        let mut reply = Vec::with_capacity(1 + NONCE_BYTES + PROOF_BYTES);
        reply.push(0u8);
        reply.extend_from_slice(&server_nonce);
        reply.extend_from_slice(&server_proof);
        stream.write_all(&reply).await?;

        let mut client_proof = [0u8; PROOF_BYTES];
        stream.read_exact(&mut client_proof).await?;
        let expected = link_proof(
            token.as_bytes(),
            ATTACH_ROLE,
            LinkRole::Client,
            &client_nonce,
            &server_nonce,
            &cx,
        );
        if !proofs_match(&client_proof, &expected) {
            return Err(AttachError::Proof(format!("proof mismatch for {id}")));
        }
        Ok(id)
    }
}

/// The dialling half of an attach link, used by the tier BELOW (a node
/// dialling in): connects, names its roster id, checks the acceptor's
/// proof and answers with its own. Compiled only with the `node`
/// feature; the accepting tier never dials it.
#[cfg(feature = "node")]
pub(crate) async fn dial_attach_stream(
    endpoint: &Endpoint,
    id: &EntryId,
    token: &[u8],
    domain: &[u8],
    binding: &[u8],
) -> Result<LinkStream, AttachError> {
    let mut stream = match endpoint {
        Endpoint::Local(path) => {
            #[cfg(unix)]
            {
                LinkStream::Local(
                    tesserax_transport::local::connect_local(path)
                        .await
                        .map_err(AttachError::Io)?,
                )
            }
            #[cfg(windows)]
            {
                let _ = path;
                return Err(AttachError::Unsupported(
                    "local dial on Windows via ncp: not yet implemented".into(),
                ));
            }
        }
        Endpoint::Http(url) => {
            let (authority, _) =
                split_authority(url).map_err(|e| AttachError::BadEndpoint(e.to_string()))?;
            let addr = if authority.contains(':') {
                authority
            } else {
                format!("{authority}:80")
            };
            let tcp = TcpStream::connect(addr).await.map_err(AttachError::Io)?;
            tcp.set_nodelay(true).map_err(AttachError::Io)?;
            LinkStream::Tcp(tcp)
        }
        Endpoint::Ws(url) => {
            return Err(AttachError::Unsupported(format!(
                "ws dial is not an attach endpoint ({url})"
            )));
        }
    };
    let id_bytes = id.as_str().as_bytes();
    let client_nonce = random_nonce()?;
    let mut hello = Vec::with_capacity(2 + id_bytes.len() + NONCE_BYTES);
    hello.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
    hello.extend_from_slice(id_bytes);
    hello.extend_from_slice(&client_nonce);
    stream.write_all(&hello).await?;

    let mut status = [0u8; 1];
    stream.read_exact(&mut status).await?;
    if status[0] == 1 {
        return Err(AttachError::NotOnRoster(id.clone()));
    }
    if status[0] != 0 {
        return Err(AttachError::Proof(format!(
            "refused with status {}",
            status[0]
        )));
    }
    let mut server_nonce = [0u8; NONCE_BYTES];
    stream.read_exact(&mut server_nonce).await?;
    let mut server_proof = [0u8; PROOF_BYTES];
    stream.read_exact(&mut server_proof).await?;
    let cx = LinkContext::new(domain, binding);
    let expected_server = link_proof(
        token,
        ATTACH_ROLE,
        LinkRole::Server,
        &client_nonce,
        &server_nonce,
        &cx,
    );
    if !proofs_match(&server_proof, &expected_server) {
        return Err(AttachError::Proof("acceptor proof mismatch".into()));
    }
    let client_proof = link_proof(
        token,
        ATTACH_ROLE,
        LinkRole::Client,
        &client_nonce,
        &server_nonce,
        &cx,
    );
    stream.write_all(&client_proof).await?;
    stream.flush().await?;
    Ok(stream)
}
