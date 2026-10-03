//! The HTTP side of [`RemoteHandle`](super::RemoteHandle): a small pool of
//! HTTP/1.1 connections for requests, one dedicated connection per event
//! stream.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::{DeserializeOwned, IgnoredAny};
use tesserax::swc::{CommandId, EventEnvelope, ResyncReply, Snapshot, SubscriptionSender};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use super::sse::SseParser;
use super::{Delivery, Link, deliver};
use crate::error::ShellError;
use crate::shell::wire::{
    COMMANDS_PATH, CommandRequest, Dispatched, EVENTS_PATH, ErrorBody, LinkDoor, RESYNC_EVENT,
    RESYNC_PATH, ResyncNotice, ResyncRequest, SNAPSHOT_PATH, WireError,
};

type Sender = SendRequest<Full<Bytes>>;

/// Where and how a [`RemoteHandle`](super::RemoteHandle) reaches an
/// [`http_shell`](crate::shell::http_shell).
///
/// Plain HTTP/1.1: over a network, put TLS in front (the key travels in
/// the `Authorization` header), or prefer the local link on one host.
#[derive(Clone)]
pub struct HttpRemote {
    /// Server address.
    pub addr: SocketAddr,
    /// Prefix the shell's routes are nested under (`""` when not nested).
    pub base_path: String,
    /// Bearer key sent on every request; it needs a grant on each door the
    /// handle uses.
    pub bearer: Option<Zeroizing<String>>,
    /// Longest a single request (not a stream) may take.
    pub timeout: Duration,
    /// How often an event stream checks that its subscriber still exists.
    pub poll: Duration,
    /// Idle connections kept for reuse.
    pub pool: usize,
    /// Largest SSE line or message accepted.
    pub max_frame_bytes: usize,
}

impl core::fmt::Debug for HttpRemote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpRemote")
            .field("addr", &self.addr)
            .field("base_path", &self.base_path)
            .field("bearer", &self.bearer.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HttpRemote {
    /// The shell at `addr`, routes not nested, no key.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            base_path: String::new(),
            bearer: None,
            timeout: Duration::from_secs(10),
            poll: Duration::from_millis(20),
            pool: 16,
            max_frame_bytes: crate::shell::link::DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Sends `key` as `Authorization: Bearer`.
    pub fn bearer(mut self, key: impl Into<String>) -> Self {
        self.bearer = Some(Zeroizing::new(key.into()));
        self
    }

    /// Routes are nested under `prefix` (for example `/app`).
    pub fn base_path(mut self, prefix: impl Into<String>) -> Self {
        self.base_path = prefix.into().trim_end_matches('/').to_owned();
        self
    }

    /// Request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

pub(crate) struct HttpLink {
    addr: SocketAddr,
    host: HeaderValue,
    base: String,
    auth: Option<HeaderValue>,
    pool: Mutex<Vec<Sender>>,
    pool_max: usize,
    max_frame: usize,
}

struct Answer {
    status: StatusCode,
    body: Bytes,
}

impl HttpLink {
    pub(crate) fn new(cfg: &HttpRemote) -> Result<Self, ShellError> {
        let host = HeaderValue::from_str(&cfg.addr.to_string())
            .map_err(|e| ShellError::Config(e.to_string()))?;
        let auth = match &cfg.bearer {
            Some(key) => {
                let mut v = HeaderValue::from_str(&format!("Bearer {}", key.as_str()))
                    .map_err(|_| ShellError::Config("bearer key is not a header value".into()))?;
                v.set_sensitive(true);
                Some(v)
            }
            None => None,
        };
        if !cfg.base_path.is_empty() && !cfg.base_path.starts_with('/') {
            return Err(ShellError::Config("base_path must start with '/'".into()));
        }
        Ok(Self {
            addr: cfg.addr,
            host,
            base: cfg.base_path.clone(),
            auth,
            pool: Mutex::new(Vec::new()),
            pool_max: cfg.pool,
            max_frame: cfg.max_frame_bytes.max(1),
        })
    }

    fn idle(&self) -> MutexGuard<'_, Vec<Sender>> {
        self.pool.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn connect(&self) -> Result<Sender, ShellError> {
        let tcp = TcpStream::connect(self.addr).await?;
        tcp.set_nodelay(true)?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| ShellError::Protocol(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }

    /// An idle connection that is still usable, else a new one; `true` when
    /// it was reused.
    async fn checkout(&self) -> Result<(Sender, bool), ShellError> {
        loop {
            let idle = self.idle().pop();
            match idle {
                Some(mut sender) => {
                    if !sender.is_closed() && sender.ready().await.is_ok() {
                        return Ok((sender, true));
                    }
                }
                None => return Ok((self.connect().await?, false)),
            }
        }
    }

    fn checkin(&self, sender: Sender) {
        let mut idle = self.idle();
        if idle.len() < self.pool_max {
            idle.push(sender);
        }
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        extra: &[(header::HeaderName, HeaderValue)],
    ) -> Result<Request<Full<Bytes>>, ShellError> {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header(header::HOST, self.host.clone());
        if let Some(auth) = &self.auth {
            req = req.header(header::AUTHORIZATION, auth.clone());
        }
        if body.is_some() {
            req = req.header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        for (k, v) in extra {
            req = req.header(k, v.clone());
        }
        req.body(Full::new(body.unwrap_or_default()))
            .map_err(|e| ShellError::Protocol(e.to_string()))
    }

    /// One request/response on a pooled connection. A request a reused
    /// connection could not even send (it had been closed) is sent once
    /// more on a fresh one; a request that may have reached the server is
    /// never repeated.
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        extra: &[(header::HeaderName, HeaderValue)],
    ) -> Result<Answer, ShellError> {
        self.send_on(method, path, body, extra, true).await
    }

    /// [`send`](Self::send), or with `pooled == false` on a connection of
    /// its own that is closed afterwards (for stream tasks, which run on
    /// another runtime than the pool's connections).
    async fn send_on(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        extra: &[(header::HeaderName, HeaderValue)],
        pooled: bool,
    ) -> Result<Answer, ShellError> {
        let mut req = self.request(method, path, body, extra)?;
        let mut fresh_tried = !pooled;
        loop {
            let (mut sender, reused) = if fresh_tried {
                (self.connect().await?, false)
            } else {
                self.checkout().await?
            };
            match sender.try_send_request(req).await {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp
                        .into_body()
                        .collect()
                        .await
                        .map_err(|e| ShellError::Protocol(e.to_string()))?
                        .to_bytes();
                    if pooled {
                        self.checkin(sender);
                    }
                    return Ok(Answer { status, body });
                }
                Err(mut e) => match e.take_message() {
                    Some(unsent) if reused && !fresh_tried => {
                        req = unsent;
                        fresh_tried = true;
                    }
                    _ => {
                        return Err(ShellError::Io(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            e.into_error().to_string(),
                        )));
                    }
                },
            }
        }
    }

    pub(crate) async fn dispatch<C: Serialize>(
        &self,
        request: &CommandRequest<C>,
    ) -> Result<CommandId, ShellError> {
        let body = encode(request)?;
        let answer = self
            .send(Method::POST, COMMANDS_PATH, Some(body), &[])
            .await?;
        if answer.status == StatusCode::ACCEPTED {
            let d: Dispatched = decode(&answer.body)?;
            return Ok(d.id);
        }
        Err(refusal(&answer, LinkDoor::Control))
    }

    pub(crate) async fn snapshot<S: DeserializeOwned>(
        &self,
        cached: Option<&Arc<Snapshot<S>>>,
    ) -> Result<Arc<Snapshot<S>>, ShellError> {
        let mut extra = Vec::new();
        if let Some(c) = cached {
            let tag = HeaderValue::from_str(&format!("\"{}\"", c.revision))
                .map_err(|e| ShellError::Protocol(e.to_string()))?;
            extra.push((header::IF_NONE_MATCH, tag));
        }
        let answer = self.send(Method::GET, SNAPSHOT_PATH, None, &extra).await?;
        match (answer.status, cached) {
            (StatusCode::OK, _) => decode::<Snapshot<S>>(&answer.body).map(Arc::new),
            (StatusCode::NOT_MODIFIED, Some(c)) => Ok(Arc::clone(c)),
            _ => Err(refusal(&answer, LinkDoor::Observe)),
        }
    }

    pub(crate) async fn resync<V, S>(&self, after: u64) -> Result<ResyncReply<V, S>, ShellError>
    where
        V: DeserializeOwned,
        S: DeserializeOwned,
    {
        self.resync_on(after, true).await
    }

    async fn resync_on<V, S>(
        &self,
        after: u64,
        pooled: bool,
    ) -> Result<ResyncReply<V, S>, ShellError>
    where
        V: DeserializeOwned,
        S: DeserializeOwned,
    {
        let body = encode(&ResyncRequest { after })?;
        let answer = self
            .send_on(Method::POST, RESYNC_PATH, Some(body), &[], pooled)
            .await?;
        if answer.status == StatusCode::OK {
            return decode(&answer.body);
        }
        Err(refusal(&answer, LinkDoor::Control))
    }

    /// Opens `GET /v1/events` on a dedicated connection and, once the
    /// serving port has admitted the subscriber, pumps the stream into
    /// `sender` on a task.
    pub(crate) async fn subscribe<V>(
        &self,
        capacity: usize,
        sender: SubscriptionSender<V>,
        poll: Duration,
        link: Arc<Link>,
    ) -> Result<(), ShellError>
    where
        V: DeserializeOwned + Send + 'static,
    {
        let mut conn = self.connect().await?;
        let accept = (
            header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        let req = self.request(
            Method::GET,
            &format!("{EVENTS_PATH}?capacity={capacity}"),
            None,
            &[accept],
        )?;
        let resp = conn
            .send_request(req)
            .await
            .map_err(|e| ShellError::Protocol(e.to_string()))?;
        if resp.status() != StatusCode::OK {
            let status = resp.status();
            let body = resp
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            return Err(refusal(&Answer { status, body }, LinkDoor::Observe));
        }
        let max = self.max_frame;
        tokio::spawn(pump(resp.into_body(), sender, poll, max, link, conn));
        Ok(())
    }
}

/// Reads SSE messages into `sender` until the stream ends, the subscriber
/// is gone, or it is cut (by the port as slow, or here because its queue
/// is full). `_conn` keeps the connection's request half until then.
async fn pump<V>(
    mut body: Incoming,
    sender: SubscriptionSender<V>,
    poll: Duration,
    max: usize,
    link: Arc<Link>,
    _conn: Sender,
) where
    V: DeserializeOwned,
{
    let mut parser = SseParser::new(max);
    let mut tick = tokio::time::interval(poll.max(Duration::from_millis(1)));
    loop {
        tokio::select! {
            frame = body.frame() => {
                let Some(Ok(frame)) = frame else { return };
                let Ok(data) = frame.into_data() else { continue };
                let Ok(messages) = parser.push(&data) else { return };
                for message in messages {
                    let delivery = if message.event.as_deref() == Some(RESYNC_EVENT) {
                        match serde_json::from_str::<ResyncNotice>(&message.data) {
                            Ok(notice) => Delivery::Notice(notice),
                            Err(_) => return,
                        }
                    } else {
                        match serde_json::from_str::<EventEnvelope<V>>(&message.data) {
                            Ok(event) => Delivery::Event(event),
                            Err(_) => return,
                        }
                    };
                    if !deliver(&sender, delivery, &link).await {
                        return;
                    }
                }
            }
            _ = tick.tick() => {
                if sender.is_closed() {
                    return;
                }
            }
        }
    }
}

/// `oldest_available` as the serving port reports it now (asked from a
/// stream task, so on a connection of its own).
pub(crate) async fn oldest_available(link: &HttpLink) -> Option<u64> {
    link.resync_on::<IgnoredAny, IgnoredAny>(u64::MAX, false)
        .await
        .ok()
        .map(|r| r.oldest_available)
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Bytes, ShellError> {
    serde_json::to_vec(value)
        .map(Bytes::from)
        .map_err(|e| ShellError::Codec(e.to_string()))
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ShellError> {
    serde_json::from_slice(body).map_err(|e| ShellError::Codec(e.to_string()))
}

/// What a non-success answer means: the port's own refusal when the body
/// says so, a door refusal on 401 / 403, else the bare status.
fn refusal(answer: &Answer, door: LinkDoor) -> ShellError {
    if let Ok(body) = serde_json::from_slice::<ErrorBody>(&answer.body) {
        if let Some(e) = body.error.to_dispatch() {
            return ShellError::Dispatch(e);
        }
        if let Some(e) = body.error.to_subscribe() {
            return ShellError::Subscribe(e);
        }
        if body.error == WireError::Unauthorized {
            return ShellError::Unauthorized {
                door: door.as_str(),
            };
        }
    }
    if matches!(
        answer.status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return ShellError::Unauthorized {
            door: door.as_str(),
        };
    }
    let excerpt: String = String::from_utf8_lossy(&answer.body)
        .chars()
        .take(200)
        .collect();
    ShellError::Status {
        status: answer.status.as_u16(),
        message: excerpt,
    }
}
