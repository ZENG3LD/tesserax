//! The local side of [`RemoteHandle`](super::RemoteHandle): owner-only
//! links, one pool per door for requests, one dedicated link per event
//! stream.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde::Serialize;
use serde::de::{DeserializeOwned, IgnoredAny};
use tesserax::swc::{CommandId, ResyncReply, Snapshot, SubscriptionSender};
use tesserax_transport::local::{LocalClientStream, connect_local};
use tokio::io::{AsyncWriteExt, BufReader, ReadHalf, WriteHalf};

use super::{Delivery, Link, deliver};
use crate::error::ShellError;
use crate::shell::link::{
    DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_FRAME_BYTES, LinkKeys, connect_handshake, read_json,
};
use crate::shell::wire::{
    CommandRequest, LinkDoor, LinkReply, LinkReplyFrame, LinkRequest, LinkRequestFrame,
    LinkStreamFrame, WireError,
};

/// Where and how a [`RemoteHandle`](super::RemoteHandle) reaches a
/// [`local_shell`](crate::shell::local_shell).
#[derive(Clone, Debug)]
pub struct LocalRemote {
    /// Socket path (Unix) or pipe name (Windows) the shell listens on.
    pub endpoint: PathBuf,
    /// Secrets of the doors this handle may use, and the proof context
    /// (must equal the shell's).
    pub keys: LinkKeys,
    /// Longest a single request (not a stream) may take.
    pub timeout: Duration,
    /// Longest a link handshake may take.
    pub handshake_timeout: Duration,
    /// How often an event stream checks that its subscriber still exists.
    pub poll: Duration,
    /// Idle links kept per door for reuse.
    pub pool: usize,
    /// Largest line either end may send.
    pub max_frame_bytes: usize,
}

impl LocalRemote {
    /// The shell at `endpoint`, using the doors `keys` has secrets for.
    pub fn new(endpoint: impl Into<PathBuf>, keys: LinkKeys) -> Self {
        Self {
            endpoint: endpoint.into(),
            keys,
            timeout: Duration::from_secs(10),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            poll: Duration::from_millis(20),
            pool: 8,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

type Reader = BufReader<ReadHalf<LocalClientStream>>;
type Writer = WriteHalf<LocalClientStream>;

struct Conn {
    reader: Reader,
    writer: Writer,
}

pub(crate) struct LocalLink {
    endpoint: PathBuf,
    keys: LinkKeys,
    handshake_timeout: Duration,
    max_frame: usize,
    control: Mutex<Vec<Conn>>,
    observe: Mutex<Vec<Conn>>,
    pool_max: usize,
    next_id: AtomicU64,
}

impl LocalLink {
    pub(crate) fn new(cfg: &LocalRemote) -> Result<Self, ShellError> {
        cfg.keys.validate()?;
        Ok(Self {
            endpoint: cfg.endpoint.clone(),
            keys: cfg.keys.clone(),
            handshake_timeout: cfg.handshake_timeout,
            max_frame: cfg.max_frame_bytes.max(1),
            control: Mutex::new(Vec::new()),
            observe: Mutex::new(Vec::new()),
            pool_max: cfg.pool,
            next_id: AtomicU64::new(1),
        })
    }

    fn idle(&self, door: LinkDoor) -> MutexGuard<'_, Vec<Conn>> {
        let pool = match door {
            LinkDoor::Control => &self.control,
            LinkDoor::Observe => &self.observe,
        };
        pool.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn open(&self, door: LinkDoor) -> Result<Conn, ShellError> {
        if !self.keys.has(door) {
            return Err(ShellError::Unauthorized {
                door: door.as_str(),
            });
        }
        let stream = connect_local(&self.endpoint).await?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        tokio::time::timeout(
            self.handshake_timeout,
            connect_handshake(&mut reader, &mut writer, &self.keys, door),
        )
        .await
        .map_err(|_| ShellError::Timeout)??;
        Ok(Conn { reader, writer })
    }

    /// One request/response through `door`. A request a reused link could
    /// not write is written once more on a fresh link; one that was
    /// written is never repeated.
    async fn call<C, V, S>(
        &self,
        door: LinkDoor,
        request: LinkRequest<C>,
    ) -> Result<LinkReply<V, S>, ShellError>
    where
        C: Serialize,
        V: DeserializeOwned,
        S: DeserializeOwned,
    {
        self.call_on(door, request, true).await
    }

    /// [`call`](Self::call), or with `pooled == false` on a link of its own
    /// that is closed afterwards (for stream tasks, which run on another
    /// runtime than the pooled links).
    async fn call_on<C, V, S>(
        &self,
        door: LinkDoor,
        request: LinkRequest<C>,
        pooled: bool,
    ) -> Result<LinkReply<V, S>, ShellError>
    where
        C: Serialize,
        V: DeserializeOwned,
        S: DeserializeOwned,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut line = serde_json::to_vec(&LinkRequestFrame { id, request })
            .map_err(|e| ShellError::Codec(e.to_string()))?;
        if line.len() > self.max_frame {
            return Err(ShellError::Codec(format!(
                "frame of {} bytes exceeds {}",
                line.len(),
                self.max_frame
            )));
        }
        line.push(b'\n');
        let idle = if pooled { self.idle(door).pop() } else { None };
        let (mut conn, reused) = match idle {
            Some(conn) => (conn, true),
            None => (self.open(door).await?, false),
        };
        if let Err(e) = write_line(&mut conn.writer, &line).await {
            if !reused {
                return Err(e);
            }
            conn = self.open(door).await?;
            write_line(&mut conn.writer, &line).await?;
        }
        let frame: LinkReplyFrame<V, S> = read_json(&mut conn.reader, self.max_frame)
            .await?
            .ok_or_else(|| ShellError::Protocol("link closed before the reply".into()))?;
        if frame.id != id {
            return Err(ShellError::Protocol(format!(
                "reply {} to request {id}",
                frame.id
            )));
        }
        if pooled {
            let mut pool = self.idle(door);
            if pool.len() < self.pool_max {
                pool.push(conn);
            }
        }
        Ok(frame.reply)
    }

    pub(crate) async fn dispatch<C: Serialize>(
        &self,
        request: CommandRequest<C>,
    ) -> Result<CommandId, ShellError> {
        let request = match request.id {
            Some(id) => LinkRequest::DispatchEnvelope {
                envelope: tesserax::swc::CommandEnvelope {
                    id,
                    command: request.command,
                },
            },
            None => LinkRequest::Dispatch {
                command: request.command,
            },
        };
        match self
            .call::<C, IgnoredAny, IgnoredAny>(LinkDoor::Control, request)
            .await?
        {
            LinkReply::Dispatched { id } => Ok(id),
            other => Err(unexpected(other, LinkDoor::Control)),
        }
    }

    pub(crate) async fn snapshot<S: DeserializeOwned>(
        &self,
        cached: Option<&Arc<Snapshot<S>>>,
    ) -> Result<Arc<Snapshot<S>>, ShellError> {
        let request = LinkRequest::<()>::Snapshot {
            if_revision: cached.map(|c| c.revision),
        };
        match self
            .call::<(), IgnoredAny, S>(LinkDoor::Observe, request)
            .await?
        {
            LinkReply::Snapshot { snapshot } => Ok(snapshot),
            LinkReply::NotModified { revision } => match cached {
                Some(c) if c.revision == revision => Ok(Arc::clone(c)),
                _ => Err(ShellError::Protocol(
                    "not-modified for another revision".into(),
                )),
            },
            other => Err(unexpected(other, LinkDoor::Observe)),
        }
    }

    pub(crate) async fn resync<V, S>(&self, after: u64) -> Result<ResyncReply<V, S>, ShellError>
    where
        V: DeserializeOwned,
        S: DeserializeOwned,
    {
        match self
            .call::<(), V, S>(LinkDoor::Control, LinkRequest::Resync { after })
            .await?
        {
            LinkReply::Resync { reply } => Ok(reply),
            other => Err(unexpected(other, LinkDoor::Control)),
        }
    }

    /// Opens a dedicated observe link, subscribes and, once the serving
    /// port admitted the subscriber, pumps its frames into `sender` on a
    /// task.
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
        let mut conn = self.open(LinkDoor::Observe).await?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let frame = LinkRequestFrame {
            id,
            request: LinkRequest::<()>::Subscribe {
                capacity,
                after: None,
            },
        };
        let mut line = serde_json::to_vec(&frame).map_err(|e| ShellError::Codec(e.to_string()))?;
        line.push(b'\n');
        write_line(&mut conn.writer, &line).await?;
        let reply: LinkReplyFrame<IgnoredAny, IgnoredAny> =
            read_json(&mut conn.reader, self.max_frame)
                .await?
                .ok_or_else(|| ShellError::Protocol("link closed before the reply".into()))?;
        match reply.reply {
            LinkReply::Subscribed if reply.id == id => {}
            other => return Err(unexpected(other, LinkDoor::Observe)),
        }
        let max = self.max_frame;
        tokio::spawn(pump(conn, sender, poll, max, link));
        Ok(())
    }
}

async fn write_line(writer: &mut Writer, line: &[u8]) -> Result<(), ShellError> {
    writer.write_all(line).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads the next stream frame, giving the reader back with the result so
/// the read survives a `select!` round that took the other branch.
async fn next_frame<V: DeserializeOwned>(
    mut reader: Reader,
    max: usize,
) -> (Reader, Result<Option<LinkStreamFrame<V>>, ShellError>) {
    let frame = read_json(&mut reader, max).await;
    (reader, frame)
}

async fn pump<V>(
    conn: Conn,
    sender: SubscriptionSender<V>,
    poll: Duration,
    max: usize,
    link: Arc<Link>,
) where
    V: DeserializeOwned,
{
    // The write half stays open (a half-closed link reads as a closed
    // subscriber on the shell) until the pump ends.
    let Conn {
        reader,
        writer: _writer,
    } = conn;
    let mut tick = tokio::time::interval(poll.max(Duration::from_millis(1)));
    let mut pending = Box::pin(next_frame::<V>(reader, max));
    loop {
        tokio::select! {
            (reader, frame) = &mut pending => {
                let delivery = match frame {
                    Ok(Some(LinkStreamFrame::Event { event })) => Delivery::Event(event),
                    Ok(Some(LinkStreamFrame::Resync { notice })) => Delivery::Notice(notice),
                    _ => return,
                };
                if !deliver(&sender, delivery, &link).await {
                    return;
                }
                pending = Box::pin(next_frame::<V>(reader, max));
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
/// stream task, so on a link of its own).
pub(crate) async fn oldest_available(link: &LocalLink) -> Option<u64> {
    let request = LinkRequest::<()>::Resync { after: u64::MAX };
    match link
        .call_on::<(), IgnoredAny, IgnoredAny>(LinkDoor::Control, request, false)
        .await
    {
        Ok(LinkReply::Resync { reply }) => Some(reply.oldest_available),
        _ => None,
    }
}

fn unexpected<V, S>(reply: LinkReply<V, S>, door: LinkDoor) -> ShellError {
    match reply {
        LinkReply::Error { error, message } => {
            if let Some(e) = error.to_dispatch() {
                ShellError::Dispatch(e)
            } else if let Some(e) = error.to_subscribe() {
                ShellError::Subscribe(e)
            } else if error == WireError::Unauthorized {
                ShellError::Unauthorized {
                    door: door.as_str(),
                }
            } else {
                ShellError::Protocol(message)
            }
        }
        _ => ShellError::Protocol("reply does not answer the request".into()),
    }
}
