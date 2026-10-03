//! [`local_shell`]: a port served as NDJSON over an owner-only local
//! socket (Unix) or pipe (Windows).

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tesserax::swc::Port;
use tesserax_transport::local::{LocalServerStream, OwnerOnlyListener};
use tokio::io::{AsyncReadExt, AsyncWrite, BufReader};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::feed::{self, FeedItem};
use super::link::{
    DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_FRAME_BYTES, LinkKeys, accept_handshake, read_json,
    write_json,
};
use super::wire::{
    LinkDoor, LinkReply, LinkReplyFrame, LinkRequest, LinkRequestFrame, LinkStreamFrame, WireError,
};
use crate::error::ShellError;

/// Bounds of a [`local_shell`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalShellOpts {
    /// Longest a handshake may take before the link is dropped.
    pub handshake_timeout: Duration,
    /// Largest line either end may send.
    pub max_frame_bytes: usize,
    /// Links served at once; further peers wait in the listen backlog.
    pub max_links: usize,
    /// How often a feed thread checks that its link is still there.
    pub feed_poll: Duration,
}

impl Default for LocalShellOpts {
    fn default() -> Self {
        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_links: 256,
            feed_poll: Duration::from_millis(50),
        }
    }
}

/// Serves `port` on `listener` until the returned task is aborted (or the
/// listener fails for good): every accepted link runs the handshake of
/// [`LinkKeys`] for one door, then answers requests of that door only —
/// `control` dispatches and resyncs, `observe` reads snapshots and
/// subscribes. Frames are those of [`wire`](super::wire).
///
/// Must be called inside a tokio runtime (the accept loop and the links
/// are tasks on it). Refuses keys without a usable door secret.
pub fn local_shell<P, C, V, S>(
    port: P,
    listener: OwnerOnlyListener,
    keys: LinkKeys,
    opts: LocalShellOpts,
) -> Result<JoinHandle<()>, ShellError>
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    keys.validate()?;
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| ShellError::NoRuntime)?;
    let shared = Arc::new(LinkShared {
        port: Arc::new(port),
        keys,
        opts,
    });
    Ok(runtime.spawn(accept_loop(listener, shared)))
}

struct LinkShared<P> {
    port: Arc<P>,
    keys: LinkKeys,
    opts: LocalShellOpts,
}

async fn accept_loop<P, C, V, S>(mut listener: OwnerOnlyListener, shared: Arc<LinkShared<P>>)
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    let slots = Arc::new(Semaphore::new(shared.opts.max_links.max(1)));
    loop {
        let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        match listener.accept().await {
            Ok(stream) => {
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    serve_link(stream, shared).await;
                    drop(permit);
                });
            }
            Err(e) => {
                tracing::warn!(target: "tesserax_framework::shell", error = %e, "local accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn serve_link<P, C, V, S>(stream: LocalServerStream, shared: Arc<LinkShared<P>>)
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let max = shared.opts.max_frame_bytes;
    let door = match tokio::time::timeout(
        shared.opts.handshake_timeout,
        accept_handshake(&mut reader, &mut writer, &shared.keys),
    )
    .await
    {
        Ok(Ok(door)) => door,
        Ok(Err(e)) => {
            tracing::info!(target: "tesserax_framework::shell", error = %e, "local link refused");
            return;
        }
        Err(_) => return,
    };
    loop {
        let frame: LinkRequestFrame<C> = match read_json(&mut reader, max).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return,
            Err(e) => {
                let reply: LinkReplyFrame<V, S> = LinkReplyFrame {
                    id: 0,
                    reply: LinkReply::Error {
                        error: WireError::BadRequest,
                        message: e.to_string(),
                    },
                };
                let _ = write_json(&mut writer, &reply, max).await;
                return;
            }
        };
        let id = frame.id;
        if let LinkRequest::Subscribe { capacity, after } = frame.request {
            if door != LinkDoor::Observe {
                if reply(&mut writer, id, refused_door::<V, S>(door), max)
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
            let subscription = match shared.port.subscribe(capacity) {
                Ok(s) => s,
                Err(e) => {
                    let r: LinkReply<V, S> = LinkReply::Error {
                        error: WireError::from_subscribe(e),
                        message: e.to_string(),
                    };
                    if reply(&mut writer, id, r, max).await.is_err() {
                        return;
                    }
                    continue;
                }
            };
            let Some(rx) = feed::start(
                Arc::clone(&shared.port),
                subscription,
                after,
                shared.opts.feed_poll,
            ) else {
                let r: LinkReply<V, S> = LinkReply::Error {
                    error: WireError::Unavailable,
                    message: "no feed thread".into(),
                };
                let _ = reply(&mut writer, id, r, max).await;
                return;
            };
            if reply(&mut writer, id, LinkReply::<V, S>::Subscribed, max)
                .await
                .is_ok()
            {
                stream_feed(rx, &mut reader, &mut writer, max).await;
            }
            return;
        }
        let answer = answer(&*shared.port, door, frame.request);
        if reply(&mut writer, id, answer, max).await.is_err() {
            return;
        }
    }
}

fn refused_door<V, S>(door: LinkDoor) -> LinkReply<V, S> {
    LinkReply::Error {
        error: WireError::Unauthorized,
        message: format!("not served through the {} door", door.as_str()),
    }
}

async fn reply<W, V, S>(
    writer: &mut W,
    id: u64,
    reply: LinkReply<V, S>,
    max: usize,
) -> Result<(), ShellError>
where
    W: AsyncWrite + Unpin,
    V: Serialize,
    S: Serialize,
{
    write_json(writer, &LinkReplyFrame { id, reply }, max).await
}

/// Every request but `Subscribe`, for a link opened through `door`.
fn answer<P, C, V, S>(port: &P, door: LinkDoor, request: LinkRequest<C>) -> LinkReply<V, S>
where
    P: Port<C, V, S> + ?Sized,
{
    let needs = match &request {
        LinkRequest::Dispatch { .. }
        | LinkRequest::DispatchEnvelope { .. }
        | LinkRequest::Resync { .. } => LinkDoor::Control,
        LinkRequest::Snapshot { .. } | LinkRequest::Subscribe { .. } => LinkDoor::Observe,
    };
    if needs != door {
        return refused_door(door);
    }
    let dispatched = |r: Result<tesserax::swc::CommandId, tesserax::swc::DispatchError>| match r {
        Ok(id) => LinkReply::Dispatched { id },
        Err(e) => LinkReply::Error {
            error: WireError::from_dispatch(e),
            message: e.to_string(),
        },
    };
    match request {
        LinkRequest::Dispatch { command } => dispatched(port.dispatch(command)),
        LinkRequest::DispatchEnvelope { envelope } => {
            let id = envelope.id;
            dispatched(port.dispatch_envelope(envelope).map(|()| id))
        }
        LinkRequest::Resync { after } => LinkReply::Resync {
            reply: port.resync(after),
        },
        LinkRequest::Snapshot { if_revision } => {
            let snapshot = port.snapshot();
            if if_revision == Some(snapshot.revision) {
                LinkReply::NotModified {
                    revision: snapshot.revision,
                }
            } else {
                LinkReply::Snapshot { snapshot }
            }
        }
        LinkRequest::Subscribe { .. } => LinkReply::Error {
            error: WireError::BadRequest,
            message: "subscribe is answered by the link loop".into(),
        },
    }
}

/// Forwards the feed until it ends or the peer closes the link (read side
/// at end of stream); any byte the peer sends on a subscribed link is
/// ignored.
async fn stream_feed<R, W, V>(
    mut rx: tokio::sync::mpsc::Receiver<FeedItem<V>>,
    reader: &mut R,
    writer: &mut W,
    max: usize,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    V: Serialize,
{
    let mut scratch = [0u8; 256];
    loop {
        tokio::select! {
            item = rx.recv() => {
                let frame = match item {
                    Some(FeedItem::Event(event)) => LinkStreamFrame::Event { event },
                    Some(FeedItem::Resync(notice)) => LinkStreamFrame::Resync { notice },
                    None => return,
                };
                if write_json(writer, &frame, max).await.is_err() {
                    return;
                }
            }
            read = reader.read(&mut scratch) => {
                if !matches!(read, Ok(n) if n > 0) {
                    return;
                }
            }
        }
    }
}
