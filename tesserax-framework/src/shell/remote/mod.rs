//! [`RemoteHandle`]: the root [`Port`] over the wire of a shell.

mod http;
mod local;
mod sse;

use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tesserax::publish::Published;
use tesserax::swc::{
    CommandEnvelope, CommandId, CoreEvent, DispatchError, EventEnvelope, Generation, Port,
    ResyncReply, SendError, Snapshot, SubscribeError, Subscription, SubscriptionSender,
    subscription_channel,
};
use tokio::runtime::Runtime;

pub use self::http::HttpRemote;
pub use self::local::LocalRemote;
use crate::error::ShellError;
use crate::shell::wire::{CommandRequest, ResyncNotice};

/// Transport of one remote handle.
pub(crate) enum Link {
    Http(http::HttpLink),
    Local(local::LocalLink),
}

impl Link {
    async fn dispatch<C: Serialize>(
        &self,
        request: CommandRequest<C>,
    ) -> Result<CommandId, ShellError> {
        match self {
            Link::Http(h) => h.dispatch(&request).await,
            Link::Local(l) => l.dispatch(request).await,
        }
    }

    async fn snapshot<S: DeserializeOwned>(
        &self,
        cached: Option<&Arc<Snapshot<S>>>,
    ) -> Result<Arc<Snapshot<S>>, ShellError> {
        match self {
            Link::Http(h) => h.snapshot(cached).await,
            Link::Local(l) => l.snapshot(cached).await,
        }
    }

    async fn resync<V, S>(&self, after: u64) -> Result<ResyncReply<V, S>, ShellError>
    where
        V: DeserializeOwned,
        S: DeserializeOwned,
    {
        match self {
            Link::Http(h) => h.resync(after).await,
            Link::Local(l) => l.resync(after).await,
        }
    }

    async fn subscribe<V>(
        self: &Arc<Self>,
        capacity: usize,
        sender: SubscriptionSender<V>,
        poll: Duration,
    ) -> Result<(), ShellError>
    where
        V: DeserializeOwned + Send + 'static,
    {
        match &**self {
            Link::Http(h) => h.subscribe(capacity, sender, poll, Arc::clone(self)).await,
            Link::Local(l) => l.subscribe(capacity, sender, poll, Arc::clone(self)).await,
        }
    }

    async fn oldest_available(&self) -> Option<u64> {
        match self {
            Link::Http(h) => http::oldest_available(h).await,
            Link::Local(l) => local::oldest_available(l).await,
        }
    }
}

/// What a stream pump hands to a subscriber.
pub(crate) enum Delivery<V> {
    Event(EventEnvelope<V>),
    Notice(ResyncNotice),
}

/// Delivers one item; false once the subscriber is finished (gone, or cut
/// and told so).
///
/// A full local queue cuts the subscriber here exactly as the port's edge
/// does: one final `ResyncRequired` naming the first undelivered sequence,
/// then disconnected. `oldest_available` is asked of the serving port
/// (through the control door); without that door it is the undelivered
/// sequence itself.
pub(crate) async fn deliver<V>(
    sender: &SubscriptionSender<V>,
    delivery: Delivery<V>,
    link: &Link,
) -> bool {
    match delivery {
        Delivery::Event(event) => {
            let sequence = event.sequence;
            match sender.try_send(event) {
                Ok(()) => true,
                Err(SendError::Closed) => false,
                Err(SendError::Full) => {
                    let oldest = link.oldest_available().await.unwrap_or(sequence);
                    sender.send_final(cut_marker(sequence, oldest));
                    false
                }
            }
        }
        Delivery::Notice(notice) => {
            sender.send_final(cut_marker(notice.after.saturating_add(1), notice.oldest));
            false
        }
    }
}

fn cut_marker<V>(sequence: u64, oldest_available: u64) -> EventEnvelope<V> {
    EventEnvelope {
        sequence,
        command_id: None,
        subject: None,
        generation: Generation::default(),
        event: CoreEvent::ResyncRequired { oldest_available },
    }
}

/// Two runtimes: requests run on a current-thread runtime that the
/// calling thread drives itself inside `block_on` (no hand-off to another
/// thread per round trip); event streams run on a one-worker runtime so
/// they progress while nobody calls. Pooled connections belong to the
/// request runtime and are never touched from a stream task.
struct Remote<S> {
    requests: Option<Runtime>,
    streams: Option<Runtime>,
    link: Arc<Link>,
    snapshot: Published<Snapshot<S>>,
    timeout: Duration,
    poll: Duration,
}

impl<S> Drop for Remote<S> {
    fn drop(&mut self) {
        for runtime in [self.requests.take(), self.streams.take()]
            .into_iter()
            .flatten()
        {
            runtime.shutdown_background();
        }
    }
}

/// The root [`Port`] over the wire of an [`http_shell`](crate::shell::http_shell)
/// or a [`local_shell`](crate::shell::local_shell). Cheap to clone; clones
/// share one connection pool and one snapshot cache.
///
/// The contract is the port's: `dispatch` answers the serving port's own
/// `Full` / `Disconnected` / `IdsExhausted`, command ids are the serving
/// port's, `subscribe` fails with `TooManySubscribers` exactly when the
/// serving port does, a slow subscriber ends with `ResyncRequired` and is
/// disconnected, `resync` is the serving port's reply (with its `gap`).
///
/// What the wire changes:
/// - every call waits for one round trip (bounded by the configured
///   timeout); it blocks the calling thread and refuses to run on a thread
///   that drives an async runtime (`ShellError::InsideRuntime`);
/// - events arrive asynchronously, and between the serving port and the
///   local [`Subscription`] there is one more bounded queue, so a slow
///   subscriber is cut either by the port or by this handle — the
///   subscriber sees the same final marker either way;
/// - failures the port has no word for (the link is down, the credential
///   does not open the door) surface as `Disconnected` from `dispatch`, as
///   an already disconnected subscription from `subscribe`, and as the last
///   snapshot seen from `snapshot`; `resync` then answers that snapshot
///   with `gap = true` and no events. The `try_*` methods report the
///   precise [`ShellError`].
///
/// Dropping the last clone stops its streams (their subscriptions
/// disconnect).
pub struct RemoteHandle<C, V, S> {
    inner: Arc<Remote<S>>,
    _types: PhantomData<fn(C) -> V>,
}

impl<C, V, S> Clone for RemoteHandle<C, V, S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            _types: PhantomData,
        }
    }
}

impl<C, V, S> core::fmt::Debug for RemoteHandle<C, V, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match &*self.inner.link {
            Link::Http(_) => "http",
            Link::Local(_) => "local",
        };
        f.debug_struct("RemoteHandle")
            .field("link", &kind)
            .field("revision", &self.inner.snapshot.load().revision)
            .finish_non_exhaustive()
    }
}

impl<C, V, S> RemoteHandle<C, V, S>
where
    C: Serialize + Send + 'static,
    V: DeserializeOwned + Send + 'static,
    S: DeserializeOwned + Send + Sync + 'static,
{
    /// Connects to an HTTP shell and reads its current snapshot (through
    /// the observe door).
    pub fn http(remote: HttpRemote) -> Result<Self, ShellError> {
        let link = Link::Http(http::HttpLink::new(&remote)?);
        Self::start(link, remote.timeout, remote.poll)
    }

    /// Connects to a local shell and reads its current snapshot (through
    /// the observe door).
    pub fn local(remote: LocalRemote) -> Result<Self, ShellError> {
        let link = Link::Local(local::LocalLink::new(&remote)?);
        Self::start(link, remote.timeout, remote.poll)
    }

    fn start(link: Link, timeout: Duration, poll: Duration) -> Result<Self, ShellError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(ShellError::InsideRuntime);
        }
        let requests = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let streams = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("tesserax-remote")
            .enable_io()
            .enable_time()
            .build()?;
        let link = Arc::new(link);
        let first = requests.block_on(async {
            tokio::time::timeout(timeout, link.snapshot::<S>(None))
                .await
                .map_err(|_| ShellError::Timeout)?
        });
        let first = match first {
            Ok(s) => s,
            Err(e) => {
                requests.shutdown_background();
                streams.shutdown_background();
                return Err(e);
            }
        };
        Ok(Self {
            inner: Arc::new(Remote {
                requests: Some(requests),
                streams: Some(streams),
                link,
                snapshot: Published::from_arc(first),
                timeout,
                poll,
            }),
            _types: PhantomData,
        })
    }

    /// Runs one request on the calling thread (request runtime).
    fn block<T, F>(&self, future: F) -> Result<T, ShellError>
    where
        F: Future<Output = Result<T, ShellError>>,
    {
        Self::block_on(self.inner.requests.as_ref(), self.inner.timeout, future)
    }

    fn block_on<T, F>(
        runtime: Option<&Runtime>,
        timeout: Duration,
        future: F,
    ) -> Result<T, ShellError>
    where
        F: Future<Output = Result<T, ShellError>>,
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(ShellError::InsideRuntime);
        }
        let runtime = runtime.ok_or(ShellError::NoRuntime)?;
        runtime.block_on(async {
            tokio::time::timeout(timeout, future)
                .await
                .map_err(|_| ShellError::Timeout)?
        })
    }

    /// Dispatches `command`; the id is the serving port's.
    pub fn try_dispatch(&self, command: C) -> Result<CommandId, ShellError> {
        let link = &self.inner.link;
        self.block(link.dispatch(CommandRequest { id: None, command }))
    }

    /// Dispatches `envelope` keeping its id.
    pub fn try_dispatch_envelope(&self, envelope: CommandEnvelope<C>) -> Result<(), ShellError> {
        let link = &self.inner.link;
        let request = CommandRequest {
            id: Some(envelope.id),
            command: envelope.command,
        };
        self.block(link.dispatch(request)).map(|_| ())
    }

    /// The serving port's current snapshot (the cached one when its
    /// revision is unchanged), and caches it.
    pub fn try_snapshot(&self) -> Result<Arc<Snapshot<S>>, ShellError> {
        let cached = self.inner.snapshot.load();
        let link = &self.inner.link;
        let fresh = self.block(link.snapshot(Some(&cached)))?;
        if !Arc::ptr_eq(&fresh, &cached) {
            self.inner.snapshot.store_arc(Arc::clone(&fresh));
        }
        Ok(fresh)
    }

    /// The serving port's resync reply (control door), and caches its
    /// snapshot.
    pub fn try_resync(&self, after_sequence: u64) -> Result<ResyncReply<V, S>, ShellError> {
        let link = &self.inner.link;
        let reply: ResyncReply<V, S> = self.block(link.resync(after_sequence))?;
        self.inner.snapshot.store_arc(Arc::clone(&reply.snapshot));
        Ok(reply)
    }

    /// Subscribes on the serving port with room for `capacity` events there
    /// and here.
    pub fn try_subscribe(&self, capacity: usize) -> Result<Subscription<V>, ShellError> {
        let (sender, subscription) = subscription_channel(capacity);
        let link = Arc::clone(&self.inner.link);
        let poll = self.inner.poll;
        // The stream's connection and pump live on the stream runtime.
        Self::block_on(
            self.inner.streams.as_ref(),
            self.inner.timeout,
            async move { link.subscribe(capacity, sender, poll).await },
        )?;
        Ok(subscription)
    }

    /// The last snapshot this handle saw, without a round trip.
    pub fn cached_snapshot(&self) -> Arc<Snapshot<S>> {
        self.inner.snapshot.load()
    }
}

impl<C, V, S> Port<C, V, S> for RemoteHandle<C, V, S>
where
    C: Serialize + Send + 'static,
    V: DeserializeOwned + Send + 'static,
    S: DeserializeOwned + Send + Sync + 'static,
{
    fn dispatch(&self, command: C) -> Result<CommandId, DispatchError> {
        self.try_dispatch(command).map_err(dispatch_error)
    }

    fn dispatch_envelope(&self, envelope: CommandEnvelope<C>) -> Result<(), DispatchError> {
        self.try_dispatch_envelope(envelope).map_err(dispatch_error)
    }

    fn snapshot(&self) -> Arc<Snapshot<S>> {
        self.try_snapshot()
            .unwrap_or_else(|_| self.inner.snapshot.load())
    }

    fn subscribe(&self, capacity: usize) -> Result<Subscription<V>, SubscribeError> {
        match self.try_subscribe(capacity) {
            Ok(s) => Ok(s),
            Err(ShellError::Subscribe(e)) => Err(e),
            // The link is down or the door is shut: like a port whose
            // kernel is gone, a subscription that is already disconnected.
            Err(_) => Ok(subscription_channel(capacity).1),
        }
    }

    fn resync(&self, after_sequence: u64) -> ResyncReply<V, S> {
        self.try_resync(after_sequence).unwrap_or_else(|_| {
            let snapshot = self.inner.snapshot.load();
            let sequence = snapshot.through_sequence;
            ResyncReply {
                event_sequence: sequence,
                oldest_available: sequence.saturating_add(1),
                gap: true,
                snapshot,
                events: Vec::new(),
            }
        })
    }
}

fn dispatch_error(e: ShellError) -> DispatchError {
    match e {
        ShellError::Dispatch(d) => d,
        _ => DispatchError::Disconnected,
    }
}
