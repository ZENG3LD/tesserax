//! [`http_shell`]: a port served as four self-describing routes.

use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{MatchedPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tesserax::error::NameError;
use tesserax::swc::Port;
use tesserax::{DoorName, HttpMethod, RouteEntry, Scope, Tier};
use tesserax_auth::{AuthGate, Denial};
use tesserax_http::{DocRouter, RouteDoc};

use super::feed::{self, FeedItem};
use super::wire::{
    COMMANDS_PATH, CommandRequest, Dispatched, EVENTS_PATH, ErrorBody, EventsQuery, LAST_EVENT_ID,
    RESYNC_EVENT, RESYNC_PATH, ResyncRequest, SNAPSHOT_PATH, WireError,
};

/// Default subscriber queue of `GET /v1/events` without `capacity`.
pub const DEFAULT_SUBSCRIPTION_CAPACITY: usize = 256;

/// How [`http_shell`] (and, for the feed, `local_shell`) serves a port.
///
/// Door split: `POST /v1/commands` and `POST /v1/resync` are admitted only
/// through `control_door`, `GET /v1/snapshot` and `GET /v1/events` only
/// through `observe_door`, each at its tier (and scope, if set). A key
/// that may do both carries a grant for each door. A tier of `Public`
/// without a scope opens that door to everyone, as it does for any route.
#[derive(Clone, Debug)]
pub struct ShellOpts {
    /// Door of commands and resync.
    pub control_door: DoorName,
    /// Door of snapshot and events.
    pub observe_door: DoorName,
    /// Minimum tier on the control door (default `Authenticated`).
    pub control_tier: Tier,
    /// Minimum tier on the observe door (default `Authenticated`).
    pub observe_tier: Tier,
    /// Scope required on the control door.
    pub control_scope: Option<Scope>,
    /// Scope required on the observe door.
    pub observe_scope: Option<Scope>,
    /// Subscriber queue when a client names none.
    pub default_capacity: usize,
    /// SSE keep-alive comment interval (also how soon a vanished client is
    /// noticed on an idle stream).
    pub keep_alive: Duration,
    /// How often a feed thread checks that its client is still there.
    pub feed_poll: Duration,
}

impl ShellOpts {
    /// Doors `control_door` / `observe_door`, both at `Authenticated`.
    pub fn new(control_door: DoorName, observe_door: DoorName) -> Self {
        Self {
            control_door,
            observe_door,
            control_tier: Tier::Authenticated,
            observe_tier: Tier::Authenticated,
            control_scope: None,
            observe_scope: None,
            default_capacity: DEFAULT_SUBSCRIPTION_CAPACITY,
            keep_alive: Duration::from_secs(15),
            feed_poll: Duration::from_millis(50),
        }
    }

    /// Doors named `control` and `observe`.
    pub fn standard() -> Result<Self, NameError> {
        Ok(Self::new(
            DoorName::new("control")?,
            DoorName::new("observe")?,
        ))
    }

    /// Tier of the control door.
    pub fn control_tier(mut self, tier: Tier) -> Self {
        self.control_tier = tier;
        self
    }

    /// Tier of the observe door.
    pub fn observe_tier(mut self, tier: Tier) -> Self {
        self.observe_tier = tier;
        self
    }

    /// Scope required on the control door.
    pub fn control_scope(mut self, scope: Scope) -> Self {
        self.control_scope = Some(scope);
        self
    }

    /// Scope required on the observe door.
    pub fn observe_scope(mut self, scope: Scope) -> Self {
        self.observe_scope = Some(scope);
        self
    }

    /// SSE keep-alive interval.
    pub fn keep_alive(mut self, every: Duration) -> Self {
        self.keep_alive = every;
        self
    }

    /// Feed thread poll interval.
    pub fn feed_poll(mut self, every: Duration) -> Self {
        self.feed_poll = every;
        self
    }
}

struct Shared<P, C, V, S> {
    port: Arc<P>,
    opts: ShellOpts,
    _types: PhantomData<fn(C) -> (V, S)>,
}

type St<P, C, V, S> = State<Arc<Shared<P, C, V, S>>>;

/// Serves `port` as `POST /v1/commands`, `GET /v1/snapshot`,
/// `GET /v1/events` and `POST /v1/resync` (wire form in
/// [`wire`](super::wire)), each route checked by `gate` restricted to its
/// door (see [`ShellOpts`]).
///
/// The router records every route with its description and tier, so
/// `HttpExt::with_routes` puts them in a server's route table (OpenAPI,
/// and a server-wide gate, see them too). The door check runs on the
/// routes themselves, so it holds even when the server installs no gate.
/// Port calls are made on the async handler; `port` must not block (the
/// in-process `Handle` never does).
pub fn http_shell<P, C, V, S>(port: P, gate: AuthGate, opts: ShellOpts) -> DocRouter
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    let doc = |text: &str, door: &DoorName, tier: Tier, scope: &Option<Scope>| {
        let d = RouteDoc::bearer(text)
            .tier(tier)
            .label("door", door.as_str());
        match scope {
            Some(s) => d.scope(s.clone()),
            None => d,
        }
    };
    let control = DoorCheck {
        gate: gate.clone(),
        door: opts.control_door.clone(),
        tier: opts.control_tier,
        scope: opts.control_scope.clone(),
    };
    let observe = DoorCheck {
        gate,
        door: opts.observe_door.clone(),
        tier: opts.observe_tier,
        scope: opts.observe_scope.clone(),
    };
    let control_routes = DocRouter::new()
        .post(
            COMMANDS_PATH,
            post_command::<P, C, V, S>,
            doc(
                "Enqueue one command; answers its id or why the ingress refused it.",
                &opts.control_door,
                opts.control_tier,
                &opts.control_scope,
            ),
        )
        .post(
            RESYNC_PATH,
            post_resync::<P, C, V, S>,
            doc(
                "Current snapshot plus every retained event after `after`; `gap` tells whether events were lost.",
                &opts.control_door,
                opts.control_tier,
                &opts.control_scope,
            ),
        );
    let observe_routes = DocRouter::new()
        .get(
            SNAPSHOT_PATH,
            get_snapshot::<P, C, V, S>,
            doc(
                "Current snapshot; ETag is the revision, If-None-Match answers 304.",
                &opts.observe_door,
                opts.observe_tier,
                &opts.observe_scope,
            ),
        )
        .get(
            EVENTS_PATH,
            get_events::<P, C, V, S>,
            doc(
                "Server-Sent Events, id = sequence; resumes after Last-Event-ID or `after`, `resync` event on a gap.",
                &opts.observe_door,
                opts.observe_tier,
                &opts.observe_scope,
            ),
        );
    let shared = Arc::new(Shared {
        port: Arc::new(port),
        opts,
        _types: PhantomData,
    });
    let control_routes = control_routes
        .with_state(Arc::clone(&shared))
        .route_layer(from_fn_with_state(Arc::new(control), door_mw));
    let observe_routes = observe_routes
        .with_state(shared)
        .route_layer(from_fn_with_state(Arc::new(observe), door_mw));
    control_routes.merge(observe_routes)
}

/// The gate decision for one door.
struct DoorCheck {
    gate: AuthGate,
    door: DoorName,
    tier: Tier,
    scope: Option<Scope>,
}

async fn door_mw(State(check): State<Arc<DoorCheck>>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    let Some(path) = parts
        .extensions
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
    else {
        return Denial::Misconfigured.into_response();
    };
    let method = match HttpMethod::parse(parts.method.as_str()) {
        Some(HttpMethod::Head) => HttpMethod::Get,
        Some(m) => m,
        None => return Denial::Unauthorized.into_response(),
    };
    let mut entry = RouteEntry::new(method, path, check.tier);
    if let Some(scope) = &check.scope {
        entry = entry.with_scope(scope.clone());
    }
    match check.gate.check(&parts, &entry, Some(&check.door)).await {
        Err(denial) => denial.into_response(),
        Ok(principal) => {
            if let Some(p) = principal {
                parts.extensions.insert(p);
            }
            next.run(Request::from_parts(parts, body)).await
        }
    }
}

fn json<T: Serialize + ?Sized>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut resp = (status, body).into_response();
            let h = resp.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(e) => refuse(WireError::Unavailable, format!("encoding failed: {e}")),
    }
}

fn refuse(error: WireError, message: impl Into<String>) -> Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::BAD_REQUEST);
    let body = ErrorBody::new(error, message);
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    let mut resp = (status, bytes).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if error == WireError::Full {
        h.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    resp
}

async fn post_command<P, C, V, S>(State(sh): St<P, C, V, S>, body: Bytes) -> Response
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    let request: CommandRequest<C> = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return refuse(WireError::BadRequest, e.to_string()),
    };
    let result = match request.id {
        Some(id) => sh
            .port
            .dispatch_envelope(tesserax::swc::CommandEnvelope {
                id,
                command: request.command,
            })
            .map(|()| id),
        None => sh.port.dispatch(request.command),
    };
    match result {
        Ok(id) => json(StatusCode::ACCEPTED, &Dispatched { id }),
        Err(e) => refuse(WireError::from_dispatch(e), e.to_string()),
    }
}

async fn post_resync<P, C, V, S>(State(sh): St<P, C, V, S>, body: Bytes) -> Response
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    let request: ResyncRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return refuse(WireError::BadRequest, e.to_string()),
    };
    json(StatusCode::OK, &sh.port.resync(request.after))
}

/// The revision an `If-None-Match` value names (`"7"`, `W/"7"`, a list),
/// or `Some(None)` for `*`.
fn if_none_match(headers: &HeaderMap) -> Vec<Option<u64>> {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|tag| {
            let tag = tag.trim();
            if tag == "*" {
                return Some(None);
            }
            let tag = tag.strip_prefix("W/").unwrap_or(tag);
            tag.strip_prefix('"')?
                .strip_suffix('"')?
                .parse()
                .ok()
                .map(Some)
        })
        .collect()
}

fn etag(revision: u64) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("\"{revision}\"")).ok()
}

async fn get_snapshot<P, C, V, S>(State(sh): St<P, C, V, S>, headers: HeaderMap) -> Response
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    let snapshot = sh.port.snapshot();
    let revision = snapshot.revision;
    let mut resp = if if_none_match(&headers)
        .into_iter()
        .any(|t| t.is_none_or(|r| r == revision))
    {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        json(StatusCode::OK, &*snapshot)
    };
    let h = resp.headers_mut();
    if let Some(tag) = etag(revision) {
        h.insert(header::ETAG, tag);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

async fn get_events<P, C, V, S>(
    State(sh): St<P, C, V, S>,
    query: Result<Query<EventsQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Response
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    let Ok(Query(query)) = query else {
        return refuse(WireError::BadRequest, "bad query");
    };
    let last_event_id = match headers.get(LAST_EVENT_ID).map(|v| v.to_str()) {
        None => None,
        Some(Ok(v)) => match v.trim().parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => return refuse(WireError::BadRequest, "Last-Event-ID is not a sequence"),
        },
        Some(Err(_)) => return refuse(WireError::BadRequest, "Last-Event-ID is not a sequence"),
    };
    let resume = last_event_id.or(query.after);
    let capacity = query.capacity.unwrap_or(sh.opts.default_capacity);
    let subscription = match sh.port.subscribe(capacity) {
        Ok(s) => s,
        Err(e) => return refuse(WireError::from_subscribe(e), e.to_string()),
    };
    let Some(rx) = feed::start(
        Arc::clone(&sh.port),
        subscription,
        resume,
        sh.opts.feed_poll,
    ) else {
        return refuse(WireError::Unavailable, "no feed thread");
    };
    let events = stream::unfold(rx, |mut rx| async move {
        let event = sse_event(rx.recv().await?)?;
        Some((Ok::<Event, Infallible>(event), rx))
    });
    let mut resp = Sse::new(events)
        .keep_alive(KeepAlive::new().interval(sh.opts.keep_alive))
        .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The SSE form of a feed item; `None` (ending the stream) if it cannot be
/// encoded.
fn sse_event<V: Serialize>(item: FeedItem<V>) -> Option<Event> {
    match item {
        FeedItem::Event(event) => {
            let data = serde_json::to_string(&event).ok()?;
            Some(Event::default().id(event.sequence.to_string()).data(data))
        }
        FeedItem::Resync(notice) => {
            let data = serde_json::to_string(&notice).ok()?;
            Some(Event::default().event(RESYNC_EVENT).data(data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_none_match_forms() {
        let mut h = HeaderMap::new();
        h.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("W/\"7\", \"9\""),
        );
        assert_eq!(if_none_match(&h), [Some(7), Some(9)]);
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert_eq!(if_none_match(&h), [None]);
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"x\""));
        assert!(if_none_match(&h).is_empty());
    }
}
