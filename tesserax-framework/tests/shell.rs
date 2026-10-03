//! Shell behaviour beyond the port contract: the control / observe door
//! split (HTTP and local), snapshot ETag / 304, SSE `id:` and
//! `Last-Event-ID` resume with the gap notice, resync with `gap = true`
//! over both wires, and a real runtime driven through a remote handle.

#![cfg(all(feature = "shell", feature = "client", unix))]

mod common_shell;

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use tesserax::swc::{
    CommandId, CoreEvent, DispatchError, EffectEnvelope, EventEnvelope, Generation,
    ObservationEnvelope, Port, PortConfig, Reject, RejectCode, Snapshot, Subject, bounded_port,
};
use tesserax_framework::shell::wire::{
    ErrorBody, LinkAuthenticate, LinkDoor, LinkHello, LinkReply, LinkReplyFrame, LinkRequest,
    LinkRequestFrame, LinkServerFrame, ResyncNotice, WireError,
};
use tesserax_framework::shell::{RemoteHandle, http_shell};
use tesserax_framework::{Domain, ObservationSink, Runtime, RuntimeConfig, ShellError, Tick};
use tower::ServiceExt;

use common_shell::{CONTROL_KEY, FULL_KEY, OBSERVE_KEY, OBSERVE_SECRET};

type Cmd = u32;
type Ev = u64;
type St = u64;

fn cfg(log: usize) -> PortConfig {
    PortConfig {
        ingress_capacity: 16,
        event_log_capacity: log,
        max_subscribers: 8,
    }
}

fn event(sequence: u64) -> EventEnvelope<Ev> {
    EventEnvelope {
        sequence,
        command_id: None,
        subject: None,
        generation: Generation(0),
        event: CoreEvent::Domain(sequence),
    }
}

fn publish(kernel: &tesserax::swc::KernelPort<Cmd, Ev, St>, from: u64, to: u64) {
    let events = (from..=to).map(event).collect();
    let snapshot = Snapshot {
        revision: to,
        through_sequence: to,
        health: Default::default(),
        state: to,
    };
    kernel.publish(events, snapshot).unwrap();
}

fn router(port: tesserax::swc::Handle<Cmd, Ev, St>) -> axum::Router {
    http_shell(port, common_shell::gate(), common_shell::shell_opts())
        .into_parts()
        .0
}

fn req(method: &str, uri: &str, key: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(k) = key {
        b = b.header(header::AUTHORIZATION, format!("Bearer {k}"));
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

async fn body_of(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_only_key_is_refused_on_the_control_door_over_http() {
    let (handle, kernel) = bounded_port::<Cmd, Ev, St>(cfg(16));
    let app = router(handle);

    // Commands and resync: control door only.
    for (method, uri, body) in [
        ("POST", "/v1/commands", r#"{"command":1}"#),
        ("POST", "/v1/resync", r#"{"after":0}"#),
    ] {
        let resp = app
            .clone()
            .oneshot(req(method, uri, Some(OBSERVE_KEY), body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(
            body_of(resp).await,
            br#"{"ok":false,"error":"unauthorized"}"#
        );
        let resp = app
            .clone()
            .oneshot(req(method, uri, None, body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
        let resp = app
            .clone()
            .oneshot(req(method, uri, Some(CONTROL_KEY), body))
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{uri}: {}", resp.status());
    }
    // Only the control key's command reached the kernel.
    let drained = kernel.drain_commands(16);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].command, 1);

    // Snapshot and events: observe door only.
    for uri in ["/v1/snapshot", "/v1/events"] {
        let resp = app
            .clone()
            .oneshot(req("GET", uri, Some(CONTROL_KEY), ""))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
        let resp = app
            .clone()
            .oneshot(req("GET", uri, Some(OBSERVE_KEY), ""))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    }
}

#[test]
fn observe_only_remote_handle_reads_but_cannot_command() {
    let (handle, kernel) = bounded_port::<Cmd, Ev, St>(cfg(16));
    let served = common_shell::serve_http(handle);
    let observer: RemoteHandle<Cmd, Ev, St> = common_shell::http_remote(&served, OBSERVE_KEY);
    assert!(matches!(
        observer.try_dispatch(5),
        Err(ShellError::Unauthorized { door: "control" })
    ));
    assert_eq!(observer.dispatch(5), Err(DispatchError::Disconnected));
    assert!(matches!(
        observer.try_resync(0),
        Err(ShellError::Unauthorized { door: "control" })
    ));
    assert!(kernel.drain_commands(16).is_empty());

    let sub = observer.subscribe(8).unwrap();
    publish(&kernel, 1, 1);
    assert_eq!(
        sub.recv_timeout(Duration::from_secs(10)).unwrap().sequence,
        1
    );
    assert_eq!(observer.snapshot().revision, 1);

    // A control-only key cannot even open a handle: it reads the snapshot
    // through the observe door first.
    let refused = RemoteHandle::<Cmd, Ev, St>::http(
        tesserax_framework::shell::HttpRemote::new(served.addr.unwrap()).bearer(CONTROL_KEY),
    );
    assert!(matches!(
        refused,
        Err(ShellError::Unauthorized { door: "observe" })
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_etag_is_the_revision_and_if_none_match_answers_304() {
    let (handle, kernel) = bounded_port::<Cmd, Ev, St>(cfg(16));
    let app = router(handle);
    let get = |tag: Option<&str>| {
        let mut r = req("GET", "/v1/snapshot", Some(FULL_KEY), "");
        if let Some(t) = tag {
            r.headers_mut()
                .insert(header::IF_NONE_MATCH, t.parse().unwrap());
        }
        app.clone().oneshot(r)
    };
    let resp = get(None).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::ETAG], "\"0\"");
    let snap: Snapshot<St> = serde_json::from_slice(&body_of(resp).await).unwrap();
    assert_eq!(snap.revision, 0);

    let resp = get(Some("\"0\"")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(resp.headers()[header::ETAG], "\"0\"");
    assert!(body_of(resp).await.is_empty());

    publish(&kernel, 1, 3);
    let resp = get(Some("W/\"0\"")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::ETAG], "\"3\"");
    let snap: Snapshot<St> = serde_json::from_slice(&body_of(resp).await).unwrap();
    assert_eq!((snap.revision, snap.state), (3, 3));
    assert_eq!(
        get(Some("\"1\", \"3\"")).await.unwrap().status(),
        StatusCode::NOT_MODIFIED
    );
}

/// One parsed SSE message: (`id`, `event`, `data`).
type Sse = (Option<u64>, Option<String>, String);

/// Reads SSE messages from `body` until `n` have arrived.
async fn read_sse(body: &mut Body, n: usize) -> Vec<Sse> {
    let mut text = String::new();
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while out.len() < n {
        let left = deadline.saturating_duration_since(Instant::now());
        let frame = tokio::time::timeout(left, body.frame())
            .await
            .expect("sse message in time")
            .expect("stream open")
            .unwrap();
        let Ok(data) = frame.into_data() else {
            continue;
        };
        text.push_str(std::str::from_utf8(&data).unwrap());
        while let Some(end) = text.find("\n\n") {
            let block: String = text.drain(..end + 2).collect();
            let (mut id, mut name, mut data) = (None, None, None);
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("id: ") {
                    id = Some(v.parse().unwrap());
                } else if let Some(v) = line.strip_prefix("event: ") {
                    name = Some(v.to_owned());
                } else if let Some(v) = line.strip_prefix("data: ") {
                    data = Some(v.to_owned());
                }
            }
            if let Some(data) = data {
                out.push((id, name, data));
            }
        }
    }
    out
}

fn ids(messages: &[Sse]) -> Vec<Option<u64>> {
    messages.iter().map(|m| m.0).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn sse_ids_are_sequences_and_last_event_id_resumes() {
    let (handle, kernel) = bounded_port::<Cmd, Ev, St>(cfg(4));
    let app = router(handle);
    publish(&kernel, 1, 5); // log keeps 2..=5
    let open = |last_event_id: Option<&str>, query: &str| {
        let mut r = req("GET", &format!("/v1/events{query}"), Some(FULL_KEY), "");
        if let Some(v) = last_event_id {
            r.headers_mut().insert("last-event-id", v.parse().unwrap());
        }
        app.clone().oneshot(r)
    };

    // Resume after 3: replay 4, 5 with their sequences as ids, then live.
    let resp = open(Some("3"), "").await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");
    let mut body = resp.into_body();
    let got = read_sse(&mut body, 2).await;
    assert_eq!(ids(&got), [Some(4), Some(5)]);
    let envelope: EventEnvelope<Ev> = serde_json::from_str(&got[0].2).unwrap();
    assert_eq!(envelope, event(4));
    publish(&kernel, 6, 6);
    assert_eq!(ids(&read_sse(&mut body, 1).await), [Some(6)]);

    // Last-Event-ID wins over ?after=.
    let mut body = open(Some("5"), "?after=1").await.unwrap().into_body();
    assert_eq!(ids(&read_sse(&mut body, 1).await), [Some(6)]);
    // ?after= alone.
    let mut body = open(None, "?after=4").await.unwrap().into_body();
    assert_eq!(ids(&read_sse(&mut body, 2).await), [Some(5), Some(6)]);

    // Gone from the log: the stream opens with the resync notice (no id),
    // then continues with what is retained (3..=6).
    let mut body = open(Some("0"), "").await.unwrap().into_body();
    let got = read_sse(&mut body, 5).await;
    assert_eq!(got[0].0, None);
    assert_eq!(got[0].1.as_deref(), Some("resync"));
    let notice: ResyncNotice = serde_json::from_str(&got[0].2).unwrap();
    assert_eq!(
        notice,
        ResyncNotice {
            after: 0,
            oldest: 3,
            last: 6
        }
    );
    assert_eq!(ids(&got[1..]), [Some(3), Some(4), Some(5), Some(6)]);

    // Ahead of the log (a restarted kernel): notice, nothing replayed.
    let mut body = open(Some("99"), "").await.unwrap().into_body();
    let got = read_sse(&mut body, 1).await;
    assert_eq!(got[0].1.as_deref(), Some("resync"));
    publish(&kernel, 7, 7);
    assert_eq!(ids(&read_sse(&mut body, 1).await), [Some(7)]);

    let resp = open(Some("seven"), "").await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err: ErrorBody = serde_json::from_slice(&body_of(resp).await).unwrap();
    assert_eq!(err.error, WireError::BadRequest);
}

#[test]
fn resync_over_both_wires_reports_the_gap() {
    for over_local in [false, true] {
        let (handle, kernel) = bounded_port::<Cmd, Ev, St>(cfg(4));
        let served = if over_local {
            common_shell::serve_local(handle)
        } else {
            common_shell::serve_http(handle)
        };
        let remote: RemoteHandle<Cmd, Ev, St> = if over_local {
            common_shell::local_remote(&served, common_shell::server_keys())
        } else {
            common_shell::http_remote(&served, FULL_KEY)
        };
        publish(&kernel, 1, 10); // log keeps 7..=10
        let gap = remote.try_resync(2).unwrap();
        assert!(gap.gap);
        assert_eq!((gap.oldest_available, gap.event_sequence), (7, 10));
        assert_eq!(
            gap.events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            [7, 8, 9, 10]
        );
        assert_eq!(gap.snapshot.through_sequence, 10);
        let ahead = remote.try_resync(12).unwrap();
        assert!(ahead.gap && ahead.events.is_empty());
        let caught_up = remote.try_resync(8).unwrap();
        assert!(!caught_up.gap);
        assert_eq!(caught_up.events.len(), 2);
        // The reply's snapshot is cached for the handle.
        assert_eq!(remote.cached_snapshot().revision, 10);

        // With the server gone the port answers from what it saw last:
        // a gap, no events.
        drop(served);
        let offline = remote.resync(8);
        assert!(offline.gap && offline.events.is_empty());
        assert_eq!(offline.snapshot.through_sequence, 10);
        assert_eq!(remote.dispatch(1), Err(DispatchError::Disconnected));
    }
}

/// A raw client of the local link: handshake for `door` with `secret`.
async fn raw_link(
    endpoint: &std::path::Path,
    door: LinkDoor,
    secret: &[u8],
) -> (
    tokio::io::BufReader<tokio::io::ReadHalf<tesserax_transport::local::LocalClientStream>>,
    tokio::io::WriteHalf<tesserax_transport::local::LocalClientStream>,
    LinkServerFrame,
) {
    use tesserax_transport::proof::{LinkContext, LinkRole, link_proof};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn unhex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
    let stream = tesserax_transport::local::connect_local(endpoint)
        .await
        .unwrap();
    let (r, mut w) = tokio::io::split(stream);
    let mut r = tokio::io::BufReader::new(r);
    let mut line = String::new();
    let client_nonce = [9u8; 32];
    let hello = LinkHello {
        door,
        nonce: hex(&client_nonce),
    };
    w.write_all(format!("{}\n", serde_json::to_string(&hello).unwrap()).as_bytes())
        .await
        .unwrap();
    r.read_line(&mut line).await.unwrap();
    let challenge: LinkServerFrame = serde_json::from_str(&line).unwrap();
    let LinkServerFrame::Challenge { nonce, .. } = &challenge else {
        return (r, w, challenge);
    };
    let cx = LinkContext::new(common_shell::DOMAIN, b"schema-1");
    let proof = link_proof(
        secret,
        door.role_byte(),
        LinkRole::Client,
        &client_nonce,
        &unhex(nonce),
        &cx,
    );
    let auth = LinkAuthenticate { proof: hex(&proof) };
    w.write_all(format!("{}\n", serde_json::to_string(&auth).unwrap()).as_bytes())
        .await
        .unwrap();
    line.clear();
    r.read_line(&mut line).await.unwrap();
    let verdict: LinkServerFrame = serde_json::from_str(&line).unwrap();
    (r, w, verdict)
}

#[test]
fn local_links_serve_only_the_door_they_proved() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let (handle, kernel) = bounded_port::<Cmd, Ev, St>(cfg(16));
    let served = common_shell::serve_local(handle);
    let endpoint = served.endpoint.clone().unwrap();
    let rt = common_shell::runtime();
    rt.block_on(async {
        // Proven for observe, asking to dispatch: refused, nothing enqueued.
        let (mut r, mut w, verdict) = raw_link(&endpoint, LinkDoor::Observe, OBSERVE_SECRET).await;
        assert_eq!(verdict, LinkServerFrame::Ready);
        let frame = LinkRequestFrame {
            id: 7,
            request: LinkRequest::<Cmd>::Dispatch { command: 1 },
        };
        w.write_all(format!("{}\n", serde_json::to_string(&frame).unwrap()).as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        r.read_line(&mut line).await.unwrap();
        let reply: LinkReplyFrame<Ev, St> = serde_json::from_str(&line).unwrap();
        assert_eq!(reply.id, 7);
        assert!(matches!(
            reply.reply,
            LinkReply::Error {
                error: WireError::Unauthorized,
                ..
            }
        ));

        // Claiming the control door with the observe secret: refused at the
        // handshake.
        let (_, _, verdict) = raw_link(&endpoint, LinkDoor::Control, OBSERVE_SECRET).await;
        assert!(matches!(verdict, LinkServerFrame::Refused { .. }));
    });
    assert!(kernel.drain_commands(16).is_empty());

    // Through the handle: an observe-only key set reads and cannot command.
    let observer: RemoteHandle<Cmd, Ev, St> = common_shell::local_remote(
        &served,
        common_shell::link_keys().observe(OBSERVE_SECRET.to_vec()),
    );
    assert!(matches!(
        observer.try_dispatch(1),
        Err(ShellError::Unauthorized { door: "control" })
    ));
    let forged: RemoteHandle<Cmd, Ev, St> = common_shell::local_remote(
        &served,
        common_shell::link_keys()
            .observe(OBSERVE_SECRET.to_vec())
            .control(OBSERVE_SECRET.to_vec()),
    );
    assert!(matches!(
        forged.try_dispatch(1),
        Err(ShellError::Handshake(_))
    ));
    assert!(kernel.drain_commands(16).is_empty());
    assert_eq!(observer.snapshot().revision, 0);
}

/// A counter domain: add to the total; refuse zero.
#[derive(Default)]
struct Counter {
    total: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Added {
    Now(u64),
}

impl Domain for Counter {
    type Command = u64;
    type Effect = ();
    type Observation = ();
    type Event = Added;
    type State = u64;

    fn apply_command(
        &mut self,
        tick: &mut Tick<'_, Self>,
        id: CommandId,
        add: u64,
    ) -> Result<(), Reject> {
        if add == 0 {
            return Err(Reject::new(RejectCode::Invalid, "nothing to add"));
        }
        self.total += add;
        tick.emit(
            Some(id),
            None,
            Generation::default(),
            Added::Now(self.total),
        )?;
        Ok(())
    }

    fn generation_of(&self, _: Subject) -> Option<Generation> {
        None
    }

    fn apply_observation(&mut self, _: &mut Tick<'_, Self>, _: ObservationEnvelope<()>) {}

    fn project(&self) -> u64 {
        self.total
    }
}

#[test]
fn a_runtime_is_driven_through_remote_handles_on_both_wires() {
    let executor = |_: EffectEnvelope<()>, _: &ObservationSink<()>| {};
    let config = RuntimeConfig {
        tick_period: Duration::from_millis(2),
        ..RuntimeConfig::default()
    };
    let (runtime, handle) = Runtime::spawn(Counter::default(), config, executor).unwrap();
    let http_served = common_shell::serve_http(handle.clone());
    let local_served = common_shell::serve_local(handle);
    let over_http: RemoteHandle<u64, Added, u64> =
        common_shell::http_remote(&http_served, FULL_KEY);
    let over_local: RemoteHandle<u64, Added, u64> =
        common_shell::local_remote(&local_served, common_shell::server_keys());

    let events = over_local.subscribe(16).unwrap();
    let a = over_http.dispatch(2).unwrap();
    let b = over_local.dispatch(0).unwrap();
    let c = over_local.dispatch(5).unwrap();
    assert!(a != b && b != c && a != c, "ids come from one port");

    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen.len() < 5 {
        assert!(Instant::now() < deadline, "saw {seen:?}");
        if let Ok(e) = events.recv_timeout(Duration::from_millis(100)) {
            seen.push((e.command_id, e.event));
        }
    }
    assert!(seen.contains(&(Some(a), CoreEvent::Domain(Added::Now(2)))));
    assert!(seen.contains(&(Some(a), CoreEvent::Accepted)));
    assert!(seen.iter().any(|(id, e)| *id == Some(b)
        && matches!(e, CoreEvent::Rejected(r) if r.code == RejectCode::Invalid)));
    assert!(seen.contains(&(Some(c), CoreEvent::Domain(Added::Now(7)))));

    let deadline = Instant::now() + Duration::from_secs(10);
    while over_http.snapshot().state != 7 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(over_local.snapshot().state, 7);
    runtime.stop();
    runtime.join().unwrap();
}
