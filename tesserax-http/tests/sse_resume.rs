//! SSE resume over a real listener: a client reads part of the stream,
//! drops the connection, events are published while it is away, and a
//! reconnect with `Last-Event-ID` yields every missed event exactly once
//! and in order, then the live stream.

use std::time::Duration;

use axum::extract::Extension;
use axum::http::HeaderMap;
use tesserax::lifecycle::ShutdownBroadcast;
use tesserax::{ServerBuilder, Transport};
use tesserax_http::push::SseHub;
use tesserax_http::{DocRouter, HttpExt};

#[derive(Debug, PartialEq, Eq)]
struct Ev {
    id: Option<u64>,
    event: Option<String>,
    data: String,
}

/// Reads frames until `n` events are parsed (comments skipped).
async fn read_events(resp: &mut reqwest::Response, buf: &mut String, n: usize) -> Vec<Ev> {
    let mut out = Vec::new();
    while out.len() < n {
        while let Some(pos) = buf.find("\n\n") {
            let frame: String = buf.drain(..pos + 2).collect();
            let mut ev = Ev {
                id: None,
                event: None,
                data: String::new(),
            };
            let mut any = false;
            for line in frame.lines() {
                if let Some(v) = line.strip_prefix("id:") {
                    ev.id = v.trim().parse().ok();
                    any = true;
                } else if let Some(v) = line.strip_prefix("event:") {
                    ev.event = Some(v.trim().to_owned());
                    any = true;
                } else if let Some(v) = line.strip_prefix("data:") {
                    ev.data.push_str(v.trim_start());
                    any = true;
                }
            }
            if any {
                out.push(ev);
                if out.len() == n {
                    return out;
                }
            }
        }
        let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
            .await
            .expect("event within 5 s")
            .expect("read")
            .expect("stream open");
        buf.push_str(std::str::from_utf8(&chunk).unwrap());
    }
    out
}

async fn serve(hub: SseHub) -> tesserax::RunningServer {
    let routes = DocRouter::new().get(
        "/events",
        move |headers: HeaderMap, Extension(sd): Extension<ShutdownBroadcast>| {
            let hub = hub.clone();
            async move { hub.response_until(&headers, sd.subscribe()) }
        },
        "Event stream; honours Last-Event-ID.",
    );
    ServerBuilder::new("sse")
        .transport(Transport::local(0))
        .with_shutdown_timeout(Duration::from_secs(5))
        .with_routes(routes)
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap()
}

async fn connect(addr: std::net::SocketAddr, last: Option<u64>) -> reqwest::Response {
    let mut req = reqwest::Client::new().get(format!("http://{addr}/events"));
    if let Some(id) = last {
        req = req.header("last-event-id", id.to_string());
    }
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    resp
}

async fn wait_subscribers(hub: &SseHub, n: usize) {
    for _ in 0..500 {
        if hub.receiver_count() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("subscriber count never reached {n}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_reconnect_with_last_event_id_no_duplicates_no_gap() {
    let hub = SseHub::new(64, 64);
    let server = serve(hub.clone()).await;
    let addr = server.local_addr();

    let mut first = connect(addr, None).await;
    wait_subscribers(&hub, 1).await;
    for i in 1..=5 {
        hub.publish(format!("m{i}"));
    }
    let mut buf = String::new();
    let seen = read_events(&mut first, &mut buf, 3).await;
    assert_eq!(
        seen.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![Some(1), Some(2), Some(3)]
    );
    assert_eq!(seen[0].data, "m1");
    let last_seen = seen.last().and_then(|e| e.id).unwrap();
    drop(first); // connection dropped; 4 and 5 were in flight and are lost to it
    wait_subscribers(&hub, 0).await;

    for i in 6..=8 {
        hub.publish(format!("m{i}"));
    }
    let mut second = connect(addr, Some(last_seen)).await;
    let mut buf = String::new();
    let replay = read_events(&mut second, &mut buf, 5).await;
    wait_subscribers(&hub, 1).await;
    hub.publish("m9");
    let live = read_events(&mut second, &mut buf, 1).await;

    let all: Vec<Ev> = replay.into_iter().chain(live).collect();
    assert!(
        all.iter().all(|e| e.event.is_none()),
        "no resync expected: {all:?}"
    );
    assert_eq!(
        all.iter().map(|e| e.id.unwrap()).collect::<Vec<_>>(),
        (4..=9).collect::<Vec<u64>>(),
        "every missed event exactly once, in order, then live"
    );
    assert_eq!(
        all.iter().map(|e| e.data.as_str()).collect::<Vec<_>>(),
        ["m4", "m5", "m6", "m7", "m8", "m9"]
    );
    server.shutdown();
    server.wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_exhausted_announces_resync_then_continues() {
    let hub = SseHub::new(64, 3);
    let server = serve(hub.clone()).await;
    for i in 1..=10 {
        hub.publish(format!("m{i}"));
    }
    // The client last saw 2; only 8..=10 are retained.
    let mut resp = connect(server.local_addr(), Some(2)).await;
    let mut buf = String::new();
    let evs = read_events(&mut resp, &mut buf, 4).await;
    assert_eq!(evs[0].event.as_deref(), Some("resync"));
    let notice: serde_json::Value = serde_json::from_str(&evs[0].data).unwrap();
    assert_eq!(
        notice,
        serde_json::json!({"after": 2, "oldest": 8, "last": 10})
    );
    assert_eq!(
        evs[1..].iter().map(|e| e.id.unwrap()).collect::<Vec<_>>(),
        vec![8, 9, 10]
    );
    server.shutdown();
    server.wait().await.unwrap();
}

/// A subscriber that lags behind the live channel is caught up from the
/// history ring: still no gap and no duplicate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lagging_subscriber_is_caught_up_from_history() {
    use futures_util::StreamExt;
    let hub = SseHub::new(2, 1000);
    let stream = hub.subscribe(Some(0));
    for i in 1..=200 {
        hub.publish(format!("m{i}"));
    }
    let evs: Vec<_> = stream.take(200).collect().await;
    assert_eq!(evs.len(), 200);
    let text: Vec<String> = evs
        .into_iter()
        .map(|e| format!("{:?}", e.unwrap()))
        .collect();
    // Event's Debug shows the encoded frame; ids 1..=200 each once.
    for (i, t) in text.iter().enumerate() {
        assert!(t.contains(&format!("id: {}\\n", i + 1)), "{t}");
    }
}

/// `response_until` ends open streams on shutdown instead of holding the
/// graceful drain until its timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_stream_ends_on_shutdown() {
    let hub = SseHub::new(8, 8);
    let server = serve(hub.clone()).await;
    let mut resp = connect(server.local_addr(), None).await;
    wait_subscribers(&hub, 1).await;
    let started = std::time::Instant::now();
    server.shutdown();
    // The body finishes (None) or errors; it does not hang.
    let end = tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(Some(_)) = resp.chunk().await {}
    })
    .await;
    assert!(end.is_ok(), "stream still open after shutdown");
    server.wait().await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
}
