//! The §5.5 tests of the NCP brief: roster validation, the reconcile
//! refusal, parallel poll with a dead entry, attach admission, the
//! percent-encoding fix (N1), and the two-entry mixed-reach case no
//! shipped product covers.
//!
//! Runs under `--features c2,node` (the mixed test wires both tiers).

#![cfg(all(feature = "c2", feature = "node"))]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use tesserax_framework::ncp::c2::C2Builder;
use tesserax_framework::ncp::node::dial_attach;
use tesserax_framework::ncp::{
    AttachError, AttachListener, DownLink, EntryId, Identified, LinkSpec, Method, Oracle,
    OracleError, PollConfig, Roster, RosterEntry, RosterError, reconcile, spawn_poller_with,
};
use tesserax_transport::Endpoint;
use zeroize::Zeroizing;

fn env_of(pairs: &[(&str, &str)]) -> Arc<dyn Fn(&str) -> Option<String> + Send + Sync> {
    let map: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Arc::new(move |name| map.get(name).cloned())
}

// ── roster validation ───────────────────────────────────────────────────

#[test]
fn roster_rejects_duplicate_id() {
    let text = r#"
[[entry]]
id = "dup"
endpoint = "http://127.0.0.1:9001"
reach = "dial-out"
credential = { env = "T_A" }
[[entry]]
id = "dup"
endpoint = "http://127.0.0.1:9002"
reach = "dial-out"
credential = { env = "T_B" }
"#;
    let err = Roster::<LinkSpec>::load_with(text, env_of(&[("T_A", "a"), ("T_B", "b")]).as_ref())
        .unwrap_err();
    match err {
        RosterError::DuplicateId(id) => assert_eq!(id.as_str(), "dup"),
        other => panic!("expected DuplicateId, got {other}"),
    }
}

#[test]
fn roster_rejects_empty() {
    let err = Roster::<LinkSpec>::load_with("", env_of(&[]).as_ref()).unwrap_err();
    assert!(matches!(err, RosterError::Empty), "got {err}");
}

#[test]
fn roster_rejects_empty_endpoint_naming_the_entry() {
    let text = r#"
[[entry]]
id = "broken"
endpoint = ""
reach = "dial-out"
credential = { env = "T_A" }
"#;
    let err = Roster::<LinkSpec>::load_with(text, env_of(&[("T_A", "a")]).as_ref()).unwrap_err();
    match err {
        RosterError::EmptyEndpoint(id) => assert_eq!(id.as_str(), "broken"),
        other => panic!("expected EmptyEndpoint, got {other}"),
    }
}

#[test]
fn roster_names_the_missing_credential_variable() {
    let text = r#"
[[entry]]
id = "wing-1"
endpoint = "http://127.0.0.1:9001"
reach = "dial-out"
credential = { env-by-alias = { prefix = "FLEET_" } }
"#;
    // The alias "wing-1" maps to FLEET_WING_1; absent here.
    let err = Roster::<LinkSpec>::load_with(text, env_of(&[]).as_ref()).unwrap_err();
    match err {
        RosterError::MissingCredential { id, source_name } => {
            assert_eq!(id.as_str(), "wing-1");
            assert_eq!(source_name, "FLEET_WING_1");
        }
        other => panic!("expected MissingCredential, got {other}"),
    }
}

#[test]
fn roster_loads_with_alias_file_and_env_credentials() {
    let dir = std::env::temp_dir().join(format!("ncp-roster-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_file = dir.join("token-b");
    std::fs::write(&token_file, "sekret-b\n").unwrap();
    let text = format!(
        r#"
[[entry]]
id = "wing-1"
endpoint = "http://127.0.0.1:9001"
reach = "dial-out"
credential = {{ env-by-alias = {{ prefix = "FLEET_" }} }}
[[entry]]
id = "wing-2"
endpoint = "http://127.0.0.1:9002"
reach = "accept-in"
credential = {{ file = "{}" }}
"#,
        token_file.display()
    );
    let roster = Roster::<LinkSpec>::load_with(
        text.as_str(),
        env_of(&[("FLEET_WING_1", "sekret-a")]).as_ref(),
    )
    .unwrap();
    assert_eq!(roster.len(), 2);
    let a = roster.get(&EntryId::new("wing-1")).unwrap();
    let token = a
        .credential
        .resolve(a.id(), env_of(&[("FLEET_WING_1", "sekret-a")]).as_ref())
        .unwrap();
    assert_eq!(token.as_str(), "sekret-a");
    let b = roster.get(&EntryId::new("wing-2")).unwrap();
    let token = b.credential.resolve(b.id(), env_of(&[]).as_ref()).unwrap();
    assert_eq!(token.as_str(), "sekret-b");
    let _ = std::fs::remove_dir_all(&dir);
}

// ── reconcile: the mirage refusal ───────────────────────────────────────

struct Claim(Vec<EntryId>);

impl Identified for Claim {
    fn member_ids(&self) -> Vec<EntryId> {
        self.0.clone()
    }
}

#[test]
fn reconcile_never_adds_an_unrostered_id() {
    let text = r#"
[[entry]]
id = "a"
endpoint = "http://127.0.0.1:9001"
reach = "dial-out"
credential = { env = "T_A" }
[[entry]]
id = "b"
endpoint = "http://127.0.0.1:9002"
reach = "dial-out"
credential = { env = "T_B" }
"#;
    let roster =
        Roster::<LinkSpec>::load_with(text, env_of(&[("T_A", "a"), ("T_B", "b")]).as_ref())
            .unwrap();
    let report = Claim(vec![EntryId::new("b"), EntryId::new("stranger")]);
    let out = reconcile(&roster, &report);
    assert_eq!(out.known.len(), 1);
    assert_eq!(out.known[0].id().as_str(), "b");
    assert_eq!(out.unresolved.len(), 1);
    assert_eq!(out.unresolved[0].as_str(), "stranger");
}

// ── parallel poll with a dead entry ─────────────────────────────────────

struct HealthOracle;

impl Oracle for HealthOracle {
    type Report = Value;
    fn pull<'a>(&'a self, link: &'a DownLink) -> BoxFuture<'a, Result<Self::Report, OracleError>> {
        Box::pin(async move { link.health().await.map_err(OracleError::Link) })
    }
}

async fn serve_tcp(router: axum::Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_is_parallel_and_one_dead_entry_delays_nobody() {
    // Slow but alive: answers /health after 400 ms.
    let live = serve_tcp(axum::Router::new().route(
        "/health",
        axum::routing::get(|| async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            axum::Json(json!({"status": "ok"}))
        }),
    ))
    .await;
    // Dark: accepts and never answers.
    let dark_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dark = dark_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = dark_listener.accept().await {
            held.push(stream); // hold the connection open, say nothing
        }
    });

    let text = format!(
        r#"
[[entry]]
id = "dark"
endpoint = "http://{dark}"
reach = "dial-out"
credential = {{ env = "T_DARK" }}
[[entry]]
id = "live"
endpoint = "http://{live}"
reach = "dial-out"
credential = {{ env = "T_LIVE" }}
"#
    );
    let env = env_of(&[("T_DARK", "x"), ("T_LIVE", "y")]);
    let roster = Roster::<LinkSpec>::load_with(text.as_str(), env.as_ref()).unwrap();
    let cfg = PollConfig {
        interval: Duration::from_secs(60),
        per_entry_timeout: Duration::from_millis(800),
    };
    let started = Instant::now();
    let cache = spawn_poller_with(roster, HealthOracle, cfg, env);
    let views = loop {
        let snapshot = cache.snapshot();
        if snapshot.len() == 2 {
            break snapshot;
        }
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "first round never finished"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    // Sequential would cost dark(800 ms) + live(400 ms) = 1.2 s; parallel
    // costs max(800, 400) = 800 ms.
    assert!(
        started.elapsed() < Duration::from_millis(1050),
        "round took {:?} — polling is not parallel",
        started.elapsed()
    );
    let live_view = views.iter().find(|v| v.entry.as_str() == "live").unwrap();
    assert!(
        live_view.reachable,
        "live entry must be fresh: {live_view:?}"
    );
    assert!(live_view.error.is_none());
    let dark_view = views.iter().find(|v| v.entry.as_str() == "dark").unwrap();
    assert!(!dark_view.reachable);
    assert!(
        dark_view
            .error
            .as_deref()
            .is_some_and(|e| e.contains("timed out")),
        "dark entry must fail by timeout: {dark_view:?}"
    );
}

// ── N1: query pairs are percent-encoded ─────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_values_cannot_inject_parameters() {
    let addr = serve_tcp(axum::Router::new().route(
        "/echo",
        axum::routing::get(
            |axum::extract::RawQuery(query): axum::extract::RawQuery| async move {
                query.unwrap_or_default()
            },
        ),
    ))
    .await;
    let link = DownLink::with_token(
        EntryId::new("n1"),
        Endpoint::Http(format!("http://{addr}")),
        Zeroizing::new("k".to_owned()),
    );
    let response = link
        .raw(
            Method::GET,
            "/echo",
            &[("q", "a&b=c"), ("x", "1 2")],
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    // The server saw exactly two parameters: nothing injected through
    // the `&` or `=` inside the value, the space is %20 not a separator.
    assert_eq!(
        String::from_utf8(response.body.to_vec()).unwrap(),
        "q=a%26b%3Dc&x=1%202"
    );
}

// ── attach admission ────────────────────────────────────────────────────

const DOMAIN: &[u8] = b"ncp-test\0";
const BINDING: &[u8] = b"v1";

fn tokens(pairs: &[(&str, &str)]) -> BTreeMap<EntryId, Zeroizing<String>> {
    pairs
        .iter()
        .map(|(k, v)| (EntryId::new(*k), Zeroizing::new(v.to_string())))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_refuses_an_id_absent_from_the_roster() {
    let mut listener = AttachListener::bind_with_tokens(
        &Endpoint::Http("http://127.0.0.1:0".into()),
        tokens(&[("known", "pw")]),
        DOMAIN,
        BINDING,
    )
    .await
    .unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = Endpoint::Http(format!("http://{addr}"));

    // The accept side must be polled for handshakes to run at all: a
    // dial before it just sits in the TCP backlog. One accept() admits
    // one rostered entry; refused diallers are swallowed by its loop.
    let accept = tokio::spawn(async move { listener.accept().await });

    // Unknown id: the dialler is told so, and the listener serves on.
    let err = dial_attach(
        &endpoint,
        &EntryId::new("stranger"),
        Zeroizing::new("pw".to_owned()),
        DOMAIN,
        BINDING,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AttachError::NotOnRoster(ref id) if id.as_str() == "stranger"),
        "got {err}"
    );

    // Known id, wrong token: the acceptor's proof must not match.
    let err = dial_attach(
        &endpoint,
        &EntryId::new("known"),
        Zeroizing::new("nope".to_owned()),
        DOMAIN,
        BINDING,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AttachError::Proof(_)), "got {err}");

    // Known id, right token: admitted, and the stream carries bytes.
    let mut node_side = dial_attach(
        &endpoint,
        &EntryId::new("known"),
        Zeroizing::new("pw".to_owned()),
        DOMAIN,
        BINDING,
    )
    .await
    .unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    node_side.stream.write_all(b"hi").await.unwrap();
    let (id, mut tier_side) = accept.await.unwrap().unwrap();
    assert_eq!(id.as_str(), "known");
    let mut buf = [0u8; 2];
    tier_side.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");
}

// ── the mixed-reach case: one process, per-entry reach and transport ────

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_tier_serves_local_dialout_and_http_acceptin_together() {
    // Entry A: local socket, this tier dials out. The socket serves
    // /health over HTTP, gated by the roster token.
    let dir = std::env::temp_dir().join(format!("ncp-mix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let socket = dir.join("svc-a.sock");
    let router = axum::Router::new().route(
        "/health",
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            let ok = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                == Some("Bearer sekret-a");
            if ok {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(json!({"status": "ok"})),
                )
            } else {
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    axum::Json(json!({"error": "no"})),
                )
            }
        }),
    );
    let local_listener = tesserax_transport::local::OwnerOnlyListener::bind(&socket)
        .await
        .unwrap();
    tokio::spawn(tesserax_transport::serve_ipc(
        local_listener,
        router,
        std::future::pending(),
    ));

    // Entry B: HTTP, the entry dials in (accept-in) — port 0, the real
    // port comes back from the bound listener. Reach and transport are
    // per entry, in ONE process — the case no product covers today.
    let text = format!(
        r#"
[[entry]]
id = "svc-a"
endpoint = "unix:{}"
reach = "dial-out"
credential = {{ env = "MIX_A" }}
[[entry]]
id = "node-b"
endpoint = "http://127.0.0.1:0"
reach = "accept-in"
credential = {{ env = "MIX_B" }}
"#,
        socket.display()
    );
    let env = env_of(&[("MIX_A", "sekret-a"), ("MIX_B", "pw-b")]);
    let roster = Roster::<LinkSpec>::load_with(text.as_str(), env.as_ref()).unwrap();

    let mut tier = C2Builder::new()
        .below(roster)
        .attach_context(DOMAIN, BINDING)
        .env(env)
        .oracle(
            HealthOracle,
            PollConfig {
                interval: Duration::from_secs(60),
                per_entry_timeout: Duration::from_secs(2),
            },
        )
        .build()
        .await
        .unwrap();

    // Dial-out side: exactly one down link (B is accept-in), and it
    // answers health over the local socket with the roster token.
    assert_eq!(tier.links().count(), 1);
    let a = tier
        .link(&EntryId::new("svc-a"))
        .expect("dial-out link for A");
    let health = a.health().await.unwrap();
    assert_eq!(health["status"], "ok");

    // Accept-in side: B dials, is admitted by roster id + proof.
    assert_eq!(tier.attach_listeners().len(), 1);
    let b_addr = tier.attach_listeners()[0].local_addr().unwrap();
    let endpoint = Endpoint::Http(format!("http://{b_addr}"));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let accept = tokio::spawn(async move {
        let admitted = tier.attach_listeners()[0].accept().await;
        let _ = tx.send(admitted);
    });
    let link = dial_attach(
        &endpoint,
        &EntryId::new("node-b"),
        Zeroizing::new("pw-b".to_owned()),
        DOMAIN,
        BINDING,
    )
    .await
    .unwrap();
    assert_eq!(link.id.as_str(), "node-b");
    let (admitted, _stream) = rx.await.unwrap().unwrap();
    accept.await.unwrap();
    assert_eq!(admitted.as_str(), "node-b");

    let _ = std::fs::remove_dir_all(&dir);
}
