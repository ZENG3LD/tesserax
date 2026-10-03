//! Server half: builder validation, built-in probes, layer order, plugins,
//! live listeners.
#![cfg(feature = "server")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Extension, Request};
use axum::http::{Request as HttpRequest, StatusCode};
use axum::middleware::{self, Next};
use axum::routing::{get, post};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

use tesserax::lifecycle::{DependencyCheck, DrainState, hook};
use tesserax::{
    BuildCx, BuildError, HttpMethod, LayerStage, ReloadConfig, RequestId, RouteEntry, RouteTable,
    ServerBuilder, ServerPlugin, StartedInfo, Tier, TlsConfig, Transport,
};

fn loopback() -> Transport {
    Transport::local(0)
}

fn base(name: &str) -> ServerBuilder {
    ServerBuilder::new(name).transport(loopback()).get_tier(
        "/ping",
        get(|| async { "pong" }),
        Tier::Public,
    )
}

async fn call(router: &Router, method: &str, uri: &str) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

/// Minimal HTTP/1.1 client: one request per connection.
async fn http(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text[9..12].parse().unwrap();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

// ---- builder (ports of the satellite-free builder tests of the source toolkit) ----------------

#[tokio::test]
async fn builder_builds_minimal_loopback_server() {
    let server = base("minimal").build().await.expect("build");
    assert_eq!(server.name(), "minimal");
    assert_eq!(
        server.bind(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    );
    let (status, body) = call(&server.router(), "GET", "/ping").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Value::String("pong".into()));
}

#[tokio::test]
async fn builder_without_transport_is_rejected() {
    let err = ServerBuilder::new("x").build().await.unwrap_err();
    assert!(matches!(err, BuildError::MissingTransport));
}

#[tokio::test]
async fn tls_and_ipc_transports_need_an_extension() {
    let tls = Transport::Tls {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        tls: TlsConfig::from_paths("cert.pem", "key.pem"),
    };
    for t in [
        tls,
        Transport::Ipc {
            socket_path: "x.sock".into(),
        },
    ] {
        let err = ServerBuilder::new("x")
            .transport(t)
            .build()
            .await
            .unwrap_err();
        assert!(matches!(err, BuildError::TransportNotWired { .. }), "{err}");
    }
}

#[tokio::test]
async fn duplicate_and_invalid_routes_are_rejected() {
    let dup = base("dup").get_tier("/ping", get(|| async { "again" }), Tier::Public);
    assert!(matches!(
        dup.build().await.unwrap_err(),
        BuildError::DuplicateRoute { .. }
    ));

    let reserved = base("res").post_tier("/health", post(|| async { "" }), Tier::Public);
    assert!(matches!(
        reserved.build().await.unwrap_err(),
        BuildError::InvalidRoute { .. }
    ));

    for bad in ["nope", "/items/:id", "/files/*rest"] {
        let b = base("bad").get_tier(bad, get(|| async { "" }), Tier::Public);
        assert!(
            matches!(
                b.build().await.unwrap_err(),
                BuildError::InvalidRoute { .. }
            ),
            "{bad}"
        );
    }
    // Same path, different verbs is fine; `{param}` templates are fine.
    base("ok")
        .post_tier("/ping", post(|| async { "posted" }), Tier::Public)
        .get_tier("/items/{id}", get(|| async { "" }), Tier::Public)
        .build()
        .await
        .expect("build");
}

#[tokio::test]
async fn admin_route_without_gate_on_a_reachable_transport_is_rejected() {
    // Even with no user admin route, the built-in POST /admin/drain is Admin.
    let err = ServerBuilder::new("open")
        .transport(Transport::public(0))
        .build()
        .await
        .unwrap_err();
    match err {
        BuildError::UnauthenticatedAdminRoute { method, path, tier } => {
            assert_eq!(
                (method, path.as_str(), tier),
                (HttpMethod::Post, "/admin/drain", Tier::Admin)
            );
        }
        other => panic!("unexpected {other}"),
    }

    // A gate at TierGate makes it acceptable.
    ServerBuilder::new("gated")
        .transport(Transport::public(0))
        .layer_at(LayerStage::TierGate, |r| r)
        .build()
        .await
        .expect("gated build");

    // Loopback-only transports are allowed without a gate.
    ServerBuilder::new("local")
        .transport(Transport::Dual {
            public_addr: "127.0.0.1:0".parse().unwrap(),
            admin_port: 0,
        })
        .get_tier("/root-only", get(|| async { "" }), Tier::Root)
        .build()
        .await
        .expect("loopback build");
}

// ---- built-in probes behave as before ------------------------------------------

#[tokio::test]
async fn health_livez_readyz_and_drain_behave_as_before() {
    let server = base("probes").build().await.unwrap();
    let router = server.router();

    assert_eq!(
        call(&router, "GET", "/health").await,
        (StatusCode::OK, serde_json::json!({"ok": true}))
    );
    assert_eq!(
        call(&router, "GET", "/livez").await,
        (StatusCode::OK, serde_json::json!({"ok": true}))
    );
    assert_eq!(
        call(&router, "GET", "/readyz").await,
        (
            StatusCode::OK,
            serde_json::json!({"ready": true, "reason": null})
        )
    );
    assert_eq!(
        call(&router, "POST", "/admin/drain").await,
        (
            StatusCode::OK,
            serde_json::json!({"ok": true, "draining": true})
        )
    );
    assert!(server.drain_state().is_draining());
    assert_eq!(
        call(&router, "GET", "/readyz").await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"ready": false, "reason": "draining"})
        )
    );
    // Liveness and health are unaffected by drain.
    assert_eq!(call(&router, "GET", "/livez").await.0, StatusCode::OK);
    assert_eq!(call(&router, "GET", "/health").await.0, StatusCode::OK);
    // Wrong verb on a built-in.
    assert_eq!(
        call(&router, "GET", "/admin/drain").await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn detail_health_reports_dependencies_and_503_on_failure() {
    let server = base("detail")
        .version("1.2.3")
        .with_dependency_check(DependencyCheck::new("db", || async { Ok(()) }))
        .with_dependency_check(DependencyCheck::new("upstream", || async {
            Err("refused".into())
        }))
        .with_background_task("sweep", Duration::from_secs(3600), || async { Ok(()) })
        .build()
        .await
        .unwrap();
    let (status, body) = call(&server.router(), "GET", "/health").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["ok"], false);
    assert_eq!(body["service"], "detail");
    assert_eq!(body["version"], "1.2.3");
    assert_eq!(body["dependencies"][1]["status"], "error");
    assert_eq!(body["background_tasks"][0], "sweep");
}

#[tokio::test]
async fn reload_endpoint_runs_the_hook() {
    let count = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&count);
    let server = base("reload")
        .with_reload(ReloadConfig::default())
        .on_reload(hook(move |_ctx| {
            let c = Arc::clone(&c);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }))
        .build()
        .await
        .unwrap();
    assert!(
        server
            .route_table()
            .lookup(HttpMethod::Post, "/reload")
            .is_some()
    );
    let (status, body) = call(&server.router(), "POST", "/reload").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "reload accepted");
    assert_eq!(count.load(Ordering::SeqCst), 1);

    let without = base("no-reload").build().await.unwrap();
    assert!(
        without
            .route_table()
            .lookup(HttpMethod::Post, "/reload")
            .is_none()
    );
    assert_eq!(
        call(&without.router(), "POST", "/reload").await.0,
        StatusCode::NOT_FOUND
    );
}

// ---- layers, extensions ---------------------------------------------------------

type Trace = Arc<Mutex<Vec<LayerStage>>>;

fn tracing_layer(
    trace: Trace,
    stage: LayerStage,
) -> impl FnOnce(Router) -> Router + Send + 'static {
    move |r: Router| {
        r.layer(middleware::from_fn(move |req: Request, next: Next| {
            let trace = Arc::clone(&trace);
            async move {
                trace.lock().unwrap().push(stage);
                next.run(req).await
            }
        }))
    }
}

/// The documented order (innermost first). There is no written layer-order
/// table in the imported source; this is the order in which its router
/// assembly applies layers, except that idempotency moved inside the gate
/// (owner ruling 2026-09-30): idempotency inside the tier rate limit inside
/// the tier gate, all three as route layers, so both see the admitted
/// caller; then body limit, metrics, etag, csrf, response signing,
/// traceparent, request id, ip acl + auth ban, compression, cors + security
/// headers, access log, server timing).
const DOCUMENTED_ORDER: [LayerStage; 15] = [
    LayerStage::Idempotency,
    LayerStage::TierRateLimit,
    LayerStage::TierGate,
    LayerStage::BodyLimit,
    LayerStage::Metrics,
    LayerStage::Etag,
    LayerStage::Csrf,
    LayerStage::ResponseSigning,
    LayerStage::Traceparent,
    LayerStage::RequestId,
    LayerStage::PeerGuard,
    LayerStage::Compression,
    LayerStage::Decorate,
    LayerStage::AccessLog,
    LayerStage::ServerTiming,
];

#[tokio::test]
async fn layer_stage_order_equals_documented_order() {
    assert_eq!(LayerStage::ALL, DOCUMENTED_ORDER);
    let mut sorted = LayerStage::ALL;
    sorted.sort();
    assert_eq!(sorted, DOCUMENTED_ORDER, "Ord follows the stack order");

    // Behaviour: install one recording layer per stage, in scrambled order;
    // a request must meet them outermost first.
    let trace: Trace = Arc::default();
    let mut b = base("order");
    for i in 0..LayerStage::ALL.len() {
        let stage = LayerStage::ALL[(i * 7) % LayerStage::ALL.len()];
        b = b.layer_at(stage, tracing_layer(Arc::clone(&trace), stage));
    }
    let server = b.build().await.unwrap();
    let (status, _) = call(&server.router(), "GET", "/ping").await;
    assert_eq!(status, StatusCode::OK);
    let seen = trace.lock().unwrap().clone();
    let mut expected = DOCUMENTED_ORDER.to_vec();
    expected.reverse();
    assert_eq!(seen, expected);

    // Public probes bypass the route-scoped stages only.
    trace.lock().unwrap().clear();
    call(&server.router(), "GET", "/livez").await;
    let seen = trace.lock().unwrap().clone();
    assert!(!seen.contains(&LayerStage::TierGate));
    assert!(!seen.contains(&LayerStage::TierRateLimit));
    assert!(!seen.contains(&LayerStage::Idempotency));
    assert!(seen.contains(&LayerStage::ServerTiming));
    // The admin built-in is gated.
    trace.lock().unwrap().clear();
    call(&server.router(), "POST", "/admin/drain").await;
    assert!(trace.lock().unwrap().contains(&LayerStage::TierGate));
}

#[tokio::test]
async fn gate_at_tier_gate_can_refuse_gated_routes_only() {
    let server = ServerBuilder::new("gate")
        .transport(Transport::public(0))
        .get_tier("/secret", get(|| async { "s" }), Tier::Admin)
        .layer_at(LayerStage::TierGate, |r: Router| {
            r.route_layer(middleware::from_fn(|_req: Request, _next: Next| async {
                StatusCode::UNAUTHORIZED
            }))
        })
        .build()
        .await
        .unwrap();
    let router = server.router();
    assert_eq!(
        call(&router, "GET", "/secret").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&router, "POST", "/admin/drain").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(call(&router, "GET", "/health").await.0, StatusCode::OK);
    assert!(!server.drain_state().is_draining());
}

#[tokio::test]
async fn extensions_are_injected() {
    #[derive(Clone)]
    struct Greeting(&'static str);
    let server = base("ext")
        .extension(Greeting("hi"))
        .get_tier(
            "/ext",
            get(
                |Extension(g): Extension<Greeting>,
                 Extension(t): Extension<Arc<RouteTable>>,
                 Extension(d): Extension<DrainState>| async move {
                    format!("{} {} {}", g.0, t.len(), d.is_draining())
                },
            ),
            Tier::Public,
        )
        .build()
        .await
        .unwrap();
    let (status, body) = call(&server.router(), "GET", "/ext").await;
    assert_eq!(status, StatusCode::OK);
    // /ping, /ext, /health, /livez, /readyz, /admin/drain
    assert_eq!(body, Value::String("hi 6 false".into()));
}

#[tokio::test]
async fn request_id_is_minted_or_propagated() {
    let server = base("rid")
        .get_tier(
            "/rid",
            get(|Extension(id): Extension<RequestId>| async move { id.to_string() }),
            Tier::Public,
        )
        .build()
        .await
        .unwrap();
    let resp = server
        .router()
        .oneshot(
            HttpRequest::builder()
                .uri("/rid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let header = resp
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(header.len(), 36);
    assert_eq!(String::from_utf8(body.to_vec()).unwrap(), header);

    let resp = server
        .router()
        .oneshot(
            HttpRequest::builder()
                .uri("/rid")
                .header("x-request-id", "trace-1-abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.headers().get("x-request-id").unwrap(), "trace-1-abc");

    let off = base("rid-off").without_request_id().build().await.unwrap();
    let resp = off
        .router()
        .oneshot(
            HttpRequest::builder()
                .uri("/ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.headers().get("x-request-id").is_none());
}

#[tokio::test]
async fn body_size_limit_returns_413() {
    let server = base("limit")
        .with_body_size_limit(8)
        .post_tier(
            "/echo",
            post(|body: String| async move { body }),
            Tier::Public,
        )
        .build()
        .await
        .unwrap();
    let send = |len: usize| {
        server.router().oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/echo")
                .header("content-length", len.to_string())
                .body(Body::from("x".repeat(len)))
                .unwrap(),
        )
    };
    assert_eq!(send(8).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        send(9).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

// ---- plugins ----------------------------------------------------------------------

#[derive(Default)]
struct Seen {
    at_build: Option<RouteTable>,
    had_gate: bool,
    started: Option<StartedInfo>,
}

struct StubPlugin(Arc<Mutex<Seen>>);

impl ServerPlugin for StubPlugin {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn on_build(&mut self, cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        let mut seen = self.0.lock().unwrap();
        seen.at_build = Some(cx.route_table().clone());
        seen.had_gate = cx.has_gate();
        cx.route(
            RouteEntry::new(HttpMethod::Get, "/plugin", Tier::Public).with_label("added by plugin"),
            get(|| async { "from plugin" }),
        );
        Ok(())
    }

    fn on_started(&mut self, info: &StartedInfo) {
        self.0.lock().unwrap().started = Some(info.clone());
    }
}

struct FailingPlugin;

impl ServerPlugin for FailingPlugin {
    fn name(&self) -> &'static str {
        "failing"
    }

    fn on_build(&mut self, _cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        Err(BuildError::Plugin {
            plugin: "failing",
            message: "no".into(),
        })
    }
}

#[tokio::test]
async fn plugin_sees_route_table_in_on_build_and_bound_addr_on_start() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let server = base("plugins")
        .post_tier("/jobs", post(|| async { "" }), Tier::Authenticated)
        .with_plugin(StubPlugin(Arc::clone(&seen)))
        .build()
        .await
        .unwrap();

    {
        let s = seen.lock().unwrap();
        let table = s.at_build.as_ref().expect("on_build ran");
        assert_eq!(
            table.lookup(HttpMethod::Get, "/ping").map(|r| r.tier),
            Some(Tier::Public)
        );
        assert_eq!(
            table.lookup(HttpMethod::Post, "/jobs").map(|r| r.tier),
            Some(Tier::Authenticated)
        );
        let drain = table
            .lookup(HttpMethod::Post, "/admin/drain")
            .expect("built-ins visible");
        assert!(drain.builtin);
        assert_eq!(drain.tier, Tier::Admin);
        assert!(!s.had_gate);
    }
    assert!(
        server
            .route_table()
            .lookup(HttpMethod::Get, "/plugin")
            .is_some()
    );
    assert_eq!(
        call(&server.router(), "GET", "/plugin").await.1,
        Value::String("from plugin".into())
    );

    let running = server.start().await.unwrap();
    {
        let s = seen.lock().unwrap();
        let info = s.started.as_ref().expect("on_started ran");
        assert_eq!(info.local_addr, running.local_addr());
        assert_ne!(info.local_addr.port(), 0);
        assert_eq!(info.route_table.len(), 7);
    }
    running.shutdown();
    running.wait().await.unwrap();

    let err = base("fail")
        .with_plugin(FailingPlugin)
        .build()
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        BuildError::Plugin {
            plugin: "failing",
            ..
        }
    ));
}

// ---- live listeners (ports of the ConnectInfo regression tests) --------------

async fn whoami(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
    addr.to_string()
}

#[tokio::test]
async fn public_listener_reports_real_connect_info() {
    let running = base("ci-public")
        .get_tier("/whoami", get(whoami), Tier::Public)
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let (status, body) = http(running.local_addr(), "GET", "/whoami").await;
    assert_eq!(status, 200);
    let seen: SocketAddr = body.parse().unwrap();
    assert_eq!(seen.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(seen.port(), 0);
    running.shutdown();
    running.wait().await.unwrap();
}

#[tokio::test]
async fn admin_listener_reports_real_connect_info() {
    let running = ServerBuilder::new("ci-admin")
        .transport(Transport::Dual {
            public_addr: "127.0.0.1:0".parse().unwrap(),
            admin_port: 0,
        })
        .get_tier("/whoami", get(whoami), Tier::Public)
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let admin = running.admin_addr().expect("dual has an admin listener");
    assert_ne!(admin, running.local_addr());
    let (status, body) = http(admin, "GET", "/whoami").await;
    assert_eq!(status, 200);
    let seen: SocketAddr = body.parse().unwrap();
    assert_eq!(seen.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(seen.port(), 0);
    running.shutdown();
    running.wait().await.unwrap();
}

#[tokio::test]
async fn live_drain_flow_and_lifecycle_hooks() {
    let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let ticks = Arc::new(AtomicUsize::new(0));
    let (e1, e2, t) = (Arc::clone(&events), Arc::clone(&events), Arc::clone(&ticks));
    let running = base("live")
        .on_start(hook(move |_| {
            let e = Arc::clone(&e1);
            async move {
                e.lock().unwrap().push("start");
                Ok(())
            }
        }))
        .on_stop(hook(move |_| {
            let e = Arc::clone(&e2);
            async move {
                e.lock().unwrap().push("stop");
                Ok(())
            }
        }))
        .with_background_task("tick", Duration::from_millis(10), move || {
            let t = Arc::clone(&t);
            async move {
                t.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let addr = running.local_addr();
    assert_eq!(http(addr, "GET", "/readyz").await.0, 200);
    assert_eq!(
        http(addr, "POST", "/admin/drain").await,
        (200, r#"{"draining":true,"ok":true}"#.to_owned())
    );
    assert_eq!(http(addr, "GET", "/readyz").await.0, 503);
    assert_eq!(http(addr, "GET", "/livez").await.0, 200);
    assert!(running.drain_state().is_draining());

    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(ticks.load(Ordering::SeqCst) >= 1);
    assert_eq!(running.background_status().len(), 1);
    running.shutdown();
    running.wait().await.unwrap();
    assert_eq!(*events.lock().unwrap(), ["start", "stop"]);
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "listener closed"
    );
}

#[tokio::test]
async fn failing_on_start_aborts_start() {
    let server = base("bad-start")
        .on_start(hook(|_| async { Err("nope".into()) }))
        .build()
        .await
        .unwrap();
    let err = server.start().await.unwrap_err();
    assert!(err.to_string().contains("on_start"));
}

// ---- listener driver hook ------------------------------------------------------------------------

/// Stand-in for a transport crate: serves over loopback TCP but reports a
/// path, like an owner-only socket driver would.
struct FakeDriver {
    kind: &'static str,
    fail: bool,
    bound: Arc<Mutex<Option<SocketAddr>>>,
    ended: Arc<AtomicUsize>,
}

impl tesserax::ListenerDriver for FakeDriver {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn start(
        &self,
        transport: &Transport,
        router: Router,
        shutdown: tesserax::ShutdownSignal,
    ) -> tesserax::lifecycle::BoxFuture<'static, std::io::Result<tesserax::DriverListener>> {
        let Transport::Ipc { socket_path } = transport.clone() else {
            panic!("driver called for a foreign transport");
        };
        let fail = self.fail;
        let bound = Arc::clone(&self.bound);
        let ended = Arc::clone(&self.ended);
        Box::pin(async move {
            if fail {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "fake bind failure",
                ));
            }
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            *bound.lock().unwrap() = Some(l.local_addr()?);
            Ok(tesserax::DriverListener::new(
                tesserax::ListenerAddr::Path(socket_path),
                async move {
                    let _ = axum::serve(l, router)
                        .with_graceful_shutdown(shutdown)
                        .await;
                    ended.fetch_add(1, Ordering::SeqCst);
                },
            ))
        })
    }
}

fn fake(
    kind: &'static str,
    fail: bool,
) -> (FakeDriver, Arc<Mutex<Option<SocketAddr>>>, Arc<AtomicUsize>) {
    let bound = Arc::new(Mutex::new(None));
    let ended = Arc::new(AtomicUsize::new(0));
    (
        FakeDriver {
            kind,
            fail,
            bound: Arc::clone(&bound),
            ended: Arc::clone(&ended),
        },
        bound,
        ended,
    )
}

#[tokio::test]
async fn listener_driver_serves_its_transport_and_drains_on_shutdown() {
    struct SeesPath(Arc<Mutex<Option<std::path::PathBuf>>>);
    impl ServerPlugin for SeesPath {
        fn name(&self) -> &'static str {
            "sees-path"
        }
        fn on_build(&mut self, _cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
            Ok(())
        }
        fn on_started(&mut self, info: &StartedInfo) {
            *self.0.lock().unwrap() = info.local_path.clone();
        }
    }
    let (driver, bound, ended) = fake("ipc", false);
    let seen = Arc::new(Mutex::new(None));
    let running = ServerBuilder::new("driven")
        .transport(Transport::Ipc {
            socket_path: "/run/example/app.sock".into(),
        })
        .get_tier("/ping", get(|| async { "pong" }), Tier::Public)
        .listener_driver(driver)
        .with_plugin(SeesPath(Arc::clone(&seen)))
        .build()
        .await
        .expect("an ipc driver wires the transport")
        .start()
        .await
        .expect("start");
    let path = std::path::PathBuf::from("/run/example/app.sock");
    assert_eq!(running.local_path(), Some(path.as_path()));
    assert_eq!(seen.lock().unwrap().as_deref(), Some(path.as_path()));
    assert!(running.local_addr().ip().is_unspecified());

    let addr = bound.lock().unwrap().expect("driver bound");
    assert_eq!(http(addr, "GET", "/ping").await, (200, "pong".into()));
    // The whole router is served, built-ins included; Ipc is local-only so
    // the ungated admin route is allowed.
    assert_eq!(http(addr, "GET", "/readyz").await.0, 200);

    running.shutdown();
    running.wait().await.expect("wait");
    assert_eq!(
        ended.load(Ordering::SeqCst),
        1,
        "serve future ran to its end"
    );
}

#[tokio::test]
async fn listener_driver_of_another_kind_leaves_the_transport_unwired() {
    let (driver, _, _) = fake("tls", false);
    let err = ServerBuilder::new("x")
        .transport(Transport::Ipc {
            socket_path: "x.sock".into(),
        })
        .listener_driver(driver)
        .build()
        .await
        .unwrap_err();
    assert!(
        matches!(err, BuildError::TransportNotWired { kind: "ipc" }),
        "{err}"
    );
}

#[tokio::test]
async fn listener_driver_bind_failure_fails_start() {
    let (driver, _, _) = fake("ipc", true);
    let err = ServerBuilder::new("x")
        .transport(Transport::Ipc {
            socket_path: "x.sock".into(),
        })
        .listener_driver(driver)
        .build()
        .await
        .expect("build")
        .start()
        .await
        .unwrap_err();
    assert!(
        matches!(err, tesserax::RunError::Io(ref e) if e.kind() == std::io::ErrorKind::AddrInUse),
        "{err}"
    );
}
