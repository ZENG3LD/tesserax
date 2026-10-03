//! End-to-end decisions of the gate installed on a real `ServerBuilder`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Extension};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::{get, post};
use tower::ServiceExt;

use tesserax::audit::{AuditEvent, AuditSink};
use tesserax::{
    BuildCx, BuildError, DoorName, HttpMethod, KeyId, Principal, RouteEntry, Scope, ScopeSet,
    ServerBuilder, ServerPlugin, Tier, Transport,
};
use tesserax_auth::{
    AuthBan, AuthBanConfig, AuthChain, AuthExt, AuthGate, AuthLayer, AuthOutcome, BoxFuture, Door,
    Grant, KeyHash, KeyRecord, KeyRing, PathTemplate, Policy,
};

const OPS: &str = "ops-key-0123456789";
const VIEWER: &str = "viewer-key-0123456789";
const REPORTER: &str = "reporter-key-0123456789";
const EXPIRED: &str = "expired-key-0123456789";

fn door(name: &str) -> DoorName {
    DoorName::new(name).unwrap()
}

fn scope(name: &str) -> Scope {
    Scope::new(name).unwrap()
}

fn record(id: &str, raw: &str, grants: Vec<Grant>) -> KeyRecord {
    KeyRecord::new(KeyId::new(id).unwrap(), KeyHash::of_raw(raw), grants)
}

fn ring() -> KeyRing {
    KeyRing::from_records(vec![
        record("ops", OPS, vec![Grant::new(door("control"), Tier::Root)]),
        record(
            "viewer",
            VIEWER,
            vec![Grant::new(door("observe"), Tier::Authenticated)],
        ),
        record(
            "reporter",
            REPORTER,
            vec![
                Grant::new(door("control"), Tier::Authenticated)
                    .with_scopes([scope("reports.read")].into_iter().collect()),
            ],
        ),
        record(
            "old",
            EXPIRED,
            vec![Grant::new(door("control"), Tier::Root)],
        )
        .expires_at_ms(1_000),
    ])
    .unwrap()
}

fn t(s: &str) -> PathTemplate {
    PathTemplate::new(s).unwrap()
}

fn gate(ring: KeyRing) -> AuthGate {
    AuthGate::new(ring)
        .door(Door::new(door("control"), Policy::Any))
        .door(Door::new(
            door("observe"),
            Policy::Exact(vec![
                (HttpMethod::Get, t("/jobs")),
                (HttpMethod::Get, t("/jobs/{id}")),
            ]),
        ))
        .with_clock(|| 10_000)
}

async fn who(p: Option<Extension<Principal>>) -> String {
    p.map(|Extension(p)| format!("{}@{}:{}", p.key_id, p.door, p.tier))
        .unwrap_or_else(|| "anonymous".into())
}

fn builder() -> ServerBuilder {
    ServerBuilder::new("auth-test")
        .transport(Transport::public(0))
        .without_request_id()
        .get_tier("/open", get(who), Tier::Public)
        .get_tier("/jobs", get(who), Tier::Authenticated)
        .get_tier("/jobs/{id}", get(who), Tier::Authenticated)
        .post_tier("/jobs", post(who), Tier::Admin)
        .route_entry(
            RouteEntry::new(HttpMethod::Get, "/reports", Tier::Authenticated)
                .with_scope(scope("reports.read")),
            get(who),
        )
}

async fn app(gate: AuthGate) -> Router {
    builder()
        .with_auth(gate)
        .build()
        .await
        .expect("build")
        .router()
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn send(
    router: &Router,
    method: &str,
    uri: &str,
    key: Option<&str>,
    peer: &str,
    extra: &[(&str, &str)],
) -> Resp {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(k) = key {
        b = b.header("authorization", format!("Bearer {k}"));
    }
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let mut req = b.body(Body::empty()).unwrap();
    let addr: SocketAddr = peer.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body =
        String::from_utf8(to_bytes(resp.into_body(), 1 << 16).await.unwrap().to_vec()).unwrap();
    Resp {
        status,
        headers,
        body,
    }
}

const REMOTE: &str = "203.0.113.7:4000";

#[tokio::test]
async fn door_matrix() {
    let r = app(gate(ring())).await;

    // Operator key reaches every gated route, including the admin built-in.
    for (m, uri) in [("GET", "/jobs"), ("GET", "/jobs/7"), ("POST", "/jobs")] {
        let resp = send(&r, m, uri, Some(OPS), REMOTE, &[]).await;
        assert_eq!(resp.status, StatusCode::OK, "{m} {uri}");
        assert_eq!(resp.body, "ops@control:root");
    }
    assert_eq!(
        send(&r, "POST", "/admin/drain", Some(OPS), REMOTE, &[])
            .await
            .status,
        StatusCode::OK
    );

    // Scoped key reaches exactly its allow-list.
    assert_eq!(
        send(&r, "GET", "/jobs", Some(VIEWER), REMOTE, &[])
            .await
            .body,
        "viewer@observe:authenticated"
    );
    assert_eq!(
        send(&r, "GET", "/jobs/9", Some(VIEWER), REMOTE, &[])
            .await
            .status,
        StatusCode::OK
    );
    for (m, uri) in [
        ("POST", "/jobs"),
        ("GET", "/reports"),
        ("POST", "/admin/drain"),
    ] {
        assert_eq!(
            send(&r, m, uri, Some(VIEWER), REMOTE, &[]).await.status,
            StatusCode::UNAUTHORIZED,
            "{m} {uri}"
        );
    }

    // Scope is orthogonal to tier: Root without the scope is refused.
    assert_eq!(
        send(&r, "GET", "/reports", Some(REPORTER), REMOTE, &[])
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(&r, "GET", "/reports", Some(OPS), REMOTE, &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&r, "POST", "/jobs", Some(REPORTER), REMOTE, &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );

    // Public routes and probes need nothing; a bad key there is ignored.
    assert_eq!(
        send(&r, "GET", "/open", None, REMOTE, &[]).await.body,
        "anonymous"
    );
    assert_eq!(
        send(&r, "GET", "/open", Some("junk"), REMOTE, &[])
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(&r, "GET", "/health", None, REMOTE, &[]).await.status,
        StatusCode::OK
    );
    // HEAD follows the GET route's rule.
    assert_eq!(
        send(&r, "HEAD", "/jobs", Some(VIEWER), REMOTE, &[])
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn refusals_are_byte_identical_and_missing_differs() {
    let r = app(gate(ring())).await;
    let unknown = send(&r, "GET", "/jobs", Some("no-such-key"), REMOTE, &[]).await;
    let out_of_scope = send(&r, "POST", "/jobs", Some(VIEWER), REMOTE, &[]).await;
    let missing_scope = send(&r, "GET", "/reports", Some(OPS), REMOTE, &[]).await;
    let expired = send(&r, "GET", "/jobs", Some(EXPIRED), REMOTE, &[]).await;
    let other_scheme = send(
        &r,
        "GET",
        "/jobs",
        None,
        REMOTE,
        &[("authorization", "Basic dXNlcjpwdw==")],
    )
    .await;
    for other in [&out_of_scope, &missing_scope, &expired, &other_scheme] {
        assert_eq!(other.status, unknown.status);
        assert_eq!(other.headers, unknown.headers);
        assert_eq!(other.body, unknown.body);
    }
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.body, r#"{"ok":false,"error":"unauthorized"}"#);
    assert_eq!(unknown.headers.get("www-authenticate").unwrap(), "Bearer");

    let missing = send(&r, "GET", "/jobs", None, REMOTE, &[]).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.body, r#"{"ok":false,"error":"missing_credential"}"#);
    assert_ne!(missing.body, unknown.body);
}

#[tokio::test]
async fn empty_ring_refuses_everything() {
    let r = app(gate(KeyRing::new())).await;
    assert_eq!(
        send(&r, "GET", "/jobs", Some(OPS), REMOTE, &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&r, "POST", "/admin/drain", Some(OPS), REMOTE, &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&r, "GET", "/jobs", None, REMOTE, &[]).await.body,
        r#"{"ok":false,"error":"missing_credential"}"#
    );
    // A door with the default policy admits nothing either.
    let closed = AuthGate::new(ring()).door(Door::new(door("control"), Policy::default()));
    let r = app(closed).await;
    assert_eq!(
        send(&r, "GET", "/jobs", Some(OPS), REMOTE, &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn query_keys_only_where_a_door_allows_them() {
    let r = app(gate(ring())).await;
    let q = format!("/jobs?api_key={OPS}");
    assert_eq!(
        send(&r, "GET", &q, None, REMOTE, &[]).await.body,
        r#"{"ok":false,"error":"missing_credential"}"#
    );

    let allowing =
        AuthGate::new(ring()).door(Door::new(door("control"), Policy::Any).allow_query_key());
    let r = app(allowing).await;
    assert_eq!(
        send(&r, "GET", &q, None, REMOTE, &[]).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn bearer_scheme_is_strict_but_case_insensitive() {
    let r = app(gate(ring())).await;
    let lower = format!("bearer {OPS}");
    assert_eq!(
        send(
            &r,
            "GET",
            "/jobs",
            None,
            REMOTE,
            &[("authorization", &lower)]
        )
        .await
        .status,
        StatusCode::OK
    );
    let two_spaces = format!("Bearer  {OPS}");
    assert_eq!(
        send(
            &r,
            "GET",
            "/jobs",
            None,
            REMOTE,
            &[("authorization", &two_spaces)]
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn auth_ban_blocks_after_failures() {
    let ban = Arc::new(AuthBan::new(AuthBanConfig {
        max_failures: 3,
        ..AuthBanConfig::default()
    }));
    let g = gate(ring())
        .with_ban(Arc::clone(&ban))
        .trusted_proxies(tesserax::CidrList::parse("127.0.0.1").unwrap());
    let r = app(g).await;

    // Missing credentials do not count.
    for _ in 0..5 {
        send(&r, "GET", "/jobs", None, REMOTE, &[]).await;
    }
    assert!(!ban.is_banned("203.0.113.7".parse().unwrap()));

    for _ in 0..3 {
        assert_eq!(
            send(&r, "GET", "/jobs", Some("wrong"), REMOTE, &[])
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    let banned = send(&r, "GET", "/jobs", Some(OPS), REMOTE, &[]).await;
    assert_eq!(banned.status, StatusCode::FORBIDDEN);
    assert_eq!(banned.body, r#"{"ok":false,"error":"ip_banned"}"#);
    // Even the public probes are refused for a banned address (PeerGuard wraps everything).
    assert_eq!(
        send(&r, "GET", "/health", None, REMOTE, &[]).await.status,
        StatusCode::FORBIDDEN
    );
    // Another address is unaffected.
    assert_eq!(
        send(&r, "GET", "/jobs", Some(OPS), "203.0.113.8:1", &[])
            .await
            .status,
        StatusCode::OK
    );

    // Behind a trusted proxy the forwarded client is the one counted and banned.
    for _ in 0..3 {
        send(
            &r,
            "GET",
            "/jobs",
            Some("wrong"),
            "127.0.0.1:9",
            &[("x-forwarded-for", "198.51.100.4")],
        )
        .await;
    }
    assert!(ban.is_banned("198.51.100.4".parse().unwrap()));
    assert!(!ban.is_banned("127.0.0.1".parse().unwrap()));
    assert_eq!(
        send(
            &r,
            "GET",
            "/jobs",
            Some(OPS),
            "127.0.0.1:9",
            &[("x-forwarded-for", "198.51.100.5")]
        )
        .await
        .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn open_loopback_only_admits_plain_local_callers() {
    let g = AuthGate::new(KeyRing::new()).door(Door::open_loopback_only(door("local")));
    let r = app(g).await;
    let local = send(&r, "POST", "/jobs", None, "127.0.0.1:5000", &[]).await;
    assert_eq!(local.status, StatusCode::OK);
    assert_eq!(local.body, "loopback@local:admin");
    // Forwarded through a local proxy: not a plain local caller.
    let proxied = send(
        &r,
        "POST",
        "/jobs",
        None,
        "127.0.0.1:5000",
        &[("x-forwarded-for", "203.0.113.1")],
    )
    .await;
    assert_eq!(proxied.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        send(&r, "POST", "/jobs", None, REMOTE, &[]).await.status,
        StatusCode::UNAUTHORIZED
    );
    // Loopback grant is Admin, not Root.
    let root_route = ServerBuilder::new("x")
        .transport(Transport::local(0))
        .get_tier("/root", get(who), Tier::Root)
        .with_auth(AuthGate::new(KeyRing::new()).door(Door::open_loopback_only(door("local"))))
        .build()
        .await
        .unwrap()
        .router();
    assert_eq!(
        send(&root_route, "GET", "/root", None, "127.0.0.1:1", &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[derive(Default)]
struct Recorder(Mutex<Vec<AuditEvent>>);

impl AuditSink for Recorder {
    fn record(&self, e: AuditEvent) {
        self.0.lock().unwrap().push(e);
    }
}

#[tokio::test]
async fn admitted_mutations_are_audited_with_final_status() {
    let sink = Arc::new(Recorder::default());
    let r = app(gate(ring()).with_audit(Arc::clone(&sink) as Arc<dyn AuditSink>)).await;
    send(&r, "GET", "/jobs", Some(OPS), REMOTE, &[]).await;
    send(&r, "POST", "/jobs", Some(OPS), REMOTE, &[]).await;
    send(&r, "POST", "/jobs", Some(VIEWER), REMOTE, &[]).await;
    let events = sink.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1, "only the admitted mutating request");
    let e = &events[0];
    assert_eq!(
        (e.verb.as_str(), e.target.as_str(), e.status),
        ("POST", "/jobs", 200)
    );
    assert_eq!(
        (e.door.as_str(), e.principal.as_deref(), e.client.as_deref()),
        ("control", Some("ops"), Some("203.0.113.7"))
    );
    assert_eq!(e.ts_ms, 10_000);
}

/// A plugin registered *after* `with_auth` adds an Admin route; the gate
/// still enforces it because it reads the final table per request.
struct LateRoute;

impl ServerPlugin for LateRoute {
    fn name(&self) -> &'static str {
        "late-route"
    }

    fn on_build(&mut self, cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        cx.route(
            RouteEntry::new(HttpMethod::Post, "/late", Tier::Admin),
            post(who),
        );
        Ok(())
    }
}

#[tokio::test]
async fn gate_sees_routes_added_by_later_plugins() {
    let r = builder()
        .with_auth(gate(ring()))
        .with_plugin(LateRoute)
        .build()
        .await
        .unwrap()
        .router();
    assert_eq!(
        send(&r, "POST", "/late", None, REMOTE, &[]).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&r, "POST", "/late", Some(VIEWER), REMOTE, &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&r, "POST", "/late", Some(OPS), REMOTE, &[])
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn missing_route_table_fails_closed() {
    let r = builder()
        .without_auto_extensions()
        .with_auth(gate(ring()))
        .build()
        .await
        .unwrap()
        .router();
    let resp = send(&r, "GET", "/jobs", Some(OPS), REMOTE, &[]).await;
    assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(resp.body, r#"{"ok":false,"error":"gate_misconfigured"}"#);
}

#[tokio::test]
async fn with_auth_satisfies_the_admin_route_rule() {
    assert!(matches!(
        builder().build().await.unwrap_err(),
        BuildError::UnauthenticatedAdminRoute { .. }
    ));
    builder()
        .with_auth(gate(ring()))
        .build()
        .await
        .expect("gated public server builds");
}

#[tokio::test]
async fn rotating_the_ring_takes_effect_immediately() {
    let g = gate(ring());
    let handle = Arc::clone(g.key_ring());
    let r = app(g).await;
    assert_eq!(
        send(&r, "GET", "/jobs", Some(OPS), REMOTE, &[])
            .await
            .status,
        StatusCode::OK
    );
    handle.store(
        KeyRing::from_records(vec![record(
            "ops2",
            "new-ops-key",
            vec![Grant::new(door("control"), Tier::Root)],
        )])
        .unwrap(),
    );
    assert_eq!(
        send(&r, "GET", "/jobs", Some(OPS), REMOTE, &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&r, "GET", "/jobs", Some("new-ops-key"), REMOTE, &[])
            .await
            .status,
        StatusCode::OK
    );
}

struct HeaderUser;

impl AuthLayer for HeaderUser {
    fn name(&self) -> &str {
        "header-user"
    }

    fn resolve<'a>(&'a self, parts: &'a Parts) -> BoxFuture<'a, AuthOutcome> {
        Box::pin(async move {
            match parts
                .headers
                .get("x-test-user")
                .and_then(|v| v.to_str().ok())
            {
                Some("alice") => AuthOutcome::Grant {
                    key_id: KeyId::new("alice").unwrap(),
                    grants: vec![
                        Grant::new(door("observe"), Tier::Authenticated)
                            .with_scopes(ScopeSet::new()),
                    ],
                },
                Some("mallory") => AuthOutcome::Reject {
                    reason: "blocked user".into(),
                },
                _ => AuthOutcome::Abstain,
            }
        })
    }
}

#[tokio::test]
async fn chain_layers_identify_callers_without_keys() {
    let r = app(gate(ring()).chain(AuthChain::new().layer(HeaderUser))).await;
    let alice = send(
        &r,
        "GET",
        "/jobs",
        None,
        REMOTE,
        &[("x-test-user", "alice")],
    )
    .await;
    assert_eq!(alice.body, "alice@observe:authenticated");
    assert_eq!(
        send(
            &r,
            "POST",
            "/jobs",
            None,
            REMOTE,
            &[("x-test-user", "alice")]
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    let mallory = send(
        &r,
        "GET",
        "/jobs",
        None,
        REMOTE,
        &[("x-test-user", "mallory")],
    )
    .await;
    assert_eq!(mallory.body, r#"{"ok":false,"error":"unauthorized"}"#);
    // Keys still take precedence.
    assert_eq!(
        send(
            &r,
            "GET",
            "/jobs",
            Some(OPS),
            REMOTE,
            &[("x-test-user", "alice")]
        )
        .await
        .body,
        "ops@control:root"
    );
}
