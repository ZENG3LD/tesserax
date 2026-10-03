//! The HTTP surface on a real `ServerBuilder`: self-described routes land in
//! the table and are enforced by the auth gate, OpenAPI reflects the final
//! table (including routes added by later plugins), guards sit at their
//! stages (the tier rate limit sees the admitted principal), and the
//! WebSocket hub delivers by topic.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Query, WebSocketUpgrade};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use futures_util::StreamExt;
use tesserax::{
    BuildCx, BuildError, DoorName, HttpMethod, KeyId, RouteEntry, ServerBuilder, ServerPlugin,
    Tier, Transport,
};
use tesserax_auth::{AuthExt, AuthGate, Door, Grant, KeyHash, KeyRecord, KeyRing, Policy};
use tesserax_http::guard::{
    CsrfState, IDEMPOTENCY_KEY, IDEMPOTENT_REPLAYED, IdempotencyConfig, IdempotencyStore, IpAcl,
    RateLimitState, SecurityHeaders, TierRateLimit, TierRateLimitPolicy,
};
use tesserax_http::push::WsHub;
use tesserax_http::{DocRouter, HttpExt, RouteDoc};
use tower::ServiceExt;

const ADMIN_KEY: &str = "admin-key-0123456789";
const USER_KEY: &str = "user-key-0123456789";

fn gate() -> AuthGate {
    let door = DoorName::new("api").unwrap();
    let ring = KeyRing::from_records(vec![
        KeyRecord::new(
            KeyId::new("admin").unwrap(),
            KeyHash::of_raw(ADMIN_KEY),
            vec![Grant::new(door.clone(), Tier::Admin)],
        ),
        KeyRecord::new(
            KeyId::new("user").unwrap(),
            KeyHash::of_raw(USER_KEY),
            vec![Grant::new(door.clone(), Tier::Authenticated)],
        ),
    ])
    .unwrap();
    AuthGate::new(ring).door(Door::new(door, Policy::Any))
}

async fn ok() -> &'static str {
    "ok"
}

fn routes() -> DocRouter {
    let admin = DocRouter::new().post(
        "/purge",
        ok,
        RouteDoc::bearer("Purge caches.").tier(Tier::Admin),
    );
    DocRouter::new()
        .get("/ping", ok, "Liveness. No auth.")
        .get("/items/{id}", ok, RouteDoc::bearer("One item."))
        .nest("/admin", admin)
}

/// Adds a route after the OpenAPI plugin ran: it must still be listed.
struct LatePlugin;

impl ServerPlugin for LatePlugin {
    fn name(&self) -> &'static str {
        "late"
    }

    fn on_build(&mut self, cx: &mut BuildCx<'_>) -> Result<(), BuildError> {
        cx.route(
            RouteEntry::new(HttpMethod::Get, "/late", Tier::Authenticated)
                .with_label("Added by a later plugin."),
            get(ok),
        );
        Ok(())
    }
}

async fn send(router: &Router, method: &str, uri: &str, key: Option<&str>) -> (StatusCode, String) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(k) = key {
        b = b.header("authorization", format!("Bearer {k}"));
    }
    let mut req = b.body(Body::empty()).unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "192.0.2.10:5000".parse::<SocketAddr>().unwrap(),
    ));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn described_routes_are_in_the_table_and_gated() {
    let server = ServerBuilder::new("svc")
        .transport(Transport::public(0))
        .with_routes(routes())
        .with_openapi("/openapi.json")
        .with_plugin(LatePlugin)
        .with_auth(gate())
        .build()
        .await
        .unwrap();
    let table = server.route_table().clone();
    let purge = table.lookup(HttpMethod::Post, "/admin/purge").unwrap();
    assert_eq!(purge.tier, Tier::Admin);
    assert_eq!(purge.label.as_deref(), Some("Purge caches."));
    assert_eq!(
        table.lookup(HttpMethod::Get, "/ping").unwrap().tier,
        Tier::Public
    );

    let r = server.router();
    assert_eq!(send(&r, "GET", "/ping", None).await.0, StatusCode::OK);
    assert_eq!(
        send(&r, "GET", "/items/7", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&r, "GET", "/items/7", Some(USER_KEY)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&r, "POST", "/admin/purge", Some(USER_KEY)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&r, "POST", "/admin/purge", Some(ADMIN_KEY)).await.0,
        StatusCode::OK
    );

    let (status, body) = send(&r, "GET", "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["info"]["title"], "svc");
    assert_eq!(
        doc["paths"]["/admin/purge"]["post"]["summary"],
        "Purge caches."
    );
    assert_eq!(doc["paths"]["/admin/purge"]["post"]["x-tier"], "admin");
    assert_eq!(
        doc["paths"]["/items/{id}"]["get"]["parameters"][0]["name"],
        "id"
    );
    assert_eq!(
        doc["paths"]["/late"]["get"]["summary"],
        "Added by a later plugin."
    );
    assert_eq!(doc["paths"]["/health"]["get"]["x-builtin"], true);
    assert_eq!(doc["paths"]["/openapi.json"]["get"]["x-tier"], "public");
}

#[tokio::test]
async fn blank_description_fails_the_build() {
    let err = ServerBuilder::new("svc")
        .transport(Transport::local(0))
        .with_routes(DocRouter::new().get("/x", ok, "  "))
        .build()
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            BuildError::Plugin {
                plugin: "doc-router",
                ..
            }
        ),
        "{err}"
    );
}

#[tokio::test]
async fn admin_route_without_gate_still_refused_by_root() {
    let err = ServerBuilder::new("svc")
        .transport(Transport::public(0))
        .with_routes(routes())
        .build()
        .await
        .unwrap_err();
    assert!(
        matches!(err, BuildError::UnauthenticatedAdminRoute { .. }),
        "{err}"
    );
}

#[tokio::test]
async fn tier_rate_limit_sees_the_admitted_principal() {
    let policy = TierRateLimitPolicy {
        anonymous: (0.0, 1.0),
        authenticated: (0.0, 2.0),
        admin: (0.0, 5.0),
    };
    let server = ServerBuilder::new("svc")
        .transport(Transport::public(0))
        .with_routes(routes())
        .with_auth(gate())
        .with_tier_rate_limit(TierRateLimit::new(Arc::new(RateLimitState::new()), policy))
        .build()
        .await
        .unwrap();
    let r = server.router();
    // Anonymous on the public route: burst 1.
    assert_eq!(send(&r, "GET", "/ping", None).await.0, StatusCode::OK);
    assert_eq!(
        send(&r, "GET", "/ping", None).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Same address, authenticated principal: its own bucket of 2.
    assert_eq!(
        send(&r, "GET", "/items/1", Some(USER_KEY)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&r, "GET", "/items/1", Some(USER_KEY)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&r, "GET", "/items/1", Some(USER_KEY)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Admin: bucket of 5, untouched by the others.
    for _ in 0..5 {
        assert_eq!(
            send(&r, "GET", "/items/1", Some(ADMIN_KEY)).await.0,
            StatusCode::OK
        );
    }
    // A refused credential never reaches the limiter (the gate answers).
    assert_eq!(
        send(&r, "GET", "/items/1", Some("wrong")).await.0,
        StatusCode::UNAUTHORIZED
    );
}

/// One idempotent POST: `(status, body, replayed)`.
async fn idem_post(
    router: &Router,
    uri: &str,
    key: Option<&str>,
    idem: &str,
    peer: &str,
) -> (StatusCode, String, bool) {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(IDEMPOTENCY_KEY, idem);
    if let Some(k) = key {
        b = b.header("authorization", format!("Bearer {k}"));
    }
    let mut req = b.body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let replayed = resp.headers().contains_key(IDEMPOTENT_REPLAYED);
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap(), replayed)
}

#[tokio::test]
async fn idempotency_is_keyed_by_the_admitted_principal() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let (h1, h2) = (Arc::clone(&hits), Arc::clone(&hits));
    let routes = DocRouter::new()
        .post(
            "/charge",
            move || {
                let n = h1.fetch_add(1, Ordering::SeqCst) + 1;
                async move { format!("charge {n}") }
            },
            RouteDoc::bearer("Charge (idempotent)."),
        )
        .post(
            "/tip",
            move || {
                let n = h2.fetch_add(1, Ordering::SeqCst) + 1;
                async move { format!("tip {n}") }
            },
            "Anonymous tip (idempotent).",
        );
    let store = Arc::new(IdempotencyStore::new(IdempotencyConfig::default()));
    let server = ServerBuilder::new("svc")
        .transport(Transport::public(0))
        .with_routes(routes)
        .with_auth(gate())
        .with_idempotency(Arc::clone(&store))
        .build()
        .await
        .unwrap();
    let r = server.router();
    let peer = "192.0.2.10:5000";

    // Same key replays.
    let first = idem_post(&r, "/charge", Some(USER_KEY), "k1", peer).await;
    assert_eq!(first, (StatusCode::OK, "charge 1".into(), false));
    let again = idem_post(&r, "/charge", Some(USER_KEY), "k1", peer).await;
    assert_eq!(again, (StatusCode::OK, "charge 1".into(), true));

    // A different key, same address, same Idempotency-Key: its own entry.
    let other = idem_post(&r, "/charge", Some(ADMIN_KEY), "k1", peer).await;
    assert_eq!(other, (StatusCode::OK, "charge 2".into(), false));
    let other_again = idem_post(&r, "/charge", Some(ADMIN_KEY), "k1", peer).await;
    assert_eq!(other_again, (StatusCode::OK, "charge 2".into(), true));

    // A refused credential is answered by the gate: no slot, no replay.
    let refused = idem_post(&r, "/charge", Some("wrong"), "k1", peer).await;
    assert_eq!(refused.0, StatusCode::UNAUTHORIZED);
    assert!(!refused.2);

    // Anonymous routes key by the honest client address.
    let tip = idem_post(&r, "/tip", None, "k1", peer).await;
    assert_eq!(tip, (StatusCode::OK, "tip 3".into(), false));
    let tip_again = idem_post(&r, "/tip", None, "k1", peer).await;
    assert_eq!(tip_again, (StatusCode::OK, "tip 3".into(), true));
    let tip_elsewhere = idem_post(&r, "/tip", None, "k1", "198.51.100.7:1").await;
    assert_eq!(tip_elsewhere, (StatusCode::OK, "tip 4".into(), false));

    assert_eq!(hits.load(Ordering::SeqCst), 4);
    assert_eq!(store.len(), 4);
}

#[tokio::test]
async fn guards_on_the_builder() {
    let server = ServerBuilder::new("svc")
        .transport(Transport::local(0))
        .with_routes(
            DocRouter::new()
                .get("/ping", ok, "Ping.")
                .post("/form", ok, "Submit."),
        )
        .with_security_headers(SecurityHeaders::default().without_hsts())
        .with_csrf(CsrfState::new(b"csrf-secret-0123456789".to_vec()).unwrap())
        .with_ip_acl(IpAcl::deny_only(
            tesserax::CidrList::parse("198.51.100.0/24").unwrap(),
        ))
        .with_compression()
        .with_etag(Default::default())
        .with_traceparent()
        .with_server_timing()
        .with_access_log()
        .with_swagger_ui("/docs", "/openapi.json")
        .build()
        .await
        .unwrap();
    let r = server.router();
    let resp = r
        .clone()
        .oneshot(Request::get("/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let h = resp.headers();
    assert_eq!(h["x-frame-options"], "DENY");
    assert!(!h.contains_key("strict-transport-security"));
    assert!(h.contains_key("etag"));
    assert!(h.contains_key("traceparent"));
    assert!(h.contains_key("server-timing"));
    assert!(h["set-cookie"].to_str().unwrap().starts_with("csrf_token="));
    // CSRF refuses a POST without the header.
    assert_eq!(
        send(&r, "POST", "/form", None).await.0,
        StatusCode::FORBIDDEN
    );
    // Denied range.
    let mut req = Request::get("/ping").body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("198.51.100.9:1".parse::<SocketAddr>().unwrap()));
    assert_eq!(
        r.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let (status, page) = send(&r, "GET", "/docs", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("SwaggerUIBundle"));
}

#[derive(serde::Deserialize)]
struct TopicQuery {
    topic: Option<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_hub_delivers_by_topic() {
    let hub = WsHub::new(16);
    let h = hub.clone();
    let server = ServerBuilder::new("ws")
        .transport(Transport::local(0))
        .with_routes(DocRouter::new().get(
            "/ws",
            move |ws: WebSocketUpgrade, Query(q): Query<TopicQuery>| {
                let h = h.clone();
                async move { h.handle_upgrade(ws, q.topic) }
            },
            "WebSocket; ?topic= filters.",
        ))
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let url = format!("ws://{}/ws?topic=a", server.local_addr());
    let (mut sock, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    for _ in 0..500 {
        if hub.receiver_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    hub.publish("b", serde_json::json!({"n": 0}));
    hub.publish("a", serde_json::json!({"n": 1}));
    let msg = tokio::time::timeout(Duration::from_secs(5), sock.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = msg.into_text().unwrap();
    assert_eq!(text.as_str(), r#"{"topic":"a","payload":{"n":1}}"#);
    server.shutdown();
    server.wait().await.unwrap();
}
