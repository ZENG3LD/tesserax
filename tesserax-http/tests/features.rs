//! Feature-gated parts on a real builder: response signing, the CORS
//! proxy against a loopback upstream, Prometheus metrics.

#![allow(unused_imports)]

use std::net::SocketAddr;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use tesserax::{ServerBuilder, Tier, Transport};
use tesserax_http::{DocRouter, HttpExt};
use tower::ServiceExt;

#[cfg(any(feature = "signing", feature = "metrics"))]
async fn ok() -> &'static str {
    "ok"
}

#[cfg(feature = "signing")]
#[tokio::test]
async fn signing_on_the_builder_covers_admin_paths() {
    use std::sync::Arc;
    use tesserax_secrets::DaemonIdentity;
    use tesserax_secrets::signing::{ResponseSigningState, SignedResponseConfig, verify_response};

    let id = DaemonIdentity::generate().unwrap();
    let state = Arc::new(ResponseSigningState::new(
        id.clone(),
        SignedResponseConfig::default(),
    ));
    let server = ServerBuilder::new("sig")
        .transport(Transport::local(0))
        .with_routes(
            DocRouter::new()
                .get(
                    "/admin/state",
                    || async { r#"{"state":"ok"}"# },
                    "Signed state.",
                )
                .get("/ping", ok, "Ping."),
        )
        .with_compression()
        .with_response_signing(state)
        .build()
        .await
        .unwrap();
    let r = server.router();
    let resp = r
        .clone()
        .oneshot(Request::get("/admin/state").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let sig = resp.headers()["x-tesserax-sig"]
        .to_str()
        .unwrap()
        .to_owned();
    let t: u64 = resp.headers()["x-tesserax-sig-time"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    assert!(verify_response(
        id.verifying_key(),
        t,
        200,
        "/admin/state",
        &body,
        &sig
    ));
    let resp = r
        .oneshot(Request::get("/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(resp.headers().get("x-tesserax-sig").is_none());
}

#[cfg(feature = "cors-proxy")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cors_proxy_forwards_to_an_allowed_upstream_and_never_follows_redirects() {
    use axum::response::Redirect;
    use axum::routing::{get, post};
    use tesserax_http::cors_proxy::CorsProxyConfig;

    let upstream = Router::new()
        .route(
            "/data",
            get(|| async { ([("content-type", "application/json")], r#"{"v":1}"#) }),
        )
        .route(
            "/echo",
            post(|body: String| async move { format!("got {body}") }),
        )
        .route(
            "/bounce",
            get(|| async { Redirect::temporary("http://198.51.100.1/internal") }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let server = ServerBuilder::new("proxy")
        .transport(Transport::local(0))
        .with_cors_proxy(
            CorsProxyConfig::new("/proxy", vec!["127.0.0.1".into()]).with_tier(Tier::Public),
        )
        .build()
        .await
        .unwrap();
    let table = server.route_table().clone();
    assert_eq!(table.iter().filter(|e| e.path == "/proxy").count(), 3);
    let r = server.router();
    let call = |method: &'static str, target: String, body: &'static str| {
        let r = r.clone();
        async move {
            let uri = format!(
                "/proxy?url={}",
                target.replace(':', "%3A").replace('/', "%2F")
            );
            let resp = r
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let acao = resp.headers().get("access-control-allow-origin").cloned();
            let ct = resp.headers().get("content-type").cloned();
            let body = to_bytes(resp.into_body(), 1024).await.unwrap();
            (status, acao, ct, String::from_utf8(body.to_vec()).unwrap())
        }
    };
    let (s, acao, ct, body) = call("GET", format!("http://{up}/data"), "").await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, r#"{"v":1}"#));
    assert_eq!(acao.unwrap(), "*");
    assert_eq!(ct.unwrap(), "application/json");
    let (s, _, _, body) = call("POST", format!("http://{up}/echo"), "hello").await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, "got hello"));
    // The redirect is handed back, not followed.
    let (s, _, _, _) = call("GET", format!("http://{up}/bounce"), "").await;
    assert_eq!(s, StatusCode::TEMPORARY_REDIRECT);
    let (s, _, _, _) = call("GET", "http://localhost/data".into(), "").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[cfg(feature = "cors-proxy")]
#[tokio::test]
async fn cors_proxy_routes_are_gated_by_default() {
    use tesserax_http::cors_proxy::CorsProxyConfig;
    let t = ServerBuilder::new("proxy")
        .transport(Transport::local(0))
        .with_cors_proxy(CorsProxyConfig::new(
            "/proxy",
            vec!["api.example.com".into()],
        ))
        .build()
        .await
        .unwrap()
        .route_table()
        .clone();
    let tiers: Vec<_> = t
        .iter()
        .filter(|e| e.path == "/proxy")
        .map(|e| (e.method, e.tier))
        .collect();
    use tesserax::HttpMethod;
    assert!(tiers.contains(&(HttpMethod::Get, Tier::Authenticated)));
    assert!(tiers.contains(&(HttpMethod::Post, Tier::Authenticated)));
    assert!(tiers.contains(&(HttpMethod::Options, Tier::Public)));
    // A bad forward header fails the build instead of a later panic.
    let err = ServerBuilder::new("proxy")
        .transport(Transport::local(0))
        .with_cors_proxy(
            CorsProxyConfig::new("/p", vec![]).with_forward_headers(vec!["bad header".into()]),
        )
        .build()
        .await
        .unwrap_err();
    assert!(err.to_string().contains("cors-proxy"), "{err}");
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn prometheus_scrape_route_counts_by_template() {
    use tesserax_http::metrics::PrometheusState;
    let (recorder, state) = PrometheusState::unattached();
    metrics::set_global_recorder(recorder).unwrap();
    let server = ServerBuilder::new("m")
        .transport(Transport::local(0))
        .with_routes(DocRouter::new().get("/items/{id}", ok, "One item."))
        .with_prometheus_state("/metrics", Tier::Public, state)
        .build()
        .await
        .unwrap();
    let r = server.router();
    for id in [1, 2, 3] {
        let resp = r
            .clone()
            .oneshot(
                Request::get(format!("/items/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = r
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let text =
        String::from_utf8(to_bytes(resp.into_body(), 1 << 16).await.unwrap().to_vec()).unwrap();
    assert!(
        text.contains(r#"http_requests_total{method="GET",path="/items/{id}",status="200"} 3"#),
        "{text}"
    );
    // A second global install is refused and fails the build.
    let err = ServerBuilder::new("m2")
        .transport(Transport::local(0))
        .with_prometheus_metrics("/metrics", Tier::Public)
        .build()
        .await
        .unwrap_err();
    assert!(err.to_string().contains("prometheus"), "{err}");
}

#[cfg(feature = "signing")]
#[tokio::test]
async fn identity_endpoint_is_admin_and_described() {
    use base64::Engine as _;
    use tesserax::{DoorName, HttpMethod, KeyId};
    use tesserax_auth::{AuthExt, AuthGate, Door, Grant, KeyHash, KeyRecord, KeyRing, Policy};
    use tesserax_secrets::DaemonIdentity;

    const ADMIN: &str = "admin-key-0123456789";
    let door = DoorName::new("api").unwrap();
    let ring = KeyRing::from_records(vec![KeyRecord::new(
        KeyId::new("admin").unwrap(),
        KeyHash::of_raw(ADMIN),
        vec![Grant::new(door.clone(), Tier::Admin)],
    )])
    .unwrap();
    let id = DaemonIdentity::generate().unwrap();
    let server = ServerBuilder::new("svc")
        .transport(Transport::public(0))
        .with_identity_endpoint(&id)
        .with_auth(AuthGate::new(ring).door(Door::new(door, Policy::Any)))
        .build()
        .await
        .unwrap();
    let entry = server
        .route_table()
        .lookup(HttpMethod::Get, tesserax_http::IDENTITY_PATH)
        .unwrap();
    assert_eq!(entry.tier, Tier::Admin);
    assert!(entry.label.as_deref().unwrap().contains("identity"));

    let r = server.router();
    let get = |key: Option<&'static str>| {
        let r = r.clone();
        async move {
            let mut b = Request::get("/admin/identity");
            if let Some(k) = key {
                b = b.header("authorization", format!("Bearer {k}"));
            }
            let mut req = b.body(Body::empty()).unwrap();
            req.extensions_mut().insert(axum::extract::ConnectInfo(
                "192.0.2.10:5000".parse::<SocketAddr>().unwrap(),
            ));
            let resp = r.oneshot(req).await.unwrap();
            let status = resp.status();
            (status, to_bytes(resp.into_body(), 4096).await.unwrap())
        }
    };
    assert_eq!(get(None).await.0, StatusCode::UNAUTHORIZED);
    let (status, body) = get(Some(ADMIN)).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["daemon"]["name"], "svc");
    assert_eq!(v["daemon"]["pubkey_fingerprint"], id.pubkey_fingerprint());
    let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(v["daemon"]["pubkey_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(pk, id.pubkey_bytes());
}
