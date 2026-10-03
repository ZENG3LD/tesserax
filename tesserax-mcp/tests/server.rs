//! The MCP server on a real `ServerBuilder` behind the `tesserax-auth`
//! gate: tools see the admitted Principal, unadmitted calls are refused by
//! the gate before any tool runs, the routes are described and tiered in
//! the route table, and the wire bytes stay as frozen.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tesserax::{DoorName, HttpMethod, KeyId, ServerBuilder, Tier, Transport};
use tesserax_auth::{AuthExt, AuthGate, Door, Grant, KeyHash, KeyRecord, KeyRing, Policy};
use tesserax_mcp::{CallContext, McpExt, McpServer, Tool, ToolOutcome};
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

/// Counts tool runs, so a refusal can be shown to come from the gate.
type Runs = Arc<AtomicUsize>;

fn mcp() -> McpServer<Runs> {
    McpServer::<Runs>::new("tesserax-mcp-test", "0.0.0").tool(
        Tool::new(
            "whoami",
            "Names the caller.",
            json!({ "type": "object", "properties": {} }),
        ),
        |runs: Runs, ctx: CallContext, _args: Value| async move {
            runs.fetch_add(1, Ordering::SeqCst);
            ToolOutcome::ok(match ctx.principal {
                Some(p) => json!({
                    "key_id": p.key_id.to_string(),
                    "door": p.door.to_string(),
                    "admin": p.satisfies(Tier::Admin),
                }),
                None => json!({ "key_id": null }),
            })
        },
    )
}

async fn router(server: McpServer<Runs>, runs: &Runs) -> Router {
    ServerBuilder::new("svc")
        .transport(Transport::public(0))
        .with_mcp(server, Arc::clone(runs))
        .with_auth(gate())
        .build()
        .await
        .unwrap()
        .router()
}

async fn post(router: &Router, key: Option<&str>, body: &Value) -> (StatusCode, Vec<u8>) {
    let mut b = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if let Some(k) = key {
        b = b.header("authorization", format!("Bearer {k}"));
    }
    let mut req = b
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "192.0.2.10:5000".parse::<SocketAddr>().unwrap(),
    ));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, bytes.to_vec())
}

fn whoami(id: u64) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": "whoami", "arguments": {} } })
}

fn tool_text(resp: &Value) -> Value {
    serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn a_gated_tool_sees_the_admitted_principal() {
    let runs = Runs::default();
    let r = router(mcp(), &runs).await;
    let (status, body) = post(&r, Some(USER_KEY), &whoami(1)).await;
    assert_eq!(status, StatusCode::OK);
    let resp: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    assert_eq!(
        tool_text(&resp),
        json!({ "key_id": "user", "door": "api", "admin": false })
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unauthenticated_call_is_refused_by_the_gate_not_the_tool() {
    let runs = Runs::default();
    let r = router(mcp(), &runs).await;

    let (status, body) = post(&r, None, &whoami(1)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The gate's own refusal body, not a JSON-RPC envelope.
    let resp: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp, json!({ "ok": false, "error": "missing_credential" }));

    let (status, body) = post(&r, Some("wrong-key-0123456789"), &whoami(1)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let resp: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp, json!({ "ok": false, "error": "unauthorized" }));

    assert_eq!(runs.load(Ordering::SeqCst), 0, "no tool may run");
}

#[tokio::test]
async fn the_route_tier_gates_every_tool_of_the_server() {
    let runs = Runs::default();
    let r = router(mcp().tier(Tier::Admin), &runs).await;
    assert_eq!(
        post(&r, Some(USER_KEY), &whoami(1)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    let (status, body) = post(&r, Some(ADMIN_KEY), &whoami(1)).await;
    assert_eq!(status, StatusCode::OK);
    let resp: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(tool_text(&resp)["admin"], true);
}

#[tokio::test]
async fn a_public_server_hands_tools_no_principal() {
    let runs = Runs::default();
    let r = router(mcp().tier(Tier::Public), &runs).await;
    for key in [None, Some(USER_KEY)] {
        let (status, body) = post(&r, key, &whoami(1)).await;
        assert_eq!(status, StatusCode::OK);
        let resp: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(tool_text(&resp), json!({ "key_id": null }));
    }
}

#[tokio::test]
async fn every_call_of_a_batch_runs_as_the_same_principal() {
    let runs = Runs::default();
    let r = router(mcp(), &runs).await;
    let (status, body) = post(&r, Some(USER_KEY), &json!([whoami(1), whoami(2)])).await;
    assert_eq!(status, StatusCode::OK);
    let resp: Value = serde_json::from_slice(&body).unwrap();
    let items = resp.as_array().unwrap();
    assert_eq!(items.len(), 2);
    for item in items {
        assert_eq!(tool_text(item)["key_id"], "user");
    }
    assert_eq!(runs.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_routes_are_described_and_tiered_in_the_table() {
    let server = mcp().tier(Tier::Admin);
    let docs = server.route_docs();
    let built = ServerBuilder::new("svc")
        .transport(Transport::public(0))
        .with_mcp(server, Runs::default())
        .with_auth(gate())
        .build()
        .await
        .unwrap();
    let table = built.route_table();
    let post = table.lookup(HttpMethod::Post, "/mcp").unwrap();
    assert_eq!(post.tier, Tier::Admin);
    assert_eq!(
        post.label.as_deref(),
        Some("MCP JSON-RPC 2.0 endpoint (1 tools). Single request or batch.")
    );
    let delete = table.lookup(HttpMethod::Delete, "/mcp").unwrap();
    assert_eq!(delete.tier, Tier::Admin);
    assert_eq!(
        delete.label.as_deref(),
        Some("MCP session end. Stateless server: always 204.")
    );

    assert_eq!(docs.len(), 2);
    assert_eq!(
        (docs[0].method.as_str(), docs[0].path.as_str()),
        ("POST", "/mcp")
    );
    assert_eq!(
        (docs[1].method.as_str(), docs[1].path.as_str()),
        ("DELETE", "/mcp")
    );
    for d in &docs {
        assert_eq!(d.auth, "bearer");
        assert_eq!(d.tier, Tier::Admin);
        assert!(!d.public);
    }
    let public = mcp().tier(Tier::Public).route_docs();
    assert!(
        public
            .iter()
            .all(|d| d.auth == "none" && d.tier == Tier::Public)
    );
}

/// Frozen wire bytes (deployed clients parse these): compact result, no
/// `structuredContent`, notification → 204 with an empty body. Object keys
/// inside `result` come out in `serde_json`'s default (sorted) map order,
/// as they did in the source crate.
#[tokio::test]
async fn wire_bytes_are_frozen() {
    let runs = Runs::default();
    let server = McpServer::<Runs>::new("tesserax-mcp-test", "0.0.0").tool(
        Tool::new("echo", "Echoes.", json!({ "type": "object" })),
        |_: Runs, _: CallContext, args: Value| async move { ToolOutcome::ok(args) },
    );
    let r = router(server, &runs).await;

    let call = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                       "params": { "name": "echo", "arguments": { "a": [1, 2] } } });
    let (status, body) = post(&r, Some(USER_KEY), &call).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"text":"{\"a\":[1,2]}","type":"text"}],"isError":false}}"#
    );

    let unknown = json!({ "jsonrpc": "2.0", "id": 8, "method": "nope" });
    let (_, body) = post(&r, Some(USER_KEY), &unknown).await;
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"jsonrpc":"2.0","id":8,"error":{"code":-32601,"message":"unknown method \"nope\""}}"#
    );

    let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let (status, body) = post(&r, Some(USER_KEY), &note).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
}
