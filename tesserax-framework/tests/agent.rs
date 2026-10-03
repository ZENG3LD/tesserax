//! The B8e done-tests over the wire: one verb answers identically over
//! REST and MCP, and a JSON-RPC batch of two mutating verbs records two
//! audit events (the gap per-request middleware cannot close, because it
//! sees only the one batched request).

#![cfg(feature = "agent")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};
use tesserax::audit::{AuditEvent, AuditSink};
use tesserax::{DoorName, HttpMethod, KeyId, RouteEntry, Scope, Tier};
use tesserax_auth::{AuthGate, Denial, Door, Grant, KeyHash, KeyRecord, KeyRing, Policy};
use tesserax_framework::agent::{AgentDoor, AgentSurface, Verb, VerbCx, VerbError};

const READ_KEY: &str = "reader-key-0123456789";
const WRITE_KEY: &str = "writer-key-0123456789";
const FIXED_NOW_MS: u64 = 1_700_000_000_000;

// -- verbs -------------------------------------------------------------------

#[derive(Deserialize)]
struct Pair {
    a: i64,
    b: i64,
}

/// Read-only: needs `math.read`.
struct Sum;

impl Verb for Sum {
    const NAME: &'static str = "sum";
    const DOC: &'static str = "Adds two integers.";
    const SCOPE: &'static str = "math.read";
    const MUTATING: bool = false;
    type Args = Pair;
    type Out = Value;

    async fn run(&self, _cx: &VerbCx, p: Pair) -> Result<Value, VerbError> {
        Ok(json!({ "sum": p.a + p.b }))
    }
}

/// Mutating: needs `math.write`, refuses a negative increment.
struct Bump {
    counter: Arc<AtomicU64>,
}

impl Verb for Bump {
    const NAME: &'static str = "bump";
    const DOC: &'static str = "Adds `a` to the counter.";
    const SCOPE: &'static str = "math.write";
    const MUTATING: bool = true;
    type Args = Pair;
    type Out = Value;

    async fn run(&self, _cx: &VerbCx, p: Pair) -> Result<Value, VerbError> {
        if p.a < 0 {
            return Err(VerbError::invalid_args("a must be >= 0"));
        }
        let n = self.counter.fetch_add(p.a as u64, Ordering::SeqCst) + p.a as u64;
        Ok(json!({ "counter": n }))
    }
}

// -- fixtures ------------------------------------------------------------------

#[derive(Default)]
struct MemSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl AuditSink for MemSink {
    fn record(&self, event: AuditEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn door() -> DoorName {
    DoorName::new("agent").unwrap()
}

fn gate() -> AuthGate {
    let scopes = |tags: &[&str]| tags.iter().map(|t| Scope::new(t).unwrap()).collect();
    let ring = KeyRing::from_records(vec![
        KeyRecord::new(
            KeyId::new("reader").unwrap(),
            KeyHash::of_raw(READ_KEY),
            vec![Grant::new(door(), Tier::Authenticated).with_scopes(scopes(&["math.read"]))],
        ),
        KeyRecord::new(
            KeyId::new("writer").unwrap(),
            KeyHash::of_raw(WRITE_KEY),
            vec![
                Grant::new(door(), Tier::Authenticated)
                    .with_scopes(scopes(&["math.read", "math.write"])),
            ],
        ),
    ])
    .unwrap();
    AuthGate::new(ring).door(Door::new(door(), Policy::Any))
}

fn surface(sink: &Arc<MemSink>, counter: &Arc<AtomicU64>) -> AgentSurface {
    AgentSurface::new()
        .auth(gate(), door(), Tier::Authenticated)
        .audit(Arc::clone(sink) as Arc<dyn AuditSink>, || FIXED_NOW_MS)
        .verb(Sum)
        .verb(Bump {
            counter: Arc::clone(counter),
        })
}

/// The gate for the MCP route: admits the request, hands the principal to
/// the tools through the request extensions (the pattern the route layer
/// of the REST door uses; a production server gets the same from
/// `AuthExt`).
struct McpDoor {
    gate: AuthGate,
}

async fn mcp_gate_mw(State(check): State<Arc<McpDoor>>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    let Some(path) = parts
        .extensions
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
    else {
        return Denial::Misconfigured.into_response();
    };
    let method = match HttpMethod::parse(parts.method.as_str()) {
        Some(m) => m,
        None => return Denial::Unauthorized.into_response(),
    };
    let entry = RouteEntry::new(method, path, Tier::Authenticated);
    match check.gate.check(&parts, &entry, Some(&door())).await {
        Err(denial) => denial.into_response(),
        Ok(principal) => {
            if let Some(p) = principal {
                parts.extensions.insert(p);
            }
            next.run(Request::from_parts(parts, body)).await
        }
    }
}

fn rest_router(sink: &Arc<MemSink>, counter: &Arc<AtomicU64>) -> Router {
    surface(sink, counter).into_rest().into_parts().0
}

fn mcp_router(sink: &Arc<MemSink>, counter: &Arc<AtomicU64>) -> Router {
    surface(sink, counter)
        .into_mcp("agent-surface-test", "0.0.0")
        .into_doc_router()
        .into_parts()
        .0
        .layer(from_fn_with_state(
            Arc::new(McpDoor { gate: gate() }),
            mcp_gate_mw,
        ))
}

async fn post(router: &Router, path: &str, key: Option<&str>, body: &Value) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(key) = key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    let req = builder.body(Body::from(body.to_string())).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn call(id: u64, verb: &str, args: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": verb, "arguments": args },
    })
}

/// The payload of a successful MCP tool result, parsed back to JSON.
fn tool_payload(resp: &Value) -> Value {
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool result has no text payload: {resp}"));
    assert_eq!(resp["result"]["isError"], false, "call refused: {text}");
    serde_json::from_str(text).expect("payload is JSON")
}

// -- the done-tests ------------------------------------------------------------

#[tokio::test]
async fn the_same_verb_answers_identically_over_rest_and_mcp() {
    let sink = Arc::new(MemSink::default());
    let counter = Arc::new(AtomicU64::new(0));
    let rest = rest_router(&sink, &counter);
    let mcp = mcp_router(&sink, &counter);

    let args = json!({ "a": 2, "b": 40 });
    let (status, rest_body) = post(&rest, "/v1/verbs/sum", Some(READ_KEY), &args).await;
    assert_eq!(status, StatusCode::OK);
    let (status, mcp_body) = post(&mcp, "/mcp", Some(READ_KEY), &call(1, "sum", args)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        rest_body,
        tool_payload(&mcp_body),
        "one verb, one answer on both doors"
    );

    // A refusal also carries the same code and message on both doors.
    let bad = json!({ "a": -1, "b": 0 });
    let (status, rest_err) = post(&rest, "/v1/verbs/bump", Some(WRITE_KEY), &bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(rest_err["error"]["code"], "invalid_args");
    let (status, mcp_err) = post(&mcp, "/mcp", Some(WRITE_KEY), &call(1, "bump", bad)).await;
    assert_eq!(status, StatusCode::OK, "a refusal is a JSON-RPC result");
    assert_eq!(mcp_err["result"]["isError"], true);
    let text = mcp_err["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.starts_with("invalid_args: a must be >= 0"),
        "same code and message as REST: {text}"
    );
    assert_eq!(rest_err["error"]["message"], "a must be >= 0");
}

#[tokio::test]
async fn a_batched_mcp_call_with_two_mutating_verbs_records_two_audit_events() {
    let sink = Arc::new(MemSink::default());
    let counter = Arc::new(AtomicU64::new(0));
    let mcp = mcp_router(&sink, &counter);

    let batch = json!([
        call(1, "bump", json!({ "a": 1, "b": 0 })),
        call(2, "bump", json!({ "a": 2, "b": 0 })),
    ]);
    let (status, body) = post(&mcp, "/mcp", Some(WRITE_KEY), &batch).await;
    assert_eq!(status, StatusCode::OK);
    let items = body.as_array().expect("a batch answers with an array");
    assert_eq!(items.len(), 2);
    for item in items {
        assert_eq!(item["result"]["isError"], false, "call refused: {item}");
    }
    assert_eq!(counter.load(Ordering::SeqCst), 3, "both verbs ran");

    // One HTTP request, two calls: per-request middleware would have seen
    // the request once. Dispatch audited every call.
    let events = sink.events.lock().unwrap();
    assert_eq!(events.len(), 2, "every mutating call of the batch audited");
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.verb, "bump");
        assert_eq!(event.door, AgentDoor::Mcp.as_str());
        assert_eq!(event.status, 200);
        assert_eq!(event.ts_ms, FIXED_NOW_MS);
        assert_eq!(event.principal.as_deref(), Some("writer"), "event {i}");
    }
}

// -- the enforcement that makes the done-tests meaningful ----------------------

#[tokio::test]
async fn the_verb_scope_is_enforced_on_both_doors() {
    let sink = Arc::new(MemSink::default());
    let counter = Arc::new(AtomicU64::new(0));
    let rest = rest_router(&sink, &counter);
    let mcp = mcp_router(&sink, &counter);
    let args = json!({ "a": 1, "b": 0 });

    // REST: the reader lacks math.write — the route's own gate check
    // refuses before the handler (a credential that does not admit the
    // route is a 401 on the HTTP door, see `Denial`).
    let (status, _) = post(&rest, "/v1/verbs/bump", Some(READ_KEY), &args).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // REST: no key at all is refused the same way.
    let (status, _) = post(&rest, "/v1/verbs/bump", None, &args).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // MCP: one route hosts every verb, so the route check cannot know the
    // verb's scope — the in-dispatch check is what refuses the reader,
    // and the refusal is a JSON-RPC result, not an HTTP error.
    let (status, body) = post(&mcp, "/mcp", Some(READ_KEY), &call(1, "bump", args)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["isError"], true);
    let text = body["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("denied:"), "scope refusal: {text}");

    assert_eq!(counter.load(Ordering::SeqCst), 0, "refused work never ran");
    // Only the call that reached dispatch is audited: the REST refusals
    // happened at the route gate (which has its own ban/audit channel),
    // the MCP refusal happened inside dispatch.
    let events = sink.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].status, 403);
    assert_eq!(events[0].door, AgentDoor::Mcp.as_str());
}

#[tokio::test]
async fn tools_list_names_every_verb_with_its_doc_and_schema() {
    let server = AgentSurface::new()
        .verb(Sum)
        .into_mcp("agent-surface-test", "0.0.0");
    let list = server.tools_list_json();
    let tools = list["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "sum");
    assert_eq!(tools[0]["description"], "Adds two integers.");
    assert_eq!(tools[0]["inputSchema"]["type"], "object");
}

#[tokio::test]
async fn headers_reach_the_verb_through_the_context_on_both_doors() {
    struct Echo;
    impl Verb for Echo {
        const NAME: &'static str = "echo";
        const DOC: &'static str = "Echoes a correlation header.";
        const SCOPE: &'static str = "math.read";
        const MUTATING: bool = false;
        type Args = Value;
        type Out = Value;
        async fn run(&self, cx: &VerbCx, _args: Value) -> Result<Value, VerbError> {
            let corr = cx
                .headers
                .get("x-correlation")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            Ok(json!({ "door": cx.door.as_str(), "correlation": corr }))
        }
    }

    let sink = Arc::new(MemSink::default());
    let rest = AgentSurface::new()
        .auth(gate(), door(), Tier::Authenticated)
        .audit(sink as Arc<dyn AuditSink>, || FIXED_NOW_MS)
        .verb(Echo)
        .into_rest()
        .into_parts()
        .0;

    use tower::ServiceExt;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/verbs/echo")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {READ_KEY}"))
        .header("x-correlation", "abc-123")
        .body(Body::from("{}"))
        .unwrap();
    let resp = rest.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body, json!({ "door": "rest", "correlation": "abc-123" }));
}
