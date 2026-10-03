//! The agent surface (feature `agent`): one [`Verb`] — one function —
//! answers over two doors, REST and MCP, and every mutating call is
//! audited inside the shared dispatch, not by per-request middleware.
//!
//! ```text
//!   REST  POST /v1/verbs/{name} ──┐
//!                                 ├── dispatch ── scope check ── run ── audit (if MUTATING)
//!   MCP   tools/call "name" ──────┘
//! ```
//!
//! Auditing inside dispatch is the point: a JSON-RPC batch carries many
//! calls in ONE HTTP request, so a middleware that audits per request
//! sees only the batch. Dispatch sees every call, so a batch of two
//! mutating verbs records two [`AuditEvent`]s.
//!
//! # Wire contract
//!
//! Success is byte-identical on both doors: the compact JSON of
//! `Verb::Out` (REST: the `200` body; MCP: `content[0].text` with
//! `isError: false`). Errors carry the same [`VerbCode`] and message on
//! both doors but in each door's own envelope — REST answers the error's
//! HTTP status with `{"error":{"code","message"}}`, MCP answers a normal
//! JSON-RPC result with `isError: true` and `"<code>: <message>"` as its
//! text (a refusal is never a JSON-RPC error, see `tesserax-mcp`).
//!
//! # Auth
//!
//! [`AgentSurface::auth`] installs an [`AuthGate`] on every REST route
//! (per-verb: the route admits only principals at the surface tier that
//! carry the verb's [`Verb::SCOPE`]) and marks the MCP server with that
//! tier for the route table. The verb scope is ALWAYS re-checked inside
//! dispatch — that is the only check a batched MCP call cannot bypass.
//! With auth configured, a call without an admitted principal is refused
//! (`denied`), so the MCP routes must be served behind the same gate.

use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tesserax::audit::{AuditEvent, AuditSink};
use tesserax::{DoorName, Principal, Scope, Tier};
use tesserax_auth::AuthGate;

mod mcp;
mod rest;

pub use rest::VERBS_PATH_PREFIX;

pub use axum::http::HeaderMap;

/// One operation an agent (or a human with a key) may call.
///
/// Implementors write the function once; [`AgentSurface`] gives it the
/// two doors. `NAME` is the route tail and the MCP tool name, `DOC` the
/// text shown to the calling agent.
///
/// `SCOPE` is the capability tag a principal must carry when the surface
/// has auth configured. It is a `&'static str` (validated once at
/// registration) rather than the design's `const SCOPE: Scope`: `Scope`
/// is `Arc`-backed and validated, so it cannot be built in a const
/// context (recorded deviation).
pub trait Verb: Send + Sync + 'static {
    /// Route tail / tool name; unique within one surface.
    const NAME: &'static str;
    /// What the verb does; becomes the route doc and the tool description.
    const DOC: &'static str;
    /// Capability tag required of the caller, e.g. `"fleet.read"`.
    const SCOPE: &'static str;
    /// True when the verb changes state; mutating calls are audited.
    const MUTATING: bool;
    /// The argument object, deserialised from the call's JSON.
    type Args: DeserializeOwned;
    /// The result, serialised compactly onto both wires.
    type Out: Serialize;

    /// Runs the verb.
    fn run(
        &self,
        cx: &VerbCx,
        args: Self::Args,
    ) -> impl Future<Output = Result<Self::Out, VerbError>> + Send;

    /// JSON Schema of [`Verb::Args`] for `tools/list`. The default is a
    /// bare object schema; verbs that want a validating schema override
    /// this (no `schemars` dependency in the framework).
    fn schema(&self) -> Value {
        json!({ "type": "object" })
    }
}

/// What a verb is handed alongside its arguments: who is calling and
/// through which door. Carries only what the request actually provided;
/// the framework invents no session state.
#[derive(Clone, Debug)]
pub struct VerbCx {
    /// The caller the auth gate admitted, if any.
    pub principal: Option<Principal>,
    /// The door the call came through.
    pub door: AgentDoor,
    /// The request's own headers (correlation ids and the like).
    pub headers: HeaderMap,
}

/// The door a call came through.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AgentDoor {
    /// `POST /v1/verbs/{name}`.
    Rest,
    /// `tools/call` on the MCP server.
    Mcp,
}

impl AgentDoor {
    /// The audit / log tag.
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentDoor::Rest => "rest",
            AgentDoor::Mcp => "mcp",
        }
    }
}

/// Why a verb call failed; maps to one HTTP status and one wire code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum VerbCode {
    /// The argument object was missing, the wrong shape, or refused by a
    /// rule the schema cannot express (HTTP 400).
    InvalidArgs,
    /// The caller is unknown or lacks the verb's scope (HTTP 403).
    Denied,
    /// The verb named no registered verb (HTTP 404).
    NotFound,
    /// The verb itself failed (HTTP 500).
    Internal,
}

impl VerbCode {
    /// The HTTP status of the REST envelope, also recorded as the audit
    /// event's outcome code on both doors.
    pub fn status(self) -> u16 {
        match self {
            VerbCode::InvalidArgs => 400,
            VerbCode::Denied => 403,
            VerbCode::NotFound => 404,
            VerbCode::Internal => 500,
        }
    }

    /// The stable wire tag (`"invalid_args"` and so on).
    pub fn wire(self) -> &'static str {
        match self {
            VerbCode::InvalidArgs => "invalid_args",
            VerbCode::Denied => "denied",
            VerbCode::NotFound => "not_found",
            VerbCode::Internal => "internal",
        }
    }
}

/// A failed verb call. The same `code` + `message` cross both doors; the
/// envelopes differ (module doc, "Wire contract").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerbError {
    code: VerbCode,
    message: String,
}

impl VerbError {
    /// One error of `code` with a caller-readable message.
    pub fn new(code: VerbCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// `invalid_args`: the argument object was refused.
    pub fn invalid_args(message: impl Into<String>) -> Self {
        Self::new(VerbCode::InvalidArgs, message)
    }

    /// `denied`: the caller is unknown or lacks the scope.
    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(VerbCode::Denied, message)
    }

    /// `internal`: the verb itself failed.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(VerbCode::Internal, message)
    }

    /// The code.
    pub fn code(&self) -> VerbCode {
        self.code
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for VerbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.wire(), self.message)
    }
}

impl std::error::Error for VerbError {}

/// The type-erased call of one verb: JSON in, JSON (or [`VerbError`]) out.
type ErasedRun = Arc<
    dyn Fn(VerbCx, Value) -> futures_util::future::BoxFuture<'static, Result<Value, VerbError>>
        + Send
        + Sync,
>;

/// A verb, type-erased for the surface's verb table.
struct RegisteredVerb {
    name: &'static str,
    doc: &'static str,
    scope: Scope,
    mutating: bool,
    schema: Value,
    run: ErasedRun,
}

/// The auth configuration of one surface.
#[derive(Clone)]
struct SurfaceAuth {
    gate: AuthGate,
    door: DoorName,
    tier: Tier,
}

/// The audit hook: sink plus the caller's clock (the framework's
/// `AuditEvent` takes its timestamp from the caller, never from a clock
/// this crate reads).
#[derive(Clone)]
struct AuditHook {
    sink: Arc<dyn AuditSink>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// The shared state both doors close over.
struct AgentShared {
    verbs: Vec<RegisteredVerb>,
    auth: Option<SurfaceAuth>,
    audit: Option<AuditHook>,
}

impl AgentShared {
    /// The one path every call takes, on both doors: find the verb,
    /// re-check the scope (the check a JSON-RPC batch cannot bypass),
    /// run, audit when mutating — outcome included.
    async fn dispatch(&self, name: &str, cx: VerbCx, args: Value) -> Result<Value, VerbError> {
        let Some(verb) = self.verbs.iter().find(|v| v.name == name) else {
            return Err(VerbError::new(
                VerbCode::NotFound,
                format!("no verb named {name}"),
            ));
        };
        if self.auth.is_some() {
            let admitted = cx
                .principal
                .as_ref()
                .is_some_and(|p| p.has_scope(&verb.scope));
            if !admitted {
                let err = VerbError::denied(format!(
                    "verb {name} requires scope {}",
                    verb.scope.as_str()
                ));
                self.record(verb, &cx, err.code().status());
                return Err(err);
            }
        }
        let result = (verb.run)(cx.clone(), args).await;
        let status = match &result {
            Ok(_) => 200,
            Err(e) => e.code().status(),
        };
        self.record(verb, &cx, status);
        result
    }

    /// Records one audit event for a mutating verb; read-only verbs are
    /// never audited. Infallible by the `AuditSink` contract.
    fn record(&self, verb: &RegisteredVerb, cx: &VerbCx, status: u16) {
        if !verb.mutating {
            return;
        }
        let Some(hook) = &self.audit else { return };
        hook.sink.record(AuditEvent {
            ts_ms: (hook.clock)(),
            door: cx.door.as_str().to_string(),
            principal: cx.principal.as_ref().map(|p| p.key_id.to_string()),
            client: None,
            verb: verb.name.to_string(),
            target: verb.name.to_string(),
            status,
        });
    }
}

/// A set of [`Verb`]s served over REST and MCP from one registration.
///
/// ```ignore
/// let surface = AgentSurface::new()
///     .auth(gate, DoorName::new("agent")?, Tier::Authenticated)
///     .audit(sink, || now_ms())
///     .verb(FleetList)
///     .verb(FleetRestart);
/// let rest: DocRouter = surface.into_rest();          // or into_mcp(..) for the tool server
/// ```
#[derive(Default)]
pub struct AgentSurface {
    verbs: Vec<RegisteredVerb>,
    auth: Option<SurfaceAuth>,
    audit: Option<AuditHook>,
}

impl AgentSurface {
    /// An empty surface with no auth (every door public) and no audit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits calls only through `door` at `tier`, with the verb's scope
    /// checked per call. On REST this installs the gate on every route;
    /// on MCP it marks the server's tier and arms the in-dispatch scope
    /// check (the MCP routes must still be served behind the same gate).
    pub fn auth(mut self, gate: AuthGate, door: DoorName, tier: Tier) -> Self {
        self.auth = Some(SurfaceAuth { gate, door, tier });
        self
    }

    /// Records one [`AuditEvent`] per mutating call (outcome included).
    /// `clock` supplies the event's `ts_ms`; this crate never reads a
    /// clock itself.
    pub fn audit(
        mut self,
        sink: Arc<dyn AuditSink>,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        self.audit = Some(AuditHook {
            sink,
            clock: Arc::new(clock),
        });
        self
    }

    /// Registers one verb. Panics on a duplicate `NAME` or an invalid
    /// `SCOPE` tag — both are programmer errors, caught at build time.
    pub fn verb<V: Verb>(mut self, v: V) -> Self {
        assert!(
            !self.verbs.iter().any(|r| r.name == V::NAME),
            "duplicate verb name {}",
            V::NAME
        );
        let scope = Scope::new(V::SCOPE)
            .unwrap_or_else(|e| panic!("verb {} has an invalid SCOPE: {e}", V::NAME));
        let verb = Arc::new(v);
        let schema = verb.schema();
        let run: ErasedRun = Arc::new(move |cx: VerbCx, args: Value| {
            let verb = Arc::clone(&verb);
            Box::pin(async move {
                let args: V::Args = serde_json::from_value(args)
                    .map_err(|e| VerbError::invalid_args(format!("verb {}: {e}", V::NAME)))?;
                let out = verb.run(&cx, args).await?;
                serde_json::to_value(out).map_err(|e| {
                    VerbError::internal(format!("verb {} result does not serialise: {e}", V::NAME))
                })
            }) as futures_util::future::BoxFuture<'static, Result<Value, VerbError>>
        });
        self.verbs.push(RegisteredVerb {
            name: V::NAME,
            doc: V::DOC,
            scope,
            mutating: V::MUTATING,
            schema,
            run,
        });
        self
    }

    /// Number of registered verbs.
    pub fn len(&self) -> usize {
        self.verbs.len()
    }

    /// True when no verb is registered.
    pub fn is_empty(&self) -> bool {
        self.verbs.is_empty()
    }

    /// The registered verb names, in registration order.
    pub fn verb_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.verbs.iter().map(|v| v.name)
    }

    /// Splits the surface into the shared state both doors close over.
    fn into_shared(self) -> Arc<AgentShared> {
        Arc::new(AgentShared {
            verbs: self.verbs,
            auth: self.auth,
            audit: self.audit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tesserax::Tier;

    #[derive(Deserialize)]
    struct Add {
        a: i64,
        b: i64,
    }

    struct Sum;

    impl Verb for Sum {
        const NAME: &'static str = "sum";
        const DOC: &'static str = "Adds two integers.";
        const SCOPE: &'static str = "math.read";
        const MUTATING: bool = false;
        type Args = Add;
        type Out = serde_json::Value;

        async fn run(&self, _cx: &VerbCx, a: Add) -> Result<Value, VerbError> {
            Ok(json!({ "sum": a.a + a.b }))
        }
    }

    struct Bump {
        counter: Arc<AtomicU64>,
    }

    impl Verb for Bump {
        const NAME: &'static str = "bump";
        const DOC: &'static str = "Increments the counter.";
        const SCOPE: &'static str = "math.write";
        const MUTATING: bool = true;
        type Args = Add;
        type Out = serde_json::Value;

        async fn run(&self, _cx: &VerbCx, a: Add) -> Result<Value, VerbError> {
            if a.a < 0 {
                return Err(VerbError::invalid_args("a must be >= 0"));
            }
            let n = self.counter.fetch_add(a.a as u64, Ordering::SeqCst) + a.a as u64;
            Ok(json!({ "counter": n }))
        }
    }

    #[derive(Default)]
    struct MemSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl AuditSink for MemSink {
        fn record(&self, event: AuditEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn cx(principal: Option<Principal>) -> VerbCx {
        VerbCx {
            principal,
            door: AgentDoor::Rest,
            headers: HeaderMap::new(),
        }
    }

    fn scoped_principal(scopes: &[&str]) -> Principal {
        Principal {
            key_id: tesserax::KeyId::new("tester").unwrap(),
            door: DoorName::new("agent").unwrap(),
            tier: Tier::Authenticated,
            scopes: scopes.iter().map(|s| Scope::new(s).unwrap()).collect(),
        }
    }

    #[test]
    fn duplicate_verb_names_panic() {
        let panic = std::panic::catch_unwind(|| AgentSurface::new().verb(Sum).verb(Sum));
        assert!(panic.is_err());
    }

    #[test]
    fn invalid_scope_tag_panics() {
        struct Bad;
        impl Verb for Bad {
            const NAME: &'static str = "bad";
            const DOC: &'static str = "Bad scope.";
            const SCOPE: &'static str = "not a scope!";
            const MUTATING: bool = false;
            type Args = Value;
            type Out = Value;
            async fn run(&self, _cx: &VerbCx, a: Value) -> Result<Value, VerbError> {
                Ok(a)
            }
        }
        let panic = std::panic::catch_unwind(|| AgentSurface::new().verb(Bad));
        assert!(panic.is_err());
    }

    #[tokio::test]
    async fn dispatch_deserialises_runs_and_serialises() {
        let shared = AgentSurface::new().verb(Sum).into_shared();
        let out = shared
            .dispatch("sum", cx(None), json!({ "a": 2, "b": 40 }))
            .await
            .unwrap();
        assert_eq!(out, json!({ "sum": 42 }));
    }

    #[tokio::test]
    async fn dispatch_maps_bad_args_to_invalid_args() {
        let shared = AgentSurface::new().verb(Sum).into_shared();
        let err = shared
            .dispatch("sum", cx(None), json!({ "a": "x" }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), VerbCode::InvalidArgs);
        assert_eq!(err.code().status(), 400);
    }

    #[tokio::test]
    async fn unknown_verb_is_not_found() {
        let shared = AgentSurface::new().verb(Sum).into_shared();
        let err = shared
            .dispatch("nope", cx(None), json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), VerbCode::NotFound);
        assert_eq!(err.code().status(), 404);
    }

    #[tokio::test]
    async fn a_surface_without_auth_never_checks_scopes() {
        let shared = AgentSurface::new().verb(Sum).into_shared();
        let out = shared.dispatch("sum", cx(None), json!({"a":1,"b":1})).await;
        assert!(out.is_ok());
    }

    #[tokio::test]
    async fn a_verb_error_surfaces_its_own_code() {
        let counter = Arc::new(AtomicU64::new(0));
        let shared = AgentSurface::new()
            .verb(Bump {
                counter: Arc::clone(&counter),
            })
            .into_shared();
        let err = shared
            .dispatch("bump", cx(None), json!({ "a": -1, "b": 0 }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), VerbCode::InvalidArgs);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "refused work must not run"
        );
    }

    #[tokio::test]
    async fn scope_is_enforced_inside_dispatch_when_auth_is_configured() {
        use tesserax_auth::{Door, Grant, KeyHash, KeyRecord, KeyRing, Policy};
        let door = DoorName::new("agent").unwrap();
        let ring = KeyRing::from_records(vec![KeyRecord::new(
            tesserax::KeyId::new("tester").unwrap(),
            KeyHash::of_raw("tester-key-0123456789"),
            vec![Grant::new(door.clone(), Tier::Authenticated)],
        )])
        .unwrap();
        let gate = AuthGate::new(ring).door(Door::new(door.clone(), Policy::Any));
        let shared = AgentSurface::new()
            .auth(gate, door, Tier::Authenticated)
            .verb(Sum)
            .into_shared();

        // No principal: refused even though the verb ran fine without auth.
        let err = shared
            .dispatch("sum", cx(None), json!({"a":1,"b":1}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), VerbCode::Denied);
        // Principal without the verb's scope: refused.
        let err = shared
            .dispatch(
                "sum",
                cx(Some(scoped_principal(&["math.write"]))),
                json!({"a":1,"b":1}),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), VerbCode::Denied);
        // Principal with the scope: runs.
        let out = shared
            .dispatch(
                "sum",
                cx(Some(scoped_principal(&["math.read"]))),
                json!({"a":1,"b":1}),
            )
            .await
            .unwrap();
        assert_eq!(out, json!({ "sum": 2 }));
    }

    #[tokio::test]
    async fn only_mutating_verbs_are_audited_outcome_included() {
        let sink = Arc::new(MemSink::default());
        let counter = Arc::new(AtomicU64::new(0));
        let shared = AgentSurface::new()
            .audit(Arc::clone(&sink) as Arc<dyn AuditSink>, || 7)
            .verb(Sum)
            .verb(Bump {
                counter: Arc::clone(&counter),
            })
            .into_shared();
        let principal = scoped_principal(&["math.write"]);
        // Read-only verb: no event.
        shared
            .dispatch("sum", cx(Some(principal.clone())), json!({"a":1,"b":1}))
            .await
            .unwrap();
        assert!(sink.events.lock().unwrap().is_empty());
        // Mutating verb, success: 200.
        shared
            .dispatch("bump", cx(Some(principal.clone())), json!({"a":3,"b":0}))
            .await
            .unwrap();
        // Mutating verb, refused by the verb itself: 400.
        shared
            .dispatch("bump", cx(Some(principal)), json!({"a":-1,"b":0}))
            .await
            .unwrap_err();
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].verb, "bump");
        assert_eq!(events[0].status, 200);
        assert_eq!(events[0].ts_ms, 7);
        assert_eq!(events[0].principal.as_deref(), Some("tester"));
        assert_eq!(events[1].status, 400);
    }
}
