//! The REST door of the agent surface: one route per verb, each behind
//! its own auth check (the verb's scope), answering the wire contract of
//! the module doc.

use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::{Value, json};
use tesserax::{DoorName, HttpMethod, Principal, RouteEntry, Scope, Tier};
use tesserax_auth::{AuthGate, Denial};
use tesserax_http::{DocRouter, RouteDoc};

use super::{AgentDoor, AgentShared, AgentSurface, VerbCx};

/// The route prefix every verb is served under: a verb `name` answers
/// `POST /v1/verbs/name`.
pub const VERBS_PATH_PREFIX: &str = "/v1/verbs";

impl AgentSurface {
    /// The REST door: `POST /v1/verbs/{name}` per verb, each route
    /// documented with the verb's `DOC` and scope. With
    /// [`AgentSurface::auth`](super::AgentSurface::auth) configured, every
    /// route runs the gate restricted to the surface door and the verb's
    /// scope before the handler — and dispatch re-checks the scope, so
    /// the check holds even where no middleware can reach (module doc).
    pub fn into_rest(self) -> DocRouter {
        let shared = self.into_shared();
        let mut router = DocRouter::new();
        for verb in &shared.verbs {
            let path = format!("{}/{}", VERBS_PATH_PREFIX, verb.name);
            let doc = RouteDoc::bearer(verb.doc)
                .label("verb", verb.name)
                .scope(verb.scope.clone());
            let doc = match &shared.auth {
                Some(auth) => doc.tier(auth.tier).label("door", auth.door.as_str()),
                None => doc,
            };
            // Each route is static (`/v1/verbs/sum`, no path parameter) so
            // it can carry its own auth layer; the verb name therefore
            // comes from the handler closure, not a `Path` extractor.
            let name = verb.name;
            let handler = axum::routing::post(
                move |State(shared): State<Arc<AgentShared>>,
                      principal: Option<Extension<Principal>>,
                      headers: HeaderMap,
                      Json(args): Json<Value>| {
                    answer(shared, name, principal, headers, args)
                },
            );
            let routes = DocRouter::new()
                .post(&path, handler, doc)
                .with_state(Arc::clone(&shared));
            let routes = match &shared.auth {
                Some(auth) => {
                    let check = Arc::new(VerbDoorCheck {
                        gate: auth.gate.clone(),
                        door: auth.door.clone(),
                        tier: auth.tier,
                        scope: verb.scope.clone(),
                    });
                    routes.route_layer(from_fn_with_state(check, verb_door_mw))
                }
                None => routes,
            };
            router = router.merge(routes);
        }
        router
    }
}

/// The gate decision for one verb's route (the http_shell door pattern:
/// the gate is checked against the matched-path template, never the raw
/// path).
struct VerbDoorCheck {
    gate: AuthGate,
    door: DoorName,
    tier: Tier,
    scope: Scope,
}

async fn verb_door_mw(
    State(check): State<Arc<VerbDoorCheck>>,
    req: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let Some(path) = parts
        .extensions
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
    else {
        return Denial::Misconfigured.into_response();
    };
    let method = match HttpMethod::parse(parts.method.as_str()) {
        Some(HttpMethod::Head) => HttpMethod::Get,
        Some(m) => m,
        None => return Denial::Unauthorized.into_response(),
    };
    let entry = RouteEntry::new(method, path, check.tier).with_scope(check.scope.clone());
    match check.gate.check(&parts, &entry, Some(&check.door)).await {
        Err(denial) => denial.into_response(),
        Ok(principal) => {
            if let Some(p) = principal {
                parts.extensions.insert(p);
            }
            next.run(Request::from_parts(parts, body)).await
        }
    }
}

/// One REST call through the shared dispatch, answered in the REST
/// envelope — bare `Out` JSON on success, `{"error":{"code","message"}}`
/// with the code's status on failure.
async fn answer(
    shared: Arc<AgentShared>,
    name: &'static str,
    principal: Option<Extension<Principal>>,
    headers: HeaderMap,
    args: Value,
) -> Response {
    let cx = VerbCx {
        principal: principal.map(|Extension(p)| p),
        door: AgentDoor::Rest,
        headers,
    };
    match shared.dispatch(name, cx, args).await {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(e) => (
            StatusCode::from_u16(e.code().status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(json!({
                "error": {
                    "code": e.code().wire(),
                    "message": e.message(),
                }
            })),
        )
            .into_response(),
    }
}
