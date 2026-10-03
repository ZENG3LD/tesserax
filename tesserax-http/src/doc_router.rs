//! [`DocRouter`]: a router whose every route carries a description.
//!
//! axum offers no way to list the routes of a built `Router`. `DocRouter`
//! records `(method, path, description, tier)` at the moment each route is
//! added, from the same call that mounts the handler, so the list can never
//! drift from what is served.
//!
//! The description is a required argument of every route-adding method
//! (`impl Into<RouteDoc>`, not `Option<RouteDoc>`): a route without one is a
//! compile error, not a manifest with a gap.
//!
//! ```
//! use tesserax_http::{DocRouter, RouteDoc};
//!
//! async fn health() -> &'static str { "ok" }
//! async fn status() -> &'static str { "{}" }
//!
//! let api: DocRouter = DocRouter::new()
//!     .get("/status", status, RouteDoc::bearer("Status snapshot."));
//! let docs = DocRouter::new()
//!     .get("/ping", health, "Liveness probe. No auth.")
//!     .nest("/api", api);
//! assert_eq!(docs.endpoints().len(), 2);
//! assert_eq!(docs.route_table().len(), 2);
//! ```
//!
//! Leaving the description out does not compile:
//!
//! ```compile_fail
//! use tesserax_http::DocRouter;
//! async fn h() -> &'static str { "ok" }
//! let _r: DocRouter = DocRouter::new().get("/x", h);
//! ```
//!
//! Nor does an optional one:
//!
//! ```compile_fail
//! use tesserax_http::{DocRouter, RouteDoc};
//! async fn h() -> &'static str { "ok" }
//! let _r: DocRouter = DocRouter::new().get("/x", h, None::<RouteDoc>);
//! ```
//!
//! # Tier
//!
//! Every [`RouteDoc`] carries the minimum [`Tier`] a caller needs; the tier
//! is what an auth gate enforces, the [`AuthKind`] is documentation. A doc
//! built with [`RouteDoc::new`] (or from a bare string) declares auth
//! `none` and therefore tier `Public`; [`RouteDoc::bearer`],
//! [`RouteDoc::session`] and [`RouteDoc::api_key`] start at
//! `Authenticated`. [`RouteDoc::tier`] and [`RouteDoc::scope`] refine it.
//! [`DocRouter::route_table`] merges tier and description into one
//! [`RouteTable`]: each entry's `label` is the description.

use std::collections::BTreeMap;
use std::convert::Infallible;

use axum::Router;
use axum::extract::Request;
use axum::handler::Handler;
use axum::response::IntoResponse;
use axum::routing::{self, MethodRouter, Route};
use serde::{Deserialize, Serialize};
use tesserax::{HttpMethod, RouteEntry, RouteTable, Scope, Tier};

/// The auth class of one route, as recorded in [`Endpoint::auth`]:
/// `none | bearer | session | api_key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthKind {
    /// No credential.
    None,
    /// `Authorization: Bearer`.
    Bearer,
    /// Session cookie.
    Session,
    /// API key.
    ApiKey,
}

impl AuthKind {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthKind::None => "none",
            AuthKind::Bearer => "bearer",
            AuthKind::Session => "session",
            AuthKind::ApiKey => "api_key",
        }
    }
}

/// What every route-adding call on [`DocRouter`] must supply: a
/// description, the tier, and optional metadata.
///
/// A bare `&str` / `String` converts to [`RouteDoc::new`]: auth `none`,
/// tier `Public`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteDoc {
    /// What the route does.
    pub description: String,
    /// Credential kind (documentation).
    pub auth: AuthKind,
    /// Minimum tier (enforced by an auth gate reading the route table).
    pub tier: Tier,
    /// Capability required in addition to the tier.
    pub scope: Option<Scope>,
    /// Reachable from outside the host (documentation flag for manifests).
    pub public: bool,
    /// Name or inline form of the request body schema.
    pub body_schema: Option<String>,
    /// Free key/value labels (owners of manifests put their own keys here).
    pub labels: BTreeMap<String, String>,
}

impl RouteDoc {
    /// Auth `none`, tier `Public`.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            auth: AuthKind::None,
            tier: Tier::Public,
            scope: None,
            public: false,
            body_schema: None,
            labels: BTreeMap::new(),
        }
    }

    /// Auth `bearer`, tier `Authenticated`.
    pub fn bearer(description: impl Into<String>) -> Self {
        Self {
            auth: AuthKind::Bearer,
            tier: Tier::Authenticated,
            ..Self::new(description)
        }
    }

    /// Auth `session`, tier `Authenticated`.
    pub fn session(description: impl Into<String>) -> Self {
        Self {
            auth: AuthKind::Session,
            tier: Tier::Authenticated,
            ..Self::new(description)
        }
    }

    /// Auth `api_key`, tier `Authenticated`.
    pub fn api_key(description: impl Into<String>) -> Self {
        Self {
            auth: AuthKind::ApiKey,
            tier: Tier::Authenticated,
            ..Self::new(description)
        }
    }

    /// Sets the minimum tier.
    pub fn tier(mut self, tier: Tier) -> Self {
        self.tier = tier;
        self
    }

    /// Requires `scope` in addition to the tier.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Marks the route as reachable from outside the host.
    pub fn public(mut self) -> Self {
        self.public = true;
        self
    }

    /// Names the request body schema.
    pub fn body_schema(mut self, schema: impl Into<String>) -> Self {
        self.body_schema = Some(schema.into());
        self
    }

    /// Adds a key/value label.
    pub fn label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_owned(), value.to_owned());
        self
    }
}

impl From<&str> for RouteDoc {
    fn from(description: &str) -> Self {
        RouteDoc::new(description)
    }
}

impl From<String> for RouteDoc {
    fn from(description: String) -> Self {
        RouteDoc::new(description)
    }
}

/// One route as recorded by [`DocRouter`]; the wire form for manifests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Upper-case verb.
    pub method: String,
    /// Route template as served (after `nest`).
    pub path: String,
    /// What the route does.
    pub description: String,
    /// `none | bearer | session | api_key`.
    pub auth: String,
    /// Minimum tier.
    pub tier: Tier,
    /// Required scope, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Reachable from outside the host.
    pub public: bool,
    /// Request body schema name.
    pub body_schema: Option<String>,
    /// Key/value labels.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// Joins a `nest` prefix with a recorded path the way `axum::Router::nest`
/// composes the paths it serves.
fn join_path(prefix: &str, path: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    match (prefix.is_empty(), path.is_empty()) {
        (true, true) => "/".to_owned(),
        (_, true) => prefix.to_owned(),
        _ => format!("{prefix}/{path}"),
    }
}

struct Recorded<S> {
    method: HttpMethod,
    path: String,
    handler: MethodRouter<S>,
    doc: RouteDoc,
}

impl<S> Recorded<S> {
    fn endpoint(&self) -> Endpoint {
        Endpoint {
            method: self.method.as_str().to_owned(),
            path: self.path.clone(),
            description: self.doc.description.clone(),
            auth: self.doc.auth.as_str().to_owned(),
            tier: self.doc.tier,
            scope: self.doc.scope.as_ref().map(|s| s.as_str().to_owned()),
            public: self.doc.public,
            body_schema: self.doc.body_schema.clone(),
            labels: self.doc.labels.clone(),
        }
    }

    fn entry(&self) -> RouteEntry {
        let mut e = RouteEntry::new(self.method, self.path.clone(), self.doc.tier)
            .with_label(self.doc.description.clone());
        if let Some(s) = &self.doc.scope {
            e = e.with_scope(s.clone());
        }
        e
    }
}

/// A route-recording router. See the module documentation.
pub struct DocRouter<S = ()> {
    routes: Vec<Recorded<S>>,
}

impl<S> Default for DocRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> std::fmt::Debug for DocRouter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(
                self.routes
                    .iter()
                    .map(|r| format!("{} {}", r.method, r.path)),
            )
            .finish()
    }
}

macro_rules! verb {
    ($(#[$m:meta])* $name:ident, $method:expr, $routing:path) => {
        $(#[$m])*
        pub fn $name<H, T>(self, path: &str, handler: H, doc: impl Into<RouteDoc>) -> Self
        where
            H: Handler<T, S>,
            T: 'static,
        {
            self.push($method, path, $routing(handler), doc.into())
        }
    };
}

impl<S> DocRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Empty router.
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    fn push(
        mut self,
        method: HttpMethod,
        path: &str,
        handler: MethodRouter<S>,
        doc: RouteDoc,
    ) -> Self {
        self.routes.push(Recorded {
            method,
            path: path.to_owned(),
            handler,
            doc,
        });
        self
    }

    verb!(
        /// `GET path` (axum also answers `HEAD`).
        get, HttpMethod::Get, routing::get
    );
    verb!(
        /// `POST path`.
        post, HttpMethod::Post, routing::post
    );
    verb!(
        /// `PUT path`.
        put, HttpMethod::Put, routing::put
    );
    verb!(
        /// `PATCH path`.
        patch, HttpMethod::Patch, routing::patch
    );
    verb!(
        /// `DELETE path`.
        delete, HttpMethod::Delete, routing::delete
    );
    verb!(
        /// `OPTIONS path`.
        options, HttpMethod::Options, routing::options
    );

    /// Mounts every route of `other` under `prefix`; recorded paths are
    /// rewritten exactly as `axum::Router::nest` rewrites served ones.
    pub fn nest(mut self, prefix: &str, other: DocRouter<S>) -> Self {
        for mut r in other.routes {
            r.path = join_path(prefix, &r.path);
            self.routes.push(r);
        }
        self
    }

    /// Adds every route of `other` at its own path.
    pub fn merge(mut self, other: DocRouter<S>) -> Self {
        self.routes.extend(other.routes);
        self
    }

    /// Wraps every route added so far in `layer` (as `MethodRouter::layer`).
    /// Never changes the recorded list.
    pub fn layer<L>(mut self, layer: L) -> Self
    where
        L: tower_layer::Layer<Route> + Clone + Send + Sync + 'static,
        L::Service:
            tower_service::Service<Request, Error = Infallible> + Clone + Send + Sync + 'static,
        <L::Service as tower_service::Service<Request>>::Response: IntoResponse + 'static,
        <L::Service as tower_service::Service<Request>>::Future: Send + 'static,
    {
        for r in &mut self.routes {
            let h = std::mem::take(&mut r.handler);
            r.handler = h.layer(layer.clone());
        }
        self
    }

    /// Wraps the matched handlers of every route added so far in `layer`
    /// (as `MethodRouter::route_layer`: a verb the route does not serve
    /// still answers 405 without running the layer).
    pub fn route_layer<L>(mut self, layer: L) -> Self
    where
        L: tower_layer::Layer<Route> + Clone + Send + Sync + 'static,
        L::Service:
            tower_service::Service<Request, Error = Infallible> + Clone + Send + Sync + 'static,
        <L::Service as tower_service::Service<Request>>::Response: IntoResponse + 'static,
        <L::Service as tower_service::Service<Request>>::Future: Send + 'static,
    {
        for r in &mut self.routes {
            let h = std::mem::take(&mut r.handler);
            r.handler = h.route_layer(layer.clone());
        }
        self
    }

    /// Supplies the handler state; the recorded list carries over.
    pub fn with_state<S2>(self, state: S) -> DocRouter<S2> {
        DocRouter {
            routes: self
                .routes
                .into_iter()
                .map(|r| Recorded {
                    method: r.method,
                    path: r.path,
                    handler: r.handler.with_state(state.clone()),
                    doc: r.doc,
                })
                .collect(),
        }
    }

    /// Recorded routes as manifest entries, in registration order.
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.routes.iter().map(Recorded::endpoint).collect()
    }

    /// Recorded routes as a [`RouteTable`]: tier and scope from each
    /// [`RouteDoc`], the description as the entry's `label`.
    pub fn route_table(&self) -> RouteTable {
        self.routes.iter().map(Recorded::entry).collect()
    }

    /// Number of recorded routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// True iff no route was added.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// The real router and the recorded list. Two verbs added separately
    /// at one path are merged into one route, as two `Router::route` calls
    /// are.
    pub fn into_parts(self) -> (Router<S>, Vec<Endpoint>) {
        let endpoints = self.endpoints();
        let mut router = Router::new();
        for r in self.routes {
            router = router.route(&r.path, r.handler);
        }
        (router, endpoints)
    }

    /// One `(entry, handler)` pair per route, for a server builder's route
    /// table (see `HttpExt::with_routes`).
    pub fn into_entries(self) -> Vec<(RouteEntry, MethodRouter<S>)> {
        self.routes
            .into_iter()
            .map(|r| (r.entry(), r.handler))
            .collect()
    }

    /// Routes whose description is empty or only whitespace.
    pub fn undescribed(&self) -> Vec<(HttpMethod, String)> {
        self.routes
            .iter()
            .filter(|r| r.doc.description.trim().is_empty())
            .map(|r| (r.method, r.path.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_path_matches_nest() {
        assert_eq!(join_path("/api", "/status"), "/api/status");
        assert_eq!(join_path("/api/", "status"), "/api/status");
        assert_eq!(join_path("/api", "/"), "/api");
        assert_eq!(join_path("/", "/"), "/");
        assert_eq!(join_path("", "/x"), "/x");
    }

    #[test]
    fn tiers_follow_auth_kind() {
        assert_eq!(RouteDoc::new("a").tier, Tier::Public);
        assert_eq!(RouteDoc::from("a").auth, AuthKind::None);
        assert_eq!(RouteDoc::bearer("a").tier, Tier::Authenticated);
        assert_eq!(RouteDoc::session("a").tier, Tier::Authenticated);
        assert_eq!(RouteDoc::api_key("a").auth.as_str(), "api_key");
        assert_eq!(RouteDoc::bearer("a").tier(Tier::Admin).tier, Tier::Admin);
    }
}
