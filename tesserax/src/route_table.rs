//! [`RouteTable`]: every route a server serves, with its minimum [`Tier`].
//!
//! The table is the single source of truth for what routes exist. The
//! server builder fills it; plugins read it at build time (OpenAPI,
//! registration with a control plane); an auth gate reads it per request to
//! find the tier a `(method, route template)` pair requires.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::tier::{Scope, Tier};

/// HTTP verbs a route can be declared with.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "UPPERCASE")
)]
pub enum HttpMethod {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `HEAD`
    Head,
    /// `OPTIONS`
    Options,
}

impl HttpMethod {
    /// Upper-case verb.
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
        }
    }

    /// Parses an upper-case verb.
    pub fn parse(verb: &str) -> Option<Self> {
        Some(match verb {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            _ => return None,
        })
    }
}

impl core::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One declared route.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RouteEntry {
    /// Verb.
    pub method: HttpMethod,
    /// Route template as registered (e.g. `/items/{id}`).
    pub path: String,
    /// Minimum tier a caller needs.
    pub tier: Tier,
    /// Capability a caller needs in addition to the tier, if any.
    pub scope: Option<Scope>,
    /// Human-readable description of the route, for documentation and
    /// plugins (OpenAPI summary, manifests); never used for admission.
    /// Routes declared through a self-describing router always carry one.
    pub label: Option<String>,
    /// True for routes the server itself provides (`/health`, `/livez`,
    /// `/readyz`, `/admin/drain`, `/reload`).
    pub builtin: bool,
}

impl RouteEntry {
    /// A route at `tier` with no scope and no label.
    pub fn new(method: HttpMethod, path: impl Into<String>, tier: Tier) -> Self {
        Self {
            method,
            path: path.into(),
            tier,
            scope: None,
            label: None,
            builtin: false,
        }
    }

    /// Adds a required scope.
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Adds a label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// Ordered list of [`RouteEntry`]s.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct RouteTable {
    routes: Vec<RouteEntry>,
}

impl RouteTable {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an entry.
    pub fn push(&mut self, entry: RouteEntry) {
        self.routes.push(entry);
    }

    /// Entries in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &RouteEntry> + '_ {
        self.routes.iter()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// True iff empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// The entry for `(method, template)`. `template` is the registered
    /// route template (axum's `MatchedPath`), not the raw request path.
    pub fn lookup(&self, method: HttpMethod, template: &str) -> Option<&RouteEntry> {
        self.routes
            .iter()
            .find(|r| r.method == method && r.path == template)
    }

    /// Entries whose tier is `Admin` or `Root`.
    pub fn privileged(&self) -> impl Iterator<Item = &RouteEntry> + '_ {
        self.routes.iter().filter(|r| r.tier >= Tier::Admin)
    }

    /// First `(method, path)` pair registered twice, if any.
    pub fn first_duplicate(&self) -> Option<&RouteEntry> {
        self.routes.iter().enumerate().find_map(|(i, r)| {
            self.routes[..i]
                .iter()
                .any(|p| p.method == r.method && p.path == r.path)
                .then_some(r)
        })
    }
}

impl FromIterator<RouteEntry> for RouteTable {
    fn from_iter<I: IntoIterator<Item = RouteEntry>>(iter: I) -> Self {
        Self {
            routes: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_and_duplicates() {
        let mut t = RouteTable::new();
        t.push(RouteEntry::new(HttpMethod::Get, "/health", Tier::Public));
        t.push(RouteEntry::new(
            HttpMethod::Post,
            "/items/{id}",
            Tier::Admin,
        ));
        assert_eq!(
            t.lookup(HttpMethod::Post, "/items/{id}").map(|r| r.tier),
            Some(Tier::Admin)
        );
        assert!(t.lookup(HttpMethod::Get, "/items/{id}").is_none());
        assert_eq!(t.privileged().count(), 1);
        assert!(t.first_duplicate().is_none());
        t.push(RouteEntry::new(HttpMethod::Get, "/health", Tier::Admin));
        assert_eq!(t.first_duplicate().map(|r| r.tier), Some(Tier::Admin));
    }

    #[test]
    fn method_names_roundtrip() {
        for m in [
            HttpMethod::Get,
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Patch,
            HttpMethod::Delete,
            HttpMethod::Head,
            HttpMethod::Options,
        ] {
            assert_eq!(HttpMethod::parse(m.as_str()), Some(m));
        }
        assert_eq!(HttpMethod::parse("get"), None);
    }
}
