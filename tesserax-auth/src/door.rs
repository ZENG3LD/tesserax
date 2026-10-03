//! Doors: named entry points with a path policy.

use tesserax::{DoorName, HttpMethod, ScopeSet, Tier};

use crate::error::AuthError;

/// A route template as the router registered it (`/items/{id}`), compared
/// against axum's `MatchedPath`, never against the raw request path.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PathTemplate(String);

impl PathTemplate {
    /// Validates that `template` starts with `/`.
    pub fn new(template: impl Into<String>) -> Result<Self, AuthError> {
        let t = template.into();
        if t.starts_with('/') {
            Ok(Self(t))
        } else {
            Err(AuthError::Malformed(format!(
                "path template {t:?} must start with '/'"
            )))
        }
    }

    /// The template.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True if `template` is this prefix or lies below it on a segment
    /// boundary (`/api` covers `/api` and `/api/x`, not `/apix`).
    fn covers(&self, template: &str) -> bool {
        let p = self.0.trim_end_matches('/');
        template == p
            || template
                .strip_prefix(p)
                .is_some_and(|rest| rest.starts_with('/'))
            || p.is_empty()
    }
}

/// Which routes a door admits. `Default` is `Exact(vec![])`: nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Policy {
    /// Every route.
    Any,
    /// Routes whose template lies under one of these prefixes.
    Prefix(Vec<PathTemplate>),
    /// Exactly these `(method, template)` pairs.
    Exact(Vec<(HttpMethod, PathTemplate)>),
}

impl Default for Policy {
    fn default() -> Self {
        Policy::Exact(Vec::new())
    }
}

impl Policy {
    /// True if the policy admits `method template`.
    pub fn admits(&self, method: HttpMethod, template: &str) -> bool {
        match self {
            Policy::Any => true,
            Policy::Prefix(prefixes) => prefixes.iter().any(|p| p.covers(template)),
            Policy::Exact(pairs) => pairs
                .iter()
                .any(|(m, t)| *m == method && t.as_str() == template),
        }
    }
}

/// A named entry point: a path policy plus how credentials may arrive.
#[derive(Clone, Debug)]
pub struct Door {
    /// Name referenced by key grants.
    pub name: DoorName,
    /// Routes this door serves.
    pub policy: Policy,
    /// Accept the key from `?api_key=` as well as the `Authorization`
    /// header (for clients such as EventSource that cannot set headers).
    /// Off by default: query strings end up in logs.
    pub allow_query_key: bool,
    /// Admit callers without a key when they connect over loopback with no
    /// forwarding headers, at this tier and these scopes.
    pub loopback_grant: Option<(Tier, ScopeSet)>,
}

impl Door {
    /// Door with `policy`, header keys only, no loopback admission.
    pub fn new(name: DoorName, policy: Policy) -> Self {
        Self {
            name,
            policy,
            allow_query_key: false,
            loopback_grant: None,
        }
    }

    /// Door admitting every route to loopback callers without a key, at
    /// `Admin` (keys are still honoured). The only way to serve without
    /// keys; remote callers still need one.
    pub fn open_loopback_only(name: DoorName) -> Self {
        Self {
            name,
            policy: Policy::Any,
            allow_query_key: false,
            loopback_grant: Some((Tier::Admin, ScopeSet::new())),
        }
    }

    /// Also accept `?api_key=`.
    pub fn allow_query_key(mut self) -> Self {
        self.allow_query_key = true;
        self
    }

    /// Changes the loopback grant.
    pub fn loopback_grant(mut self, tier: Tier, scopes: ScopeSet) -> Self {
        self.loopback_grant = Some((tier, scopes));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> PathTemplate {
        PathTemplate::new(s).unwrap()
    }

    #[test]
    fn policies() {
        assert!(Policy::Any.admits(HttpMethod::Get, "/x"));
        assert!(!Policy::default().admits(HttpMethod::Get, "/x"));
        let p = Policy::Prefix(vec![t("/api")]);
        assert!(p.admits(HttpMethod::Get, "/api"));
        assert!(p.admits(HttpMethod::Post, "/api/jobs/{id}"));
        assert!(!p.admits(HttpMethod::Get, "/apix"));
        assert!(!p.admits(HttpMethod::Get, "/health"));
        assert!(Policy::Prefix(vec![t("/")]).admits(HttpMethod::Get, "/anything"));
        let e = Policy::Exact(vec![(HttpMethod::Get, t("/jobs/{id}"))]);
        assert!(e.admits(HttpMethod::Get, "/jobs/{id}"));
        assert!(!e.admits(HttpMethod::Delete, "/jobs/{id}"));
        assert!(!e.admits(HttpMethod::Get, "/jobs/7"));
        assert!(PathTemplate::new("nope").is_err());
    }
}
