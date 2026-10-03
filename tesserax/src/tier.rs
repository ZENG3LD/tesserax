//! Access levels ([`Tier`]) and named capabilities ([`Scope`]).
//!
//! Two independent axes:
//!
//! ```text
//! Tier:  Public < Authenticated < Admin < Root     (linear; higher satisfies lower)
//! Scope: "fleet.read", "jobs.write", ...           (orthogonal; only an explicit grant satisfies)
//! ```
//!
//! `Root` never implies a scope: a route that needs `Scope("upload")` is
//! satisfied only by a caller that carries exactly that scope.

use std::collections::BTreeSet;
use std::sync::Arc;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::error::NameError;

/// Longest scope, key id or door name, in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// Access level, ordered `Public < Authenticated < Admin < Root`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum Tier {
    /// No authentication.
    #[default]
    Public,
    /// Any valid credential.
    Authenticated,
    /// Administrative credential.
    Admin,
    /// Operations on the server itself (shutdown, key rotation).
    Root,
}

impl Tier {
    /// True iff a caller at `self` may use something that requires `required`.
    pub fn satisfies(self, required: Tier) -> bool {
        self >= required
    }

    /// Lower-case name, as used in configuration and on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Public => "public",
            Tier::Authenticated => "authenticated",
            Tier::Admin => "admin",
            Tier::Root => "root",
        }
    }
}

impl core::fmt::Display for Tier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Set of tiers, e.g. the tiers a door can issue. Only its maximum matters
/// for [`satisfies`](Self::satisfies); an empty set behaves as `Public`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct TierSet {
    tiers: BTreeSet<Tier>,
}

impl TierSet {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `tier`; returns true if it was not present.
    pub fn insert(&mut self, tier: Tier) -> bool {
        self.tiers.insert(tier)
    }

    /// True iff `tier` is in the set.
    pub fn contains(&self, tier: Tier) -> bool {
        self.tiers.contains(&tier)
    }

    /// Number of tiers in the set.
    pub fn len(&self) -> usize {
        self.tiers.len()
    }

    /// True iff the set is empty.
    pub fn is_empty(&self) -> bool {
        self.tiers.is_empty()
    }

    /// Tiers in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = Tier> + '_ {
        self.tiers.iter().copied()
    }

    /// Highest tier in the set; `Public` when empty.
    pub fn max_level(&self) -> Tier {
        self.tiers.last().copied().unwrap_or(Tier::Public)
    }

    /// True iff the highest tier satisfies `required`.
    pub fn satisfies(&self, required: Tier) -> bool {
        self.max_level().satisfies(required)
    }
}

impl FromIterator<Tier> for TierSet {
    fn from_iter<I: IntoIterator<Item = Tier>>(iter: I) -> Self {
        Self {
            tiers: iter.into_iter().collect(),
        }
    }
}

/// Named capability tag, e.g. `"fleet.read"`. At most [`MAX_NAME_LEN`] bytes
/// of `[A-Za-z0-9._:-]`, never empty. Cheap to clone.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct Scope(Arc<str>);

impl Scope {
    /// Validates and wraps `name`.
    pub fn new(name: &str) -> Result<Self, NameError> {
        validate_name(name)?;
        Ok(Self(Arc::from(name)))
    }

    /// The tag.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Scope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::str::FromStr for Scope {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Scope::new(s)
    }
}

impl TryFrom<String> for Scope {
    type Error = NameError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Scope::new(&s)
    }
}

impl From<Scope> for String {
    fn from(s: Scope) -> Self {
        s.0.as_ref().to_owned()
    }
}

/// Set of [`Scope`]s a caller carries.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct ScopeSet {
    scopes: BTreeSet<Scope>,
}

impl ScopeSet {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `scope`; returns true if it was not present.
    pub fn insert(&mut self, scope: Scope) -> bool {
        self.scopes.insert(scope)
    }

    /// True iff `scope` is in the set (exact match; no wildcard, no hierarchy).
    pub fn contains(&self, scope: &Scope) -> bool {
        self.scopes.contains(scope)
    }

    /// Number of scopes.
    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    /// True iff the set is empty.
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    /// Scopes in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = &Scope> + '_ {
        self.scopes.iter()
    }
}

impl FromIterator<Scope> for ScopeSet {
    fn from_iter<I: IntoIterator<Item = Scope>>(iter: I) -> Self {
        Self {
            scopes: iter.into_iter().collect(),
        }
    }
}

pub(crate) fn validate_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong {
            len: name.len(),
            max: MAX_NAME_LEN,
        });
    }
    match name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-')))
    {
        Some(bad) => Err(NameError::BadChar(bad)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_order_is_linear() {
        assert!(Tier::Root.satisfies(Tier::Admin));
        assert!(Tier::Admin.satisfies(Tier::Authenticated));
        assert!(Tier::Authenticated.satisfies(Tier::Public));
        assert!(!Tier::Authenticated.satisfies(Tier::Admin));
        assert!(!Tier::Public.satisfies(Tier::Authenticated));
    }

    #[test]
    fn tier_set_uses_its_maximum() {
        let set: TierSet = [Tier::Authenticated, Tier::Admin].into_iter().collect();
        assert_eq!(set.max_level(), Tier::Admin);
        assert!(set.satisfies(Tier::Admin));
        assert!(!set.satisfies(Tier::Root));
        assert!(TierSet::new().satisfies(Tier::Public));
        assert!(!TierSet::new().satisfies(Tier::Authenticated));
    }

    #[test]
    fn scope_validation() {
        assert!(Scope::new("fleet.read").is_ok());
        assert!(Scope::new("a:b-c_d.9").is_ok());
        assert_eq!(Scope::new(""), Err(NameError::Empty));
        assert_eq!(Scope::new("has space"), Err(NameError::BadChar(' ')));
        assert!(matches!(
            Scope::new(&"x".repeat(MAX_NAME_LEN + 1)),
            Err(NameError::TooLong { .. })
        ));
    }

    #[test]
    fn scope_set_is_exact_match() {
        let read = Scope::new("fleet.read").unwrap();
        let write = Scope::new("fleet.write").unwrap();
        let set: ScopeSet = [read.clone()].into_iter().collect();
        assert!(set.contains(&read));
        assert!(!set.contains(&write));
    }
}
