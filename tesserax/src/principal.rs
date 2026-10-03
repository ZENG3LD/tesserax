//! [`Principal`]: who is calling, as authentication hands it to handlers,
//! tools and the audit sink.

use std::sync::Arc;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::NameError;
use crate::tier::{Scope, ScopeSet, Tier, validate_name};

macro_rules! name_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[cfg_attr(
            feature = "serde",
            derive(Serialize, Deserialize),
            serde(try_from = "String", into = "String")
        )]
        pub struct $name(Arc<str>);

        impl $name {
            /// Validates and wraps `name` (at most
            /// [`MAX_NAME_LEN`](crate::tier::MAX_NAME_LEN) bytes of `[A-Za-z0-9._:-]`).
            pub fn new(name: &str) -> Result<Self, NameError> {
                validate_name(name)?;
                Ok(Self(Arc::from(name)))
            }

            /// The name.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl core::str::FromStr for $name {
            type Err = NameError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl TryFrom<String> for $name {
            type Error = NameError;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(&s)
            }
        }

        impl From<$name> for String {
            fn from(n: $name) -> Self {
                n.0.as_ref().to_owned()
            }
        }
    };
}

name_newtype!(
    /// Public identifier of a credential (never the secret itself).
    KeyId
);
name_newtype!(
    /// Name of an entry point with its own admission policy (for example a
    /// control door and an observe door on one server).
    DoorName
);

/// An authenticated (or anonymous) caller.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Principal {
    /// Which credential was presented.
    pub key_id: KeyId,
    /// Which door admitted it.
    pub door: DoorName,
    /// Access level granted on that door.
    pub tier: Tier,
    /// Capabilities granted on that door.
    pub scopes: ScopeSet,
}

impl Principal {
    /// True iff the principal's tier satisfies `required`.
    pub fn satisfies(&self, required: Tier) -> bool {
        self.tier.satisfies(required)
    }

    /// True iff the principal carries exactly `scope`.
    pub fn has_scope(&self, scope: &Scope) -> bool {
        self.scopes.contains(scope)
    }

    /// True iff the tier satisfies `required_tier` and, when given, the scope
    /// is carried.
    pub fn allows(&self, required_tier: Tier, required_scope: Option<&Scope>) -> bool {
        self.satisfies(required_tier) && required_scope.is_none_or(|s| self.has_scope(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_checks_tier_and_scope() {
        let read = Scope::new("jobs.read").unwrap();
        let write = Scope::new("jobs.write").unwrap();
        let p = Principal {
            key_id: KeyId::new("k1").unwrap(),
            door: DoorName::new("control").unwrap(),
            tier: Tier::Admin,
            scopes: [read.clone()].into_iter().collect(),
        };
        assert!(p.allows(Tier::Authenticated, None));
        assert!(p.allows(Tier::Admin, Some(&read)));
        assert!(!p.allows(Tier::Admin, Some(&write)));
        assert!(!p.allows(Tier::Root, None));
    }

    #[test]
    fn names_validate() {
        assert!(DoorName::new("observe").is_ok());
        assert_eq!(KeyId::new(""), Err(NameError::Empty));
    }
}
