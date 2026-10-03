//! Key hashes, grants, records and the key ring.

use std::collections::BTreeSet;

use tesserax::{DoorName, KeyId, ScopeSet, Tier};
use zeroize::Zeroizing;

use crate::ct::{ct_eq_32, from_hex_32, sha256, to_hex};
use crate::error::AuthError;

/// SHA-256 of a raw key. Raw keys are hashed as soon as they are read and
/// never kept; only hashes live in a [`KeyRing`].
#[derive(Clone, Copy)]
pub struct KeyHash([u8; 32]);

impl KeyHash {
    /// Hash of a raw key.
    pub fn of_raw(raw: &str) -> Self {
        Self(sha256(raw.as_bytes()))
    }

    /// Parses a 64-digit hex hash.
    pub fn from_hex(hex: &str) -> Result<Self, AuthError> {
        from_hex_32(hex.trim())
            .map(Self)
            .ok_or_else(|| AuthError::Malformed("key hash must be 64 hex digits".into()))
    }

    /// Lower-case hex form (safe to store in configuration).
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    /// Constant-time comparison.
    pub fn ct_matches(&self, other: &KeyHash) -> bool {
        ct_eq_32(&self.0, &other.0)
    }
}

impl std::fmt::Debug for KeyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyHash({}…)", to_hex(&self.0[..4]))
    }
}

/// Generates a fresh key from the OS random number generator: 32 random
/// bytes as 64 hex digits, and its hash. Hand the raw key to the caller
/// once; store only the hash.
pub fn generate_key() -> Result<(Zeroizing<String>, KeyHash), AuthError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|e| AuthError::Rng(e.to_string()))?;
    let raw = Zeroizing::new(to_hex(bytes.as_ref()));
    let hash = KeyHash::of_raw(&raw);
    Ok((raw, hash))
}

/// Access a key has on one door.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    /// Door the grant applies to.
    pub door: DoorName,
    /// Tier on that door.
    pub tier: Tier,
    /// Scopes on that door.
    pub scopes: ScopeSet,
}

impl Grant {
    /// Grant of `tier` with no scopes.
    pub fn new(door: DoorName, tier: Tier) -> Self {
        Self {
            door,
            tier,
            scopes: ScopeSet::new(),
        }
    }

    /// Adds scopes.
    pub fn with_scopes(mut self, scopes: ScopeSet) -> Self {
        self.scopes = scopes;
        self
    }
}

/// One key.
#[derive(Clone, Debug)]
pub struct KeyRecord {
    /// Public identifier (appears in audit records).
    pub id: KeyId,
    /// Hash of the raw key.
    pub hash: KeyHash,
    /// What the key may do.
    pub grants: Vec<Grant>,
    /// Expiry in Unix milliseconds; `None` never expires.
    pub not_after_ms: Option<u64>,
    /// Free-form note.
    pub label: String,
}

impl KeyRecord {
    /// Record with no expiry and an empty label.
    pub fn new(id: KeyId, hash: KeyHash, grants: Vec<Grant>) -> Self {
        Self {
            id,
            hash,
            grants,
            not_after_ms: None,
            label: String::new(),
        }
    }

    /// Sets an expiry.
    pub fn expires_at_ms(mut self, not_after_ms: u64) -> Self {
        self.not_after_ms = Some(not_after_ms);
        self
    }

    /// True if the record is usable at `now_ms`.
    pub fn is_live(&self, now_ms: u64) -> bool {
        self.not_after_ms.is_none_or(|t| now_ms < t)
    }
}

/// All keys a gate accepts. An empty ring denies every credential.
/// Hold it in `tesserax::Published<KeyRing>` and rotate by storing a new
/// ring.
#[derive(Clone, Debug, Default)]
pub struct KeyRing {
    records: Vec<KeyRecord>,
}

impl KeyRing {
    /// Empty ring (denies everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Ring from records; key ids must be unique.
    pub fn from_records(records: Vec<KeyRecord>) -> Result<Self, AuthError> {
        let mut ids = BTreeSet::new();
        for r in &records {
            if !ids.insert(r.id.clone()) {
                return Err(AuthError::Malformed(format!("duplicate key id {}", r.id)));
            }
        }
        Ok(Self { records })
    }

    /// True if the ring has no record.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Records in order.
    pub fn records(&self) -> &[KeyRecord] {
        &self.records
    }

    /// The record whose hash equals `presented`. Every record is compared
    /// (no early exit), so timing does not reveal which record matched or
    /// how many there are before it.
    pub fn find(&self, presented: &KeyHash) -> Option<&KeyRecord> {
        let mut found = None;
        for r in &self.records {
            let hit = r.hash.ct_matches(presented);
            if hit && found.is_none() {
                found = Some(r);
            }
        }
        found
    }

    /// Parses a ring from TOML:
    ///
    /// ```toml
    /// [[key]]
    /// id = "ops"
    /// hash = "<64 hex digits: sha256 of the raw key>"
    /// label = "admin laptop"           # optional
    /// not_after_ms = 1893456000000     # optional
    ///
    /// [[key.grant]]
    /// door = "control"
    /// tier = "admin"                   # public | authenticated | admin | root
    /// scopes = ["jobs.write"]          # optional
    /// ```
    ///
    /// Raw keys are not accepted in the file.
    #[cfg(feature = "toml")]
    pub fn from_toml(text: &str) -> Result<Self, AuthError> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct File {
            #[serde(default)]
            key: Vec<KeyToml>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct KeyToml {
            id: String,
            hash: String,
            #[serde(default)]
            label: String,
            not_after_ms: Option<u64>,
            #[serde(default)]
            grant: Vec<GrantToml>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct GrantToml {
            door: String,
            tier: String,
            #[serde(default)]
            scopes: Vec<String>,
        }

        let file: File = toml::from_str(text).map_err(|e| AuthError::Malformed(e.to_string()))?;
        let bad = |e: tesserax::tier::NameError| AuthError::Malformed(e.to_string());
        let mut records = Vec::with_capacity(file.key.len());
        for k in file.key {
            let mut grants = Vec::with_capacity(k.grant.len());
            for g in k.grant {
                let tier = match g.tier.as_str() {
                    "public" => Tier::Public,
                    "authenticated" => Tier::Authenticated,
                    "admin" => Tier::Admin,
                    "root" => Tier::Root,
                    other => return Err(AuthError::Malformed(format!("unknown tier {other:?}"))),
                };
                let scopes = g
                    .scopes
                    .iter()
                    .map(|s| tesserax::Scope::new(s).map_err(bad))
                    .collect::<Result<ScopeSet, _>>()?;
                grants.push(Grant {
                    door: DoorName::new(&g.door).map_err(bad)?,
                    tier,
                    scopes,
                });
            }
            records.push(KeyRecord {
                id: KeyId::new(&k.id).map_err(bad)?,
                hash: KeyHash::from_hex(&k.hash)?,
                grants,
                not_after_ms: k.not_after_ms,
                label: k.label,
            });
        }
        Self::from_records(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_64_hex_and_distinct() {
        let (a, ha) = generate_key().unwrap();
        let (b, hb) = generate_key().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert!(!crate::ct::ct_eq_str(&a, &b));
        assert!(ha.ct_matches(&KeyHash::of_raw(&a)));
        assert!(!ha.ct_matches(&hb));
    }

    #[test]
    fn find_matches_by_hash() {
        let door = DoorName::new("d").unwrap();
        let ring = KeyRing::from_records(vec![
            KeyRecord::new(
                KeyId::new("a").unwrap(),
                KeyHash::of_raw("ka"),
                vec![Grant::new(door.clone(), Tier::Admin)],
            ),
            KeyRecord::new(KeyId::new("b").unwrap(), KeyHash::of_raw("kb"), vec![]),
        ])
        .unwrap();
        assert_eq!(
            ring.find(&KeyHash::of_raw("kb")).map(|r| r.id.as_str()),
            Some("b")
        );
        assert!(ring.find(&KeyHash::of_raw("kc")).is_none());
        assert!(KeyRing::new().find(&KeyHash::of_raw("ka")).is_none());
        let dup = KeyRing::from_records(vec![
            KeyRecord::new(KeyId::new("a").unwrap(), KeyHash::of_raw("1"), vec![]),
            KeyRecord::new(KeyId::new("a").unwrap(), KeyHash::of_raw("2"), vec![]),
        ]);
        assert!(dup.is_err());
    }

    #[test]
    fn expiry() {
        let r = KeyRecord::new(KeyId::new("a").unwrap(), KeyHash::of_raw("x"), vec![])
            .expires_at_ms(100);
        assert!(r.is_live(99));
        assert!(!r.is_live(100));
    }

    #[cfg(feature = "toml")]
    #[test]
    fn from_toml_parses_and_rejects() {
        let hash = KeyHash::of_raw("secret").to_hex();
        let text = format!(
            r#"
            [[key]]
            id = "ops"
            hash = "{hash}"
            not_after_ms = 5
            [[key.grant]]
            door = "control"
            tier = "admin"
            scopes = ["jobs.write"]
            "#
        );
        let ring = KeyRing::from_toml(&text).unwrap();
        assert_eq!(ring.len(), 1);
        let r = &ring.records()[0];
        assert_eq!(r.grants[0].tier, Tier::Admin);
        assert_eq!(r.not_after_ms, Some(5));
        assert!(ring.find(&KeyHash::of_raw("secret")).is_some());

        assert!(KeyRing::from_toml("").unwrap().is_empty());
        assert!(KeyRing::from_toml("[[key]]\nid = \"a\"\nhash = \"nothex\"").is_err());
        assert!(KeyRing::from_toml("[[key]]\nid = \"a\"\nraw = \"x\"\nhash = \"00\"").is_err());
        let bad_tier = format!(
            "[[key]]\nid = \"a\"\nhash = \"{hash}\"\n[[key.grant]]\ndoor = \"d\"\ntier = \"god\""
        );
        assert!(KeyRing::from_toml(&bad_tier).is_err());
    }
}
