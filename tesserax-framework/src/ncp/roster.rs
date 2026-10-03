//! The static roster: who sits below this tier, how each entry is reached
//! and where its credential comes from.
//!
//! A roster is written by operator edit plus restart (NCP §5): it loads
//! once at startup, validates eagerly and offers **no** insert, remove or
//! extend. The token itself is never written in the roster file — the file
//! names a [`CredentialSource`] and the secret arrives through the
//! environment or a file at load time, with a named startup refusal when
//! it is missing.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use tesserax_transport::Endpoint;
use thiserror::Error;
use zeroize::Zeroizing;

/// Identity of one roster entry (a node, a wing, a box — the product's
/// vocabulary, opaque here).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EntryId(Arc<str>);

impl EntryId {
    /// Wraps `id`; empty is rejected by roster validation, not here.
    pub fn new(id: impl Into<Arc<str>>) -> Self {
        Self(id.into())
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntryId({:?})", self.as_str())
    }
}

impl AsRef<str> for EntryId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for EntryId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EntryId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self::new(s))
    }
}

/// Who opens the connection on ONE link. The control direction is never a
/// function of this: the tier above controls the tier below on every link,
/// whoever dialled (NCP §3 vs §4).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reach {
    /// This tier dials the entry.
    DialOut,
    /// The entry dials this tier; admission = roster id + link proof.
    AcceptIn,
}

/// Where the secret for one entry comes from. The token never sits in the
/// roster file: the file names the source, the secret arrives out of band
/// (alias → environment variable name, named refusal at startup when it
/// is missing).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialSource {
    /// Environment variable named `{prefix}{ALIAS}`, where ALIAS is the
    /// entry id uppercased with every non-alphanumeric byte replaced by
    /// `_` (so the file stays free of per-deployment variable names).
    EnvByAlias {
        /// Variable name prefix, e.g. `"FLEET_"`.
        prefix: String,
    },
    /// One explicit environment variable name.
    Env(String),
    /// A file read at resolution time (trailing newlines trimmed).
    File(PathBuf),
    /// A token derived from a principal secret with a purpose label.
    /// Resolution needs the principal secret, which the roster never
    /// holds: [`Roster::load`] does not try to resolve this source, and
    /// the link for such an entry is built with
    /// [`crate::ncp::DownLink::with_token`] by the caller that owns the
    /// derivation (see `tesserax-auth` derived tokens).
    Derived {
        /// Derivation purpose label, passed to the deriver.
        purpose: String,
    },
}

impl CredentialSource {
    /// The environment variable name [`CredentialSource::EnvByAlias`]
    /// resolves to for `id`.
    pub fn env_name_for(&self, id: &EntryId) -> Option<String> {
        match self {
            CredentialSource::EnvByAlias { prefix } => Some(format!(
                "{prefix}{}",
                id.as_str()
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() {
                            c.to_ascii_uppercase()
                        } else {
                            '_'
                        }
                    })
                    .collect::<String>()
            )),
            CredentialSource::Env(name) => Some(name.clone()),
            _ => None,
        }
    }

    /// Resolves the secret through `env` (and the filesystem for
    /// [`CredentialSource::File`]). `env` is injected so the roster stays
    /// pure and tests never touch the process environment.
    ///
    /// [`CredentialSource::Derived`] is not resolvable here (see its
    /// docs); this returns [`RosterError::MissingCredential`] naming the
    /// purpose, which no correct caller should hit because load skips it.
    pub fn resolve(
        &self,
        id: &EntryId,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Zeroizing<String>, RosterError> {
        match self {
            CredentialSource::EnvByAlias { .. } | CredentialSource::Env(_) => {
                let name = self.env_name_for(id).expect("env sources have a name");
                match env(&name) {
                    Some(value) if !value.is_empty() => Ok(Zeroizing::new(value)),
                    _ => Err(RosterError::MissingCredential {
                        id: id.clone(),
                        source_name: name,
                    }),
                }
            }
            CredentialSource::File(path) => {
                let raw = std::fs::read_to_string(path).map_err(|e| RosterError::Io {
                    what: format!("credential file {}: {e}", path.display()),
                })?;
                let value = raw.trim_end_matches(['\n', '\r']).to_owned();
                if value.is_empty() {
                    return Err(RosterError::MissingCredential {
                        id: id.clone(),
                        source_name: path.display().to_string(),
                    });
                }
                Ok(Zeroizing::new(value))
            }
            CredentialSource::Derived { purpose } => Err(RosterError::MissingCredential {
                id: id.clone(),
                source_name: format!("derived:{purpose}"),
            }),
        }
    }
}

/// One roster entry as the middle tier sees it: identity, endpoint,
/// reach, credential source, free-form operator labels.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LinkSpec {
    /// Roster identity; attach admission checks against it.
    pub id: EntryId,
    /// Where the entry is reached (per entry, not per process).
    #[serde(with = "endpoint_serde")]
    pub endpoint: Endpoint,
    /// Who opens the link.
    pub reach: Reach,
    /// Where the link secret comes from.
    pub credential: CredentialSource,
    /// Free-form operator labels (role, site, …); opaque here.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// One roster entry as the top tier sees it: identity, endpoint,
/// credential. **No `reach` field exists** — the top tier always dials
/// (NCP §4, table row 1). Impossibility by absence, not by policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DialEntry {
    /// Roster identity.
    pub id: EntryId,
    /// Where the entry is reached.
    #[serde(with = "endpoint_serde")]
    pub endpoint: Endpoint,
    /// Where the link secret comes from.
    pub credential: CredentialSource,
}

/// Anything a [`Roster`] can hold.
pub trait RosterEntry {
    /// The entry's roster identity.
    fn id(&self) -> &EntryId;
}

impl RosterEntry for LinkSpec {
    fn id(&self) -> &EntryId {
        &self.id
    }
}

impl RosterEntry for DialEntry {
    fn id(&self) -> &EntryId {
        &self.id
    }
}

/// A roster entry a [`crate::ncp::DownLink`] can be built for: endpoint +
/// credential source. (The design's `spawn_poller` is generic over the
/// entry type; this trait is what the poller and the link constructor
/// actually need.)
pub trait LinkTarget: RosterEntry {
    /// Where the entry is reached.
    fn endpoint(&self) -> &Endpoint;
    /// Where the link secret comes from.
    fn credential(&self) -> &CredentialSource;
}

impl LinkTarget for LinkSpec {
    fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    fn credential(&self) -> &CredentialSource {
        &self.credential
    }
}

impl LinkTarget for DialEntry {
    fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    fn credential(&self) -> &CredentialSource {
        &self.credential
    }
}

/// The injected environment used by every pure resolver in `ncp`:
/// variable name to value. Production wraps `std::env::var`; tests a map.
pub type EnvLookup = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Where roster TOML comes from. Production reads a file; tests inline a
/// string — no process-global state either way.
pub trait RosterSource {
    /// The TOML text, or the I/O failure that stopped the read.
    fn read_toml(&self) -> Result<String, RosterError>;
}

impl RosterSource for &Path {
    fn read_toml(&self) -> Result<String, RosterError> {
        std::fs::read_to_string(self).map_err(|e| RosterError::Io {
            what: format!("roster file {}: {e}", self.display()),
        })
    }
}

impl RosterSource for PathBuf {
    fn read_toml(&self) -> Result<String, RosterError> {
        self.as_path().read_toml()
    }
}

impl RosterSource for &str {
    fn read_toml(&self) -> Result<String, RosterError> {
        Ok((*self).to_owned())
    }
}

impl RosterSource for String {
    fn read_toml(&self) -> Result<String, RosterError> {
        Ok(self.clone())
    }
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "E: DeserializeOwned"))]
struct RosterFile<E> {
    #[serde(default)]
    entry: Vec<E>,
}

/// The loaded roster: an immutable, validated set of entries.
///
/// Deliberately **no** insert / remove / extend: membership changes are
/// operator edits followed by a restart (NCP §5). An id an oracle reports
/// that is not on the roster is a suspicious fact, never a new member —
/// see [`crate::ncp::reconcile`].
pub struct Roster<E: RosterEntry> {
    entries: Arc<[E]>,
}

impl<E: RosterEntry> Clone for Roster<E> {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
        }
    }
}

impl<E: RosterEntry> fmt::Debug for Roster<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Roster")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl<E: LinkTarget + DeserializeOwned> Roster<E> {
    /// Loads and validates from `src`, resolving environment credentials
    /// through the process environment. See [`Roster::load_with`] for the
    /// pure form.
    ///
    /// The bound is [`LinkTarget`], not [`RosterEntry`]: startup
    /// validation must see each entry's credential source to refuse a
    /// missing secret with its name.
    pub fn load(src: impl RosterSource) -> Result<Self, RosterError> {
        Self::load_with(src, &|name| std::env::var(name).ok())
    }

    /// Loads and validates from `src` with the environment injected.
    ///
    /// Validation (all named, all at startup, nothing lazy):
    /// non-empty roster, unique ids, non-empty endpoint per entry
    /// ([`RosterError::EmptyEndpoint`]), and every env / file credential
    /// resolvable right now — a missing one names its variable
    /// ([`RosterError::MissingCredential`]). [`CredentialSource::Derived`]
    /// is skipped here: it resolves at link construction by the caller
    /// holding the principal secret.
    pub fn load_with(
        src: impl RosterSource,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, RosterError> {
        let text = src.read_toml()?;
        // Empty endpoints fail the typed deserialization with a generic
        // message — catch them first so the refusal names the entry.
        Self::check_endpoints(&text)?;
        let parsed: RosterFile<E> = toml::from_str(&text).map_err(|e| RosterError::Toml {
            what: e.to_string(),
        })?;
        if parsed.entry.is_empty() {
            return Err(RosterError::Empty);
        }
        let mut seen = std::collections::BTreeSet::new();
        for e in &parsed.entry {
            if !seen.insert(e.id().clone()) {
                return Err(RosterError::DuplicateId(e.id().clone()));
            }
        }
        let roster = Self {
            entries: parsed.entry.into(),
        };
        for e in roster.entries.iter() {
            match e.credential() {
                CredentialSource::Derived { .. } => {}
                source => {
                    source.resolve(e.id(), env)?;
                }
            }
        }
        Ok(roster)
    }

    /// Re-walks the raw TOML to name the entry whose endpoint string is
    /// empty (the deserializer can only fail generically).
    fn check_endpoints(text: &str) -> Result<(), RosterError> {
        let value: toml::Value = toml::from_str(text).map_err(|e| RosterError::Toml {
            what: e.to_string(),
        })?;
        let Some(entries) = value.get("entry").and_then(|e| e.as_array()) else {
            return Ok(());
        };
        for entry in entries {
            let empty = entry
                .get("endpoint")
                .and_then(|e| e.as_str())
                .is_some_and(str::is_empty);
            if empty {
                let id = entry
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("<unknown>");
                return Err(RosterError::EmptyEndpoint(EntryId::new(id)));
            }
        }
        Ok(())
    }
}

impl<E: RosterEntry> Roster<E> {
    /// The entry with `id`, if it is on the roster.
    pub fn get(&self, id: &EntryId) -> Option<&E> {
        self.entries.iter().find(|e| e.id() == id)
    }

    /// All entries, in roster order.
    pub fn iter(&self) -> impl Iterator<Item = &E> {
        self.entries.iter()
    }

    /// How many entries the roster holds (>= 1 after load).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Always false after load (an empty roster fails validation).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// A derived, still-immutable subset (e.g. only the `DialOut`
    /// entries for the poller). Not a mutation: the source roster is
    /// untouched, and the subset cannot be extended either.
    #[cfg(feature = "c2")]
    pub(crate) fn select(&self, keep: impl Fn(&E) -> bool) -> Self
    where
        E: Clone,
    {
        Self {
            entries: self.entries.iter().filter(|e| keep(e)).cloned().collect(),
        }
    }
}

/// How roster loading and validation fails. Every variant names its entry
/// where one exists — a fleet operator reads these at startup.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RosterError {
    /// The roster file or a credential file could not be read.
    #[error("io: {what}")]
    Io {
        /// What was read and why it failed.
        what: String,
    },
    /// The TOML did not parse or did not match the entry shape.
    #[error("toml: {what}")]
    Toml {
        /// The parser's message.
        what: String,
    },
    /// The roster has no entries; there is nothing to control.
    #[error("roster is empty")]
    Empty,
    /// The same id appears twice.
    #[error("duplicate entry id {0}")]
    DuplicateId(EntryId),
    /// An entry's endpoint string is empty.
    #[error("entry {0} has an empty endpoint")]
    EmptyEndpoint(EntryId),
    /// A credential source did not resolve; the variable / file / purpose
    /// is named so the refusal is actionable.
    #[error("entry {id}: missing credential ({source_name})")]
    MissingCredential {
        /// The entry whose credential is missing.
        id: EntryId,
        /// The environment variable, file path or derivation purpose.
        source_name: String,
    },
}

/// Serde for [`Endpoint`] as its string form (`unix:<path>`, URL).
mod endpoint_serde {
    use super::*;

    pub fn serialize<S: Serializer>(e: &Endpoint, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&e.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Endpoint, D::Error> {
        let text = String::deserialize(d)?;
        if text.is_empty() {
            // Marker message; Roster::check_endpoints re-points this at
            // the entry (RosterError::EmptyEndpoint).
            return Err(serde::de::Error::custom("empty endpoint"));
        }
        text.parse().map_err(serde::de::Error::custom)
    }
}
