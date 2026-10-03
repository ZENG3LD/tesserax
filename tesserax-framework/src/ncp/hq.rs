//! The top tier: the only module in `ncp` that may name the middle tier's
//! links as "below". It always dials — [`DialEntry`] has no `reach`
//! field, so "the middle tier calls up" is unrepresentable (NCP §4,
//! table row 1: impossibility by absence, not by policy).

use std::collections::BTreeMap;
use std::sync::Arc;

use super::NcpError;
use super::link::DownLink;
use super::oracle::{FleetCache, Oracle, PollConfig, spawn_poller};
use super::roster::{DialEntry, EntryId, EnvLookup, Roster, RosterError};

/// The top tier, assembled: immutable roster of dial entries and one
/// down link per entry, plus the fleet oracle.
pub struct Hq<R> {
    roster: Roster<DialEntry>,
    links: BTreeMap<EntryId, DownLink>,
    fleet: FleetCache<R>,
}

impl<R> Hq<R> {
    /// The roster this tier controls (immutable after load, NCP §5).
    pub fn roster(&self) -> &Roster<DialEntry> {
        &self.roster
    }

    /// The down link to one middle-tier entry.
    pub fn link(&self, id: &EntryId) -> Option<&DownLink> {
        self.links.get(id)
    }

    /// All down links of this tier.
    pub fn links(&self) -> impl Iterator<Item = &DownLink> {
        self.links.values()
    }

    /// The fleet view the poller publishes.
    pub fn fleet(&self) -> &FleetCache<R> {
        &self.fleet
    }
}

/// Builds an [`Hq`]: `.below(Roster<DialEntry>)`, `.oracle(..)`, build.
/// There is nothing else to point at — the top tier has no "above".
pub struct HqBuilder {
    roster: Option<Roster<DialEntry>>,
    env: Option<EnvLookup>,
}

impl std::fmt::Debug for HqBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HqBuilder").finish_non_exhaustive()
    }
}

impl Default for HqBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HqBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self {
            roster: None,
            env: None,
        }
    }

    /// The middle tier below, as dial entries.
    pub fn below(mut self, roster: Roster<DialEntry>) -> Self {
        self.roster = Some(roster);
        self
    }

    /// Injects the environment for credential resolution (tests; default
    /// is the process environment).
    pub fn env(mut self, env: EnvLookup) -> Self {
        self.env = Some(env);
        self
    }

    /// The oracle that enriches the fleet view, and its poll cadence.
    pub fn oracle<O: Oracle>(self, oracle: O, cfg: PollConfig) -> HqWithOracle<O> {
        HqWithOracle {
            base: self,
            oracle,
            poll: cfg,
        }
    }
}

/// An [`HqBuilder`] whose oracle is installed; the only state that can
/// be built.
pub struct HqWithOracle<O: Oracle> {
    base: HqBuilder,
    oracle: O,
    poll: PollConfig,
}

impl<O: Oracle> HqWithOracle<O> {
    /// Assembles the tier: one [`DownLink`] per entry (every entry dials
    /// out — no other reach exists here), then starts the fleet poller.
    /// Must run inside a tokio runtime.
    pub async fn build(self) -> Result<Hq<O::Report>, NcpError> {
        let roster = self.base.roster.ok_or(RosterError::Empty)?;
        let env = self
            .base
            .env
            .unwrap_or_else(|| Arc::new(|name| std::env::var(name).ok()));
        let mut links = BTreeMap::new();
        for entry in roster.iter() {
            let link = DownLink::resolve(entry, env.as_ref())?;
            links.insert(entry.id.clone(), link);
        }
        let fleet = spawn_poller(roster.clone(), self.oracle, self.poll);
        Ok(Hq {
            roster,
            links,
            fleet,
        })
    }
}
