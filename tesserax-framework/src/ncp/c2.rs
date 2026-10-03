//! The middle tier: routes, mirrors, resyncs, persists — and never
//! touches an OS process (that is the node tier's `node-os` half).
//!
//! A binary of this tier is built with `--features c2` and nothing above:
//! there is no `.above`, no method here that takes an endpoint to report
//! to, and no type of the tier above in scope. The rule is mechanical —
//! absence, not policy (NCP §11c) — and the `compile_fail` doctest on
//! [`C2Builder`] pins it.

use std::collections::BTreeMap;
use std::sync::Arc;

use tesserax::audit::AuditSink;
use tesserax::tier::Scope;
use tesserax_transport::Endpoint;
use thiserror::Error;

use super::NcpError;
use super::link::{AttachListener, DownLink};
use super::oracle::{FleetCache, Oracle, PollConfig};
use super::roster::{EntryId, EnvLookup, LinkSpec, Reach, Roster, RosterError};

/// A route template for the passthrough allow-list: literal segments and
/// single-segment `:parameters`, matched exactly (segment count and
/// literals must agree). `/status/:id` covers `/status/a`, not
/// `/status/a/b` and not `/statusx`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathTemplate(String);

impl PathTemplate {
    /// Validates that `template` starts with `/`.
    pub fn new(template: impl Into<String>) -> Result<Self, PassthroughError> {
        let t = template.into();
        if !t.starts_with('/') {
            return Err(PassthroughError::BadTemplate(t));
        }
        Ok(Self(t))
    }

    /// The template text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Exact template match: same segment count, literals equal,
    /// `:parameter` segments take any single non-empty segment.
    pub fn matches(&self, path: &str) -> bool {
        let want: Vec<&str> = self.0.split('/').collect();
        let got: Vec<&str> = path.split('/').collect();
        if want.len() != got.len() {
            return false;
        }
        want.iter().zip(got.iter()).all(|(w, g)| {
            if let Some(param) = w.strip_prefix(':') {
                !param.is_empty() && !g.is_empty()
            } else {
                w == g
            }
        })
    }
}

/// How a passthrough policy fails to build.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PassthroughError {
    /// A template does not start with `/`.
    #[error("bad path template {0:?}: must start with '/'")]
    BadTemplate(String),
}

/// One allow-list rule: this method on this template requires this scope.
/// The match is exact — the closed-by-default idiom of the operator box.
#[derive(Clone, Debug)]
pub struct AllowRule {
    /// The HTTP method (upper-case, e.g. `"GET"`).
    pub method: String,
    /// The route template.
    pub path: PathTemplate,
    /// The scope the caller's principal must hold.
    pub scope: Scope,
}

/// What an operator request may have forwarded to the tier below:
/// **closed by default**, every forwarded call matches one allow rule and
/// carries that rule's scope requirement (defect N2 of the moved code —
/// "forward any tail path with the operator token" — is unrepresentable
/// here).
#[derive(Clone, Debug, Default)]
pub struct PassthroughPolicy {
    /// The allow list; an empty list forwards nothing.
    pub allow: Vec<AllowRule>,
}

impl PassthroughPolicy {
    /// The scope a `(method, path)` call needs, if the policy forwards it
    /// at all. `None` = refused: closed by default.
    pub fn allows(&self, method: &str, path: &str) -> Option<&Scope> {
        let method = method.to_ascii_uppercase();
        self.allow
            .iter()
            .find(|r| r.method == method && r.path.matches(path))
            .map(|r| &r.scope)
    }
}

/// The middle tier, assembled: immutable roster, one down link per
/// `DialOut` entry, attach listeners for the `AcceptIn` ones, the fleet
/// oracle and the passthrough policy.
pub struct C2<R> {
    roster: Roster<LinkSpec>,
    links: BTreeMap<EntryId, DownLink>,
    attach: Vec<AttachListener>,
    fleet: FleetCache<R>,
    passthrough: PassthroughPolicy,
    audit: Option<Arc<dyn AuditSink>>,
}

impl<R> C2<R> {
    /// The roster this tier controls (immutable after load, NCP §5).
    pub fn roster(&self) -> &Roster<LinkSpec> {
        &self.roster
    }

    /// The down link to one entry, if it is on the roster and dialled by
    /// this tier.
    pub fn link(&self, id: &EntryId) -> Option<&DownLink> {
        self.links.get(id)
    }

    /// All down links of this tier.
    pub fn links(&self) -> impl Iterator<Item = &DownLink> {
        self.links.values()
    }

    /// The attach listeners (one per bound `AcceptIn` endpoint).
    pub fn attach_listeners(&mut self) -> &mut [AttachListener] {
        &mut self.attach
    }

    /// The fleet view the poller publishes.
    pub fn fleet(&self) -> &FleetCache<R> {
        &self.fleet
    }

    /// The passthrough allow-list.
    pub fn passthrough(&self) -> &PassthroughPolicy {
        &self.passthrough
    }

    /// The audit sink, if one was installed.
    pub fn audit(&self) -> Option<&Arc<dyn AuditSink>> {
        self.audit.as_ref()
    }
}

/// Builds a [`C2`]. Every method addresses the tier BELOW or this tier's
/// own wiring; nothing here can point up.
///
/// The mechanical proof that this tier has no client for the tier above
/// (NCP §11c): the following does not compile —
///
/// ```compile_fail
/// use tesserax_framework::ncp::c2::C2Builder;
/// // No such method exists, and no feature adds it:
/// let _ = C2Builder::new().serve_the_tier_above("http://10.0.0.1:9000");
/// ```
pub struct C2Builder {
    roster: Option<Roster<LinkSpec>>,
    passthrough: PassthroughPolicy,
    audit: Option<Arc<dyn AuditSink>>,
    env: Option<EnvLookup>,
    attach_domain: Vec<u8>,
    attach_binding: Vec<u8>,
}

impl std::fmt::Debug for C2Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("C2Builder").finish_non_exhaustive()
    }
}

impl Default for C2Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl C2Builder {
    /// An empty builder: no roster yet, closed passthrough.
    pub fn new() -> Self {
        Self {
            roster: None,
            passthrough: PassthroughPolicy::default(),
            audit: None,
            env: None,
            attach_domain: Vec::new(),
            attach_binding: Vec::new(),
        }
    }

    /// The tier below: a loaded, validated roster. The ONLY direction a
    /// builder of this tier can be pointed.
    pub fn below(mut self, roster: Roster<LinkSpec>) -> Self {
        self.roster = Some(roster);
        self
    }

    /// The passthrough allow-list (closed by default).
    pub fn passthrough(mut self, policy: PassthroughPolicy) -> Self {
        self.passthrough = policy;
        self
    }

    /// The audit sink forwarded calls record into.
    pub fn audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    /// Injects the environment for credential resolution (tests; default
    /// is the process environment).
    pub fn env(mut self, env: EnvLookup) -> Self {
        self.env = Some(env);
        self
    }

    /// The proof context (domain + binding) of the attach handshake —
    /// constants of the product's protocol.
    pub fn attach_context(
        mut self,
        domain: impl Into<Vec<u8>>,
        binding: impl Into<Vec<u8>>,
    ) -> Self {
        self.attach_domain = domain.into();
        self.attach_binding = binding.into();
        self
    }

    /// The oracle that enriches the fleet view, and its poll cadence.
    /// Types the builder: from here on it builds a `C2<O::Report>`.
    pub fn oracle<O: Oracle>(self, oracle: O, cfg: PollConfig) -> C2WithOracle<O> {
        C2WithOracle {
            base: self,
            oracle,
            poll: cfg,
        }
    }
}

/// A [`C2Builder`] whose oracle is installed; the only state that can be
/// built — a middle tier without its fleet view is half a tier.
pub struct C2WithOracle<O: Oracle> {
    base: C2Builder,
    oracle: O,
    poll: PollConfig,
}

impl<O: Oracle> C2WithOracle<O> {
    /// The passthrough allow-list (closed by default).
    pub fn passthrough(mut self, policy: PassthroughPolicy) -> Self {
        self.base.passthrough = policy;
        self
    }

    /// The audit sink forwarded calls record into.
    pub fn audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.base.audit = Some(sink);
        self
    }

    /// Assembles the tier: builds one [`DownLink`] per `DialOut` entry
    /// and binds one [`AttachListener`] per distinct `AcceptIn` endpoint,
    /// then starts the fleet poller. Must run inside a tokio runtime.
    pub async fn build(self) -> Result<C2<O::Report>, NcpError> {
        let roster = self.base.roster.ok_or(RosterError::Empty)?;
        let env = self
            .base
            .env
            .unwrap_or_else(|| Arc::new(|name| std::env::var(name).ok()));

        let mut links = BTreeMap::new();
        let mut attach_endpoints: Vec<Endpoint> = Vec::new();
        for entry in roster.iter() {
            match entry.reach {
                Reach::DialOut => {
                    let link = DownLink::resolve(entry, env.as_ref())?;
                    links.insert(entry.id.clone(), link);
                }
                Reach::AcceptIn => {
                    if !attach_endpoints.contains(&entry.endpoint) {
                        attach_endpoints.push(entry.endpoint.clone());
                    }
                }
            }
        }
        let mut attach = Vec::with_capacity(attach_endpoints.len());
        for endpoint in attach_endpoints {
            let listener = AttachListener::bind(
                &endpoint,
                &roster,
                env.as_ref(),
                self.base.attach_domain.clone(),
                self.base.attach_binding.clone(),
            )
            .await?;
            attach.push(listener);
        }

        // The poller pulls over DialOut links. An AcceptIn entry's health
        // rides the attach link the entry itself opened (§5.4: the link
        // this tier already holds) — there is nothing to dial.
        let poll_roster = roster.select(|e| e.reach == Reach::DialOut);
        let fleet = super::oracle::spawn_poller_with(poll_roster, self.oracle, self.poll, env);
        Ok(C2 {
            roster,
            links,
            attach,
            fleet,
            passthrough: self.base.passthrough,
            audit: self.base.audit,
        })
    }
}
