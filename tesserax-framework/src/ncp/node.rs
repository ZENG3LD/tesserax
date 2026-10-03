//! The node tier: an edge process that wraps its local services, dials
//! the tier above on `AcceptIn` links, and serves its own API through the
//! framework shells (`http_shell` / `local_shell`, B8b) over its own
//! `Domain` — the node's kernel is the product's, this module only
//! assembles what the node wraps.
//!
//! `node-os` adds [`os`]: spawn / kill / supervise of the services as OS
//! processes. That is the ONLY place in `ncp` where OS-process APIs may
//! appear (checked by `tests/ncp_gates.rs`).

#[cfg(feature = "node-os")]
pub mod os;

use std::collections::BTreeMap;
use std::sync::Arc;

use tesserax_transport::Endpoint;
use zeroize::Zeroizing;

use super::link::{AttachError, LinkStream};
use super::roster::EntryId;

/// One local service the node wraps: a name, the endpoint it serves on,
/// and — under `node-os` — enough to run it as a process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeService {
    /// Service name (the node's local vocabulary).
    pub name: String,
    /// Where the service serves (usually an owner-only local socket).
    pub endpoint: Endpoint,
    /// Free-form labels.
    pub labels: BTreeMap<String, String>,
}

/// The node's services, by name. Immutable after assembly: the set a node
/// wraps is deployment, not traffic.
#[derive(Clone, Debug, Default)]
pub struct ServiceRoster {
    services: Arc<BTreeMap<String, NodeService>>,
}

impl ServiceRoster {
    /// An empty roster.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a service (builder style; a name collision replaces — the
    /// last word of the deployment wins, and it is one word).
    pub fn service(mut self, service: NodeService) -> Self {
        Arc::make_mut(&mut self.services).insert(service.name.clone(), service);
        self
    }

    /// The service called `name`.
    pub fn get(&self, name: &str) -> Option<&NodeService> {
        self.services.get(name)
    }

    /// All services, by name.
    pub fn iter(&self) -> impl Iterator<Item = &NodeService> {
        self.services.values()
    }

    /// How many services the node wraps.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Whether the node wraps nothing.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }
}

/// The node, assembled: the services it wraps. Serving happens through
/// the framework shells over the node's own `Domain` — see the module
/// docs; this builder deliberately does not re-implement them.
#[derive(Clone, Debug, Default)]
pub struct Node {
    services: ServiceRoster,
}

impl Node {
    /// The services this node wraps.
    pub fn services(&self) -> &ServiceRoster {
        &self.services
    }
}

/// Builds a [`Node`]: declares the wrapped services. A node has no
/// roster of a tier below — it IS the bottom.
#[derive(Debug, Default)]
pub struct NodeBuilder {
    services: ServiceRoster,
}

impl NodeBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares one wrapped service.
    pub fn service(mut self, service: NodeService) -> Self {
        self.services = self.services.service(service);
        self
    }

    /// The whole [`ServiceRoster`] at once.
    pub fn services(mut self, roster: ServiceRoster) -> Self {
        self.services = roster;
        self
    }

    /// Assembles the node.
    pub fn build(self) -> Node {
        Node {
            services: self.services,
        }
    }
}

/// A proved attach link from the node's side: the byte stream plus the
/// id the acceptor admitted us as.
#[derive(Debug)]
pub struct AttachLink {
    /// The roster id the acceptor admitted.
    pub id: EntryId,
    /// The proved stream (proof ran before any application byte).
    pub stream: LinkStream,
}

/// Dials the tier above on an `AcceptIn` link: connects, names this
/// node's roster id, checks the acceptor's proof and answers with its
/// own (mutual `link_proof`; nothing crosses before the acceptor's proof
/// matched). This is the node's ONLY upward door, and it is opened by
/// the node — control still flows the other way (NCP §3 vs §4).
pub async fn dial_attach(
    endpoint: &Endpoint,
    id: &EntryId,
    token: Zeroizing<String>,
    domain: impl AsRef<[u8]>,
    binding: impl AsRef<[u8]>,
) -> Result<AttachLink, AttachError> {
    let stream = super::link::dial_attach_stream(
        endpoint,
        id,
        token.as_bytes(),
        domain.as_ref(),
        binding.as_ref(),
    )
    .await?;
    Ok(AttachLink {
        id: id.clone(),
        stream,
    })
}
