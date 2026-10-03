//! Pluggable credential sources: [`AuthLayer`] and [`AuthChain`].
//!
//! The key ring is built into the gate. An `AuthLayer` identifies a caller
//! some other way (a session cookie, a signed header) and hands back the
//! caller's grants; the gate then authorizes exactly as for a key.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::request::Parts;
use tesserax::KeyId;

use crate::key::Grant;

/// Boxed `Send` future (no `async-trait`).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What one layer concluded about a request.
#[derive(Clone, Debug)]
pub enum AuthOutcome {
    /// No opinion.
    Abstain,
    /// Identified the caller.
    Grant {
        /// Caller identity (appears in audit records).
        key_id: KeyId,
        /// What the caller may do.
        grants: Vec<Grant>,
    },
    /// The request must be refused (answered as `unauthorized`).
    Reject {
        /// Logged, never sent to the client.
        reason: String,
    },
}

/// One credential source. Sees headers, URI and extensions, not the body.
pub trait AuthLayer: Send + Sync + 'static {
    /// Name for logs.
    fn name(&self) -> &str;

    /// Examines the request.
    fn resolve<'a>(&'a self, parts: &'a Parts) -> BoxFuture<'a, AuthOutcome>;
}

/// How an [`AuthChain`] combines layers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthChainMode {
    /// Consult every layer. The first identity found wins; grants other
    /// layers return for the same `key_id` are added to it.
    #[default]
    Aggregating,
    /// Stop at the first `Grant` (register cheap layers first).
    StrictOrder,
}

/// Ordered layers. A `Reject` from any layer ends the chain.
#[derive(Clone, Default)]
pub struct AuthChain {
    layers: Vec<Arc<dyn AuthLayer>>,
    mode: AuthChainMode,
}

impl AuthChain {
    /// Empty chain (always abstains).
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a layer.
    pub fn layer(mut self, layer: impl AuthLayer) -> Self {
        self.layers.push(Arc::new(layer));
        self
    }

    /// Sets the mode.
    pub fn with_mode(mut self, mode: AuthChainMode) -> Self {
        self.mode = mode;
        self
    }

    /// True if no layer is registered.
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Layer names in order.
    pub fn layer_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.layers.iter().map(|l| l.name())
    }

    /// Runs the layers.
    pub async fn resolve(&self, parts: &Parts) -> AuthOutcome {
        let mut found: Option<(KeyId, Vec<Grant>)> = None;
        for layer in &self.layers {
            match layer.resolve(parts).await {
                AuthOutcome::Abstain => {}
                AuthOutcome::Reject { reason } => {
                    tracing::debug!(layer = layer.name(), %reason, "auth layer rejected");
                    return AuthOutcome::Reject { reason };
                }
                AuthOutcome::Grant { key_id: id, grants } => match &mut found {
                    None => {
                        found = Some((id, grants));
                        if self.mode == AuthChainMode::StrictOrder {
                            break;
                        }
                    }
                    Some((first, all)) if first.as_str() == id.as_str() => all.extend(grants),
                    Some(_) => {}
                },
            }
        }
        match found {
            Some((key_id, grants)) => AuthOutcome::Grant { key_id, grants },
            None => AuthOutcome::Abstain,
        }
    }
}

impl std::fmt::Debug for AuthChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthChain")
            .field("layers", &self.layer_names().collect::<Vec<_>>())
            .field("mode", &self.mode)
            .finish()
    }
}
