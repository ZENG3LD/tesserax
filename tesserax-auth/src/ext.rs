//! [`AuthExt`]: installs an [`AuthGate`] on a `tesserax::ServerBuilder`.

use tesserax::{LayerStage, ServerBuilder};

use crate::gate::AuthGate;

/// Adds authentication to a server builder.
pub trait AuthExt: Sized {
    /// Installs `gate` at `LayerStage::TierGate` (every gated route, i.e.
    /// every table route except `/health`, `/livez`, `/readyz`) and, when
    /// the gate has a ban ledger, the ban check at `LayerStage::PeerGuard`.
    ///
    /// The gate reads the final route table from the request's
    /// `Extension<Arc<RouteTable>>` at request time, so routes added by
    /// plugins registered before or after this call are all enforced. With
    /// `without_auto_extensions()` the table is missing and every gated
    /// request is refused with 500.
    fn with_auth(self, gate: AuthGate) -> Self;
}

impl AuthExt for ServerBuilder {
    fn with_auth(self, gate: AuthGate) -> Self {
        let with_gate = self.layer_at(LayerStage::TierGate, gate.tier_gate_layer());
        if gate.ban().is_some() {
            with_gate.layer_at(LayerStage::PeerGuard, gate.peer_guard_layer())
        } else {
            with_gate
        }
    }
}
