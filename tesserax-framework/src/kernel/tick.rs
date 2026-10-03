//! [`Tick`]: what a domain reducer may do during one step.

use tesserax::swc::{
    CommandId, CoreEvent, CoreHealth, EffectEnvelope, Generation, OperationId, Reject, RejectCode,
    Subject,
};

use super::domain::Domain;

/// A kernel counter that can run out.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Counter {
    /// Operation ids handed to effects.
    OperationId,
    /// Event sequences.
    EventSequence,
    /// Snapshot revisions.
    Revision,
    /// The logical tick.
    LogicalTick,
}

impl core::fmt::Display for Counter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::OperationId => "operation id",
            Self::EventSequence => "event sequence",
            Self::Revision => "snapshot revision",
            Self::LogicalTick => "logical tick",
        })
    }
}

/// A counter is spent: the effect or event was not recorded. The matching
/// [`CoreHealth`] flag is set and later commands are rejected with
/// [`RejectCode::Exhausted`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, thiserror::Error)]
#[error("kernel {counter} counter is exhausted")]
pub struct Exhausted {
    /// Which counter.
    pub counter: Counter,
}

impl From<Exhausted> for Reject {
    fn from(e: Exhausted) -> Self {
        Reject::new(RejectCode::Exhausted, e.to_string())
    }
}

/// An event waiting for its sequence (phase 5).
pub(crate) struct PendingEvent<V> {
    pub(crate) command_id: Option<CommandId>,
    pub(crate) subject: Option<Subject>,
    pub(crate) generation: Generation,
    pub(crate) event: CoreEvent<V>,
}

/// The kernel's bookkeeping of one step, lent to the domain through
/// [`Tick`]. Kept apart from the domain so both can be borrowed at once.
pub(crate) struct Ledger<E, V> {
    /// Next operation id to hand out; `u64::MAX` means spent.
    pub(crate) next_operation_id: u64,
    /// Last sequence already stamped.
    pub(crate) last_sequence: u64,
    /// Sequences held back for the outcome event of the command in flight.
    pub(crate) reserved_sequences: u64,
    pub(crate) pending_events: Vec<PendingEvent<V>>,
    pub(crate) effects: Vec<EffectEnvelope<E>>,
    pub(crate) health: CoreHealth,
    pub(crate) changed: bool,
}

impl<E, V> Ledger<E, V> {
    pub(crate) fn new(next_operation_id: u64, last_sequence: u64, health: CoreHealth) -> Self {
        let mut ledger = Self {
            next_operation_id: next_operation_id.max(1),
            last_sequence,
            reserved_sequences: 0,
            pending_events: Vec::new(),
            effects: Vec::new(),
            health,
            changed: false,
        };
        ledger.refresh_flags();
        ledger
    }

    /// Sequences still available for events of this and later steps.
    pub(crate) fn sequence_room(&self) -> u64 {
        (u64::MAX - self.last_sequence).saturating_sub(self.pending_events.len() as u64)
    }

    /// Sets the flags of counters that have nothing left.
    pub(crate) fn refresh_flags(&mut self) {
        if self.next_operation_id == u64::MAX {
            self.health.operation_id_exhausted = true;
        }
        if self.sequence_room() == 0 {
            self.health.event_sequence_exhausted = true;
        }
    }

    fn allocate_operation(&mut self) -> Result<OperationId, Exhausted> {
        if self.next_operation_id == u64::MAX {
            self.health.operation_id_exhausted = true;
            return Err(Exhausted {
                counter: Counter::OperationId,
            });
        }
        let id = OperationId(self.next_operation_id);
        self.next_operation_id += 1;
        self.refresh_flags();
        Ok(id)
    }

    /// Queues an event, keeping `reserved_sequences` untouched.
    pub(crate) fn push_event(&mut self, event: PendingEvent<V>) -> Result<(), Exhausted> {
        if self.sequence_room() <= self.reserved_sequences {
            self.health.event_sequence_exhausted = true;
            return Err(Exhausted {
                counter: Counter::EventSequence,
            });
        }
        self.pending_events.push(event);
        self.refresh_flags();
        Ok(())
    }
}

/// The domain's view of the step in progress: the logical clock, and the
/// only way to request effects and emit events.
///
/// Borrowed for one reducer call; nothing it records escapes the step except
/// through [`Step`](super::Step).
pub struct Tick<'a, D: Domain + ?Sized> {
    ledger: &'a mut Ledger<D::Effect, D::Event>,
    now: u64,
}

impl<'a, D: Domain + ?Sized> Tick<'a, D> {
    pub(crate) fn new(ledger: &'a mut Ledger<D::Effect, D::Event>, now: u64) -> Self {
        Self { ledger, now }
    }

    /// The logical tick of this step (1 for the first step of a fresh core).
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Requests `effect` about `subject` at `generation`; returns the
    /// operation id its observation will carry. The effect leaves the kernel
    /// in [`Step::effects`](super::Step::effects), in request order.
    pub fn effect(
        &mut self,
        subject: Option<Subject>,
        generation: Generation,
        effect: D::Effect,
    ) -> Result<OperationId, Exhausted> {
        let operation_id = self.ledger.allocate_operation()?;
        self.ledger.effects.push(EffectEnvelope {
            operation_id,
            subject,
            generation,
            effect,
        });
        Ok(operation_id)
    }

    /// Emits a domain event, correlated to `command_id` when it answers a
    /// command. Its sequence is stamped in phase 5.
    pub fn emit(
        &mut self,
        command_id: Option<CommandId>,
        subject: Option<Subject>,
        generation: Generation,
        event: D::Event,
    ) -> Result<(), Exhausted> {
        self.ledger.push_event(PendingEvent {
            command_id,
            subject,
            generation,
            event: CoreEvent::Domain(event),
        })
    }

    /// Records that state changed without an event, so the step projects
    /// and publishes a new revision.
    pub fn mark_changed(&mut self) {
        self.ledger.changed = true;
    }

    /// Counter health as of now.
    pub fn health(&self) -> CoreHealth {
        self.ledger.health
    }
}

impl<D: Domain + ?Sized> core::fmt::Debug for Tick<'_, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tick")
            .field("now", &self.now)
            .field("pending_effects", &self.ledger.effects.len())
            .field("pending_events", &self.ledger.pending_events.len())
            .finish()
    }
}
