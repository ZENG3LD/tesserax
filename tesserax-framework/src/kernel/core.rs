//! [`Core`]: owns one domain and runs its fixed-phase step.

use tesserax::swc::{
    CommandEnvelope, CommandId, CoreEvent, CoreHealth, EffectEnvelope, EventEnvelope, Generation,
    ObservationEnvelope, Reject, RejectCode, Snapshot,
};

use super::domain::Domain;
use super::tick::{Counter, Ledger, PendingEvent, Tick};

/// Where a core starts: the counters of a kernel restored from storage.
///
/// [`Core::resume_point`] returns the value to persist; a fresh core starts
/// from [`CoreResume::default`] (everything at zero, first operation id 1).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct CoreResume {
    /// Last published snapshot revision.
    pub revision: u64,
    /// Last published event sequence.
    pub through_sequence: u64,
    /// Next operation id to issue (0 is read as 1).
    pub next_operation_id: u64,
    /// Last logical tick.
    pub logical_tick: u64,
}

/// Something the kernel could not do in a step. Never fatal to the core;
/// the step's other output stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, thiserror::Error)]
pub enum CoreError {
    /// The revision or logical tick is spent: the step was blocked.
    #[error("kernel is blocked: {counter} counter exhausted")]
    Blocked {
        /// The spent counter.
        counter: Counter,
    },
    /// No event sequence was left for the `Accepted` / `Rejected` event of a
    /// command; its outcome is only in [`Step::outcomes`].
    #[error("no event sequence left for the outcome of command {command_id}")]
    OutcomeEventLost {
        /// The command whose outcome event was not emitted.
        command_id: CommandId,
    },
}

/// Observations one step dropped instead of applying, by reason.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct ObservationDrops {
    /// The subject is known but at a different generation.
    pub stale_generation: u64,
    /// The subject is not known to the domain.
    pub unknown_subject: u64,
    /// The operation id was never issued by this kernel.
    pub unknown_operation: u64,
    /// The step was blocked (see [`CoreError::Blocked`]).
    pub blocked: u64,
}

impl ObservationDrops {
    /// All drops together.
    pub fn total(&self) -> u64 {
        self.stale_generation + self.unknown_subject + self.unknown_operation + self.blocked
    }
}

impl core::ops::AddAssign for ObservationDrops {
    fn add_assign(&mut self, rhs: Self) {
        self.stale_generation += rhs.stale_generation;
        self.unknown_subject += rhs.unknown_subject;
        self.unknown_operation += rhs.unknown_operation;
        self.blocked += rhs.blocked;
    }
}

/// Cumulative counts over the life of a core.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct CoreStats {
    /// Steps run (blocked ones included).
    pub steps: u64,
    /// Commands accepted.
    pub commands_accepted: u64,
    /// Commands rejected (by the domain or by the kernel).
    pub commands_rejected: u64,
    /// Of `commands_rejected`, those rejected with [`RejectCode::Exhausted`].
    pub commands_exhausted: u64,
    /// Observations applied.
    pub observations_applied: u64,
    /// Observations dropped, by reason.
    pub observations_dropped: ObservationDrops,
    /// Effects issued.
    pub effects: u64,
    /// Events stamped.
    pub events: u64,
}

/// Output of one [`Core::step`].
pub struct Step<D: Domain> {
    /// One outcome per command, in arrival order.
    pub outcomes: Vec<(CommandId, Result<(), Reject>)>,
    /// Effects to run, in request order.
    pub effects: Vec<EffectEnvelope<D::Effect>>,
    /// Events, sequences strictly +1.
    pub events: Vec<EventEnvelope<D::Event>>,
    /// The new snapshot iff the step changed anything;
    /// `through_sequence` is the last of `events` (or the previous sequence).
    pub snapshot: Option<Snapshot<D::State>>,
    /// Observations dropped by this step.
    pub dropped: ObservationDrops,
    /// What the kernel could not do.
    pub errors: Vec<CoreError>,
}

impl<D: Domain> Step<D> {
    fn empty() -> Self {
        Self {
            outcomes: Vec::new(),
            effects: Vec::new(),
            events: Vec::new(),
            snapshot: None,
            dropped: ObservationDrops::default(),
            errors: Vec::new(),
        }
    }
}

impl<D: Domain> core::fmt::Debug for Step<D>
where
    D::Effect: core::fmt::Debug,
    D::Event: core::fmt::Debug,
    D::State: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Step")
            .field("outcomes", &self.outcomes)
            .field("effects", &self.effects)
            .field("events", &self.events)
            .field("snapshot", &self.snapshot)
            .field("dropped", &self.dropped)
            .field("errors", &self.errors)
            .finish()
    }
}

/// Ledger position before one command, restored if it is rejected.
struct CommandMark {
    effects: usize,
    events: usize,
    next_operation_id: u64,
    health: CoreHealth,
    changed: bool,
}

enum Verdict {
    Apply,
    Stale,
    UnknownSubject,
    UnknownOperation,
}

/// The single writer of one [`Domain`].
///
/// Owns the domain, the counters and the step bookkeeping; fields are
/// private and the type is deliberately not `Clone` (a clone would fork the
/// id and sequence authority). Only [`step`](Self::step) mutates.
pub struct Core<D: Domain> {
    domain: D,
    ledger: Ledger<D::Effect, D::Event>,
    revision: u64,
    logical_tick: u64,
    stats: CoreStats,
}

impl<D: Domain> core::fmt::Debug for Core<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Core")
            .field("revision", &self.revision)
            .field("logical_tick", &self.logical_tick)
            .field("through_sequence", &self.ledger.last_sequence)
            .field("next_operation_id", &self.ledger.next_operation_id)
            .field("health", &self.ledger.health)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

fn exhausted_reject() -> Reject {
    Reject::new(
        RejectCode::Exhausted,
        "a kernel counter is exhausted; no further commands are accepted",
    )
}

impl<D: Domain> Core<D> {
    /// A fresh core over `domain`.
    pub fn new(domain: D) -> Self {
        Self::resume(domain, CoreResume::default())
    }

    /// A core over `domain` continuing from `resume` (a restored kernel
    /// keeps its revision, sequence, operation-id and tick counters).
    pub fn resume(domain: D, resume: CoreResume) -> Self {
        let mut health = CoreHealth::default();
        if resume.revision == u64::MAX {
            health.revision_exhausted = true;
        }
        Self {
            domain,
            ledger: Ledger::new(resume.next_operation_id, resume.through_sequence, health),
            revision: resume.revision,
            logical_tick: resume.logical_tick,
            stats: CoreStats::default(),
        }
    }

    /// The counters to persist for [`resume`](Self::resume).
    pub fn resume_point(&self) -> CoreResume {
        CoreResume {
            revision: self.revision,
            through_sequence: self.ledger.last_sequence,
            next_operation_id: self.ledger.next_operation_id,
            logical_tick: self.logical_tick,
        }
    }

    /// The snapshot a port starts from: current revision and sequence, a
    /// fresh projection.
    pub fn initial_snapshot(&self) -> Snapshot<D::State> {
        Snapshot {
            revision: self.revision,
            through_sequence: self.ledger.last_sequence,
            health: self.ledger.health,
            state: self.domain.project(),
        }
    }

    /// Read access to the domain (tests, persistence of the domain itself).
    pub fn domain(&self) -> &D {
        &self.domain
    }

    /// Counter health.
    pub fn health(&self) -> CoreHealth {
        self.ledger.health
    }

    /// Cumulative counts.
    pub fn stats(&self) -> CoreStats {
        self.stats
    }

    /// Gives the domain back.
    pub fn into_domain(self) -> D {
        self.domain
    }

    /// Runs one step over `commands` and `observations` in the fixed phase
    /// order (advance, commands, observations, project, stamp; see the
    /// [module](super)). Never blocks, never fails as a whole.
    pub fn step(
        &mut self,
        commands: impl IntoIterator<Item = CommandEnvelope<D::Command>>,
        observations: impl IntoIterator<Item = ObservationEnvelope<D::Observation>>,
    ) -> Step<D> {
        self.stats.steps += 1;
        let mut step = Step::empty();

        // Phase 1: advance the logical clock.
        let spent = if self.revision == u64::MAX {
            Some(Counter::Revision)
        } else if self.logical_tick == u64::MAX {
            Some(Counter::LogicalTick)
        } else {
            None
        };
        if let Some(counter) = spent {
            return self.blocked(step, counter, commands, observations);
        }
        self.logical_tick += 1;
        let now = self.logical_tick;
        self.domain.advance(&mut Tick::new(&mut self.ledger, now));

        // Phase 2: commands in arrival order.
        for envelope in commands {
            let id = envelope.id;
            let result = self.apply_command(now, envelope);
            let event = match &result {
                Ok(()) => {
                    self.stats.commands_accepted += 1;
                    CoreEvent::Accepted
                }
                Err(reject) => {
                    self.stats.commands_rejected += 1;
                    if reject.code == RejectCode::Exhausted {
                        self.stats.commands_exhausted += 1;
                    }
                    CoreEvent::Rejected(reject.clone())
                }
            };
            let outcome = PendingEvent {
                command_id: Some(id),
                subject: None,
                generation: Generation::default(),
                event,
            };
            if self.ledger.push_event(outcome).is_err() {
                step.errors
                    .push(CoreError::OutcomeEventLost { command_id: id });
            }
            step.outcomes.push((id, result));
        }

        // Phase 3: observations, generation-checked.
        let mut applied = 0u64;
        for observation in observations {
            match self.verdict(&observation) {
                Verdict::Apply => {
                    self.domain
                        .apply_observation(&mut Tick::new(&mut self.ledger, now), observation);
                    applied += 1;
                }
                Verdict::Stale => step.dropped.stale_generation += 1,
                Verdict::UnknownSubject => step.dropped.unknown_subject += 1,
                Verdict::UnknownOperation => step.dropped.unknown_operation += 1,
            }
        }
        self.stats.observations_applied += applied;
        self.stats.observations_dropped += step.dropped;

        // Phase 4: project iff changed.
        let through_sequence = self.ledger.last_sequence + self.ledger.pending_events.len() as u64;
        let changed = self.ledger.changed || applied > 0 || !self.ledger.pending_events.is_empty();
        if changed {
            let revision = self.revision + 1;
            if revision == u64::MAX {
                self.ledger.health.revision_exhausted = true;
            }
            self.revision = revision;
            step.snapshot = Some(Snapshot {
                revision,
                through_sequence,
                health: self.ledger.health,
                state: self.domain.project(),
            });
        }

        // Phase 5: stamp events.
        step.events.reserve(self.ledger.pending_events.len());
        for pending in self.ledger.pending_events.drain(..) {
            self.ledger.last_sequence += 1;
            step.events.push(EventEnvelope {
                sequence: self.ledger.last_sequence,
                command_id: pending.command_id,
                subject: pending.subject,
                generation: pending.generation,
                event: pending.event,
            });
        }
        step.effects = std::mem::take(&mut self.ledger.effects);
        self.ledger.changed = false;
        self.stats.effects += step.effects.len() as u64;
        self.stats.events += step.events.len() as u64;
        step
    }

    /// Phase 2 for one command: kernel gate, then the domain with one
    /// sequence held back for the outcome event.
    fn apply_command(
        &mut self,
        now: u64,
        envelope: CommandEnvelope<D::Command>,
    ) -> Result<(), Reject> {
        if !self.ledger.health.is_healthy() {
            return Err(exhausted_reject());
        }
        let mark = CommandMark {
            effects: self.ledger.effects.len(),
            events: self.ledger.pending_events.len(),
            next_operation_id: self.ledger.next_operation_id,
            health: self.ledger.health,
            changed: self.ledger.changed,
        };
        self.ledger.reserved_sequences = 1;
        let result = self.domain.apply_command(
            &mut Tick::new(&mut self.ledger, now),
            envelope.id,
            envelope.command,
        );
        self.ledger.reserved_sequences = 0;
        if result.is_err() {
            self.roll_back(mark);
        }
        result
    }

    /// Undoes what a rejected command recorded in the ledger: its effects
    /// and events are discarded, the operation ids it drew are handed back
    /// (ids are dense and none of them left the kernel, so an observation
    /// naming one is dropped as an unknown operation until the id is issued
    /// again), and `changed` / the counter flags return to their values
    /// before the command (flags are then recomputed from the counters).
    fn roll_back(&mut self, mark: CommandMark) {
        self.ledger.effects.truncate(mark.effects);
        self.ledger.pending_events.truncate(mark.events);
        self.ledger.next_operation_id = mark.next_operation_id;
        self.ledger.health = mark.health;
        self.ledger.changed = mark.changed;
        self.ledger.refresh_flags();
    }

    fn verdict(&self, observation: &ObservationEnvelope<D::Observation>) -> Verdict {
        if let Some(operation_id) = observation.operation_id
            && (operation_id.0 == 0 || operation_id.0 >= self.ledger.next_operation_id)
        {
            return Verdict::UnknownOperation;
        }
        match observation.subject {
            None => Verdict::Apply,
            Some(subject) => match self.domain.generation_of(subject) {
                None => Verdict::UnknownSubject,
                Some(current) if current == observation.generation => Verdict::Apply,
                Some(_) => Verdict::Stale,
            },
        }
    }

    fn blocked(
        &mut self,
        mut step: Step<D>,
        counter: Counter,
        commands: impl IntoIterator<Item = CommandEnvelope<D::Command>>,
        observations: impl IntoIterator<Item = ObservationEnvelope<D::Observation>>,
    ) -> Step<D> {
        for envelope in commands {
            self.stats.commands_rejected += 1;
            self.stats.commands_exhausted += 1;
            step.outcomes.push((envelope.id, Err(exhausted_reject())));
        }
        step.dropped.blocked = observations.into_iter().count() as u64;
        self.stats.observations_dropped += step.dropped;
        step.errors.push(CoreError::Blocked { counter });
        step
    }
}

#[cfg(test)]
mod tests {
    use tesserax::swc::{CommandEnvelope, CommandId, Generation, ObservationEnvelope, Subject};

    use super::*;

    /// Command `true` marks the state changed and draws an operation id,
    /// then refuses; `false` does nothing and is accepted.
    struct Toucher;

    impl Domain for Toucher {
        type Command = bool;
        type Effect = ();
        type Observation = ();
        type Event = ();
        type State = ();

        fn apply_command(
            &mut self,
            tick: &mut Tick<'_, Self>,
            _: CommandId,
            refuse: bool,
        ) -> Result<(), Reject> {
            if refuse {
                tick.mark_changed();
                tick.effect(None, Generation::default(), ())?;
                return Err(Reject::new(RejectCode::Invalid, "refused"));
            }
            Ok(())
        }

        fn generation_of(&self, _: Subject) -> Option<Generation> {
            None
        }

        fn apply_observation(&mut self, _: &mut Tick<'_, Self>, _: ObservationEnvelope<()>) {}

        fn project(&self) {}
    }

    fn envelope(id: u64, refuse: bool) -> CommandEnvelope<bool> {
        CommandEnvelope {
            id: CommandId(id),
            command: refuse,
        }
    }

    #[test]
    fn a_rejected_command_restores_changed_and_operation_ids() {
        let mut core = Core::new(Toucher);
        assert!(core.apply_command(1, envelope(1, true)).is_err());
        assert!(
            !core.ledger.changed,
            "mark_changed of a rejected command leaked"
        );
        assert_eq!(core.ledger.next_operation_id, 1);
        assert!(core.ledger.effects.is_empty());

        // A change recorded before the command survives its rejection.
        core.ledger.changed = true;
        assert!(core.apply_command(1, envelope(2, true)).is_err());
        assert!(core.ledger.changed);
        assert!(core.apply_command(1, envelope(3, false)).is_ok());
        assert!(core.ledger.changed);
    }

    #[test]
    fn the_last_operation_id_drawn_by_a_rejected_command_stays_available() {
        let mut core = Core::resume(
            Toucher,
            CoreResume {
                next_operation_id: u64::MAX - 1,
                ..CoreResume::default()
            },
        );
        assert!(core.apply_command(1, envelope(1, true)).is_err());
        assert_eq!(core.ledger.next_operation_id, u64::MAX - 1);
        assert!(core.health().is_healthy());
    }
}
