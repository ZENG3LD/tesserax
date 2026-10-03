//! The [`Domain`] trait: the business logic a kernel hosts.

use tesserax::swc::{CommandId, Generation, ObservationEnvelope, Reject, Subject};

use super::tick::Tick;

/// One coherent stateful domain: its payload types and its pure,
/// synchronous reducers.
///
/// The domain owns its state; [`Core`](super::Core) owns the domain and
/// calls these methods only from [`Core::step`](super::Core::step), in the
/// fixed phase order documented on the [module](super). None of them may
/// block, sleep or perform IO: work that needs the outside world is
/// requested with [`Tick::effect`] and its result comes back later through
/// [`apply_observation`](Self::apply_observation).
///
/// ```
/// use tesserax::swc::{CommandId, Generation, ObservationEnvelope, Reject, RejectCode, Subject};
/// use tesserax_framework::{Core, Domain, Tick};
///
/// #[derive(Default)]
/// struct Counter { value: u64 }
///
/// impl Domain for Counter {
///     type Command = u64;          // add this much
///     type Effect = ();
///     type Observation = ();
///     type Event = u64;            // the new value
///     type State = u64;
///
///     fn apply_command(&mut self, tick: &mut Tick<'_, Self>, id: CommandId, add: u64)
///         -> Result<(), Reject>
///     {
///         let next = self.value.checked_add(add)
///             .ok_or_else(|| Reject::new(RejectCode::Invalid, "overflow"))?;
///         self.value = next;
///         tick.emit(Some(id), None, Generation::default(), next)?;
///         Ok(())
///     }
///     fn generation_of(&self, _: Subject) -> Option<Generation> { None }
///     fn apply_observation(&mut self, _: &mut Tick<'_, Self>, _: ObservationEnvelope<()>) {}
///     fn project(&self) -> u64 { self.value }
/// }
///
/// let mut core = Core::new(Counter::default());
/// let step = core.step(
///     [tesserax::swc::CommandEnvelope { id: CommandId(1), command: 5 }],
///     [],
/// );
/// assert!(step.outcomes[0].1.is_ok());
/// assert_eq!(step.snapshot.as_ref().map(|s| s.state), Some(5));
/// ```
pub trait Domain: Send + 'static {
    /// Intent in.
    type Command: Send + 'static;
    /// Work the domain asks a shell to perform.
    type Effect: Send + 'static;
    /// Result of an effect, or an unsolicited fact from a shell.
    type Observation: Send + 'static;
    /// Domain event out (cloned once per subscriber by the port edge).
    type Event: Clone + Send + 'static;
    /// What [`project`](Self::project) publishes.
    type State: Send + Sync + 'static;

    /// Phase 1: the logical clock moved to [`Tick::now`]. Time-driven logic
    /// (timeouts counted in ticks, retries) lives here. A state change that
    /// emits no event must call [`Tick::mark_changed`]. The default does
    /// nothing.
    fn advance(&mut self, tick: &mut Tick<'_, Self>) {
        let _ = tick;
    }

    /// Phase 2: apply one command.
    ///
    /// Validate before mutating: on `Err` the kernel discards the effects
    /// and events this call produced, hands back the operation ids it drew
    /// (they are issued again later, so a rejected command must not keep
    /// one), forgets a [`Tick::mark_changed`] it made, and publishes
    /// `Rejected`; it cannot undo a mutation of `self`. Counter exhaustion surfaces as
    /// [`Exhausted`](super::Exhausted), which converts into a
    /// [`Reject`] with `?`.
    fn apply_command(
        &mut self,
        tick: &mut Tick<'_, Self>,
        id: CommandId,
        command: Self::Command,
    ) -> Result<(), Reject>;

    /// Current generation of `subject`, or `None` when the domain does not
    /// know it. The kernel drops observations whose subject is unknown or
    /// whose generation differs, before [`apply_observation`](Self::apply_observation).
    fn generation_of(&self, subject: Subject) -> Option<Generation>;

    /// Phase 3: apply one observation that passed the kernel's checks (its
    /// operation id was issued by this kernel, and its subject, if any, is
    /// at the observation's generation). Applying an observation counts as a
    /// change.
    fn apply_observation(
        &mut self,
        tick: &mut Tick<'_, Self>,
        observation: ObservationEnvelope<Self::Observation>,
    );

    /// Phase 4: the state to publish. Called once per changed step, and once
    /// by [`Core::initial_snapshot`](super::Core::initial_snapshot).
    fn project(&self) -> Self::State;
}
