//! Pure data of the contract: ids, envelopes, events, snapshot.
//!
//! Payload types (`C`, `E`, `O`, `V`, `S`) are chosen by the domain; the
//! envelopes add only the correlation data every domain needs.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
        pub struct $name(pub u64);

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

id_newtype!(
    /// Identity of one command. Assigned by [`Port::dispatch`](super::Port::dispatch)
    /// or carried in from upstream through
    /// [`Port::dispatch_envelope`](super::Port::dispatch_envelope); echoed in
    /// every event the command causes.
    CommandId
);
id_newtype!(
    /// Identity of one effect the kernel asked a shell to perform; the matching
    /// observation carries it back.
    OperationId
);
id_newtype!(
    /// The entity a command, effect, observation or event is about (a job, a
    /// node, a connection…). Its meaning is the domain's.
    Subject
);
id_newtype!(
    /// Incarnation of a [`Subject`]. Bumps when the subject is recreated;
    /// observations carrying an older generation are stale and the kernel
    /// drops them.
    Generation
);

/// Intent in: one command on its way to the kernel.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommandEnvelope<C> {
    /// Correlation id, echoed in the events the command causes.
    pub id: CommandId,
    /// The domain command.
    pub command: C,
}

/// Work the kernel asks a shell to do (IO, compute, spawn…). The result
/// re-enters as an [`ObservationEnvelope`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EffectEnvelope<E> {
    /// Identity of this piece of work.
    pub operation_id: OperationId,
    /// Entity the effect is about, if any.
    pub subject: Option<Subject>,
    /// Generation of `subject` when the effect was issued.
    pub generation: Generation,
    /// The domain effect.
    pub effect: E,
}

/// Result of an effect (or an unsolicited fact from a shell), entering the
/// kernel as data through its own drain.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ObservationEnvelope<O> {
    /// The effect this observation answers; `None` for unsolicited facts.
    pub operation_id: Option<OperationId>,
    /// Entity the observation is about, if any.
    pub subject: Option<Subject>,
    /// Generation the observation was produced under; the kernel drops it if
    /// the subject has moved on.
    pub generation: Generation,
    /// The domain observation.
    pub observation: O,
}

/// Ordered fact out. `sequence` rises strictly by one per published event.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EventEnvelope<V> {
    /// Position in the event log, starting at 1.
    pub sequence: u64,
    /// Command that caused this event, if any.
    pub command_id: Option<CommandId>,
    /// Entity the event is about, if any.
    pub subject: Option<Subject>,
    /// Generation of `subject` the event belongs to.
    pub generation: Generation,
    /// What happened.
    pub event: CoreEvent<V>,
}

/// The event kinds every kernel speaks, with the domain's own under `Domain`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CoreEvent<V> {
    /// The command named by `command_id` was accepted.
    Accepted,
    /// The command named by `command_id` was refused.
    Rejected(Reject),
    /// A domain event.
    Domain(V),
    /// Delivered by the edge, never logged: this subscriber fell behind and
    /// was disconnected. The subscriber recovers with
    /// [`Port::resync`](super::Port::resync); events older than
    /// `oldest_available` are no longer retained.
    ResyncRequired {
        /// Oldest sequence still in the event log when the subscriber was cut.
        oldest_available: u64,
    },
}

/// Why a command was refused.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Reject {
    /// Machine-readable class.
    pub code: RejectCode,
    /// Human-readable detail.
    pub message: String,
}

impl Reject {
    /// Builds a rejection.
    pub fn new(code: RejectCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Machine-readable rejection class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RejectCode {
    /// The command is malformed or violates an invariant.
    Invalid,
    /// The command refers to an outdated generation or revision.
    Stale,
    /// The kernel cannot take the command now; retrying later may succeed.
    Busy,
    /// A kernel counter is exhausted (see [`CoreHealth`]); nothing more of
    /// this kind is accepted.
    Exhausted,
    /// The caller may not issue this command.
    Unauthorized,
    /// A domain-specific code.
    Domain(u32),
}

/// Immutable picture of kernel state, published once per changed tick.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Snapshot<S> {
    /// Rises by one per tick that changed state.
    pub revision: u64,
    /// Sequence of the last event this snapshot already reflects.
    pub through_sequence: u64,
    /// Counter health of the kernel.
    pub health: CoreHealth,
    /// Domain state.
    pub state: S,
}

impl<S> Snapshot<S> {
    /// Revision 0, sequence 0, healthy counters.
    pub fn initial(state: S) -> Self {
        Self {
            revision: 0,
            through_sequence: 0,
            health: CoreHealth::default(),
            state,
        }
    }
}

/// Saturation flags of the kernel's monotonic counters. Once a flag is set,
/// commands that need that counter are rejected with
/// [`RejectCode::Exhausted`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CoreHealth {
    /// No further [`OperationId`] can be issued.
    pub operation_id_exhausted: bool,
    /// No further event sequence can be issued.
    pub event_sequence_exhausted: bool,
    /// No further snapshot revision can be issued.
    pub revision_exhausted: bool,
}

impl CoreHealth {
    /// True when no counter is exhausted.
    pub fn is_healthy(&self) -> bool {
        !(self.operation_id_exhausted || self.event_sequence_exhausted || self.revision_exhausted)
    }
}
