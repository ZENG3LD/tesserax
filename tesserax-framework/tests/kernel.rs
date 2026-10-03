//! Kernel contract: fixed phase order, generation checks, counter
//! exhaustion, rejected commands leave nothing behind.

mod common;

use common::{Cmd, Ev, Jobs, Obs, Status};
use tesserax::swc::{
    CommandEnvelope, CommandId, CoreEvent, Generation, ObservationEnvelope, OperationId,
    RejectCode, Subject,
};
use tesserax_framework::{Core, CoreError, CoreResume, Counter};

fn cmd(id: u64, command: Cmd) -> CommandEnvelope<Cmd> {
    CommandEnvelope {
        id: CommandId(id),
        command,
    }
}

fn obs(op: u64, subject: u64, generation: u64, o: Obs) -> ObservationEnvelope<Obs> {
    ObservationEnvelope {
        operation_id: Some(OperationId(op)),
        subject: Some(Subject(subject)),
        generation: Generation(generation),
        observation: o,
    }
}

#[test]
fn phase_order_is_fixed() {
    let mut core = Core::new(Jobs::default());
    // Step 1: create a job and start two pieces of work -> operations 1, 2.
    let first = core.step(
        [
            cmd(1, Cmd::Create(10)),
            cmd(2, Cmd::Start(10, 3)),
            cmd(3, Cmd::Start(10, 4)),
        ],
        [],
    );
    assert_eq!(
        first
            .effects
            .iter()
            .map(|e| e.operation_id.0)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        core.domain().take_log(),
        [
            "advance:1",
            "command:Create(10)",
            "command:Start(10, 3)",
            "command:Start(10, 4)",
            "project",
        ]
    );

    // Step 2: observations are handed in *before* the commands in the
    // argument list order of a caller, yet always apply after commands.
    let second = core.step(
        [cmd(4, Cmd::Mark("a")), cmd(5, Cmd::Mark("b"))],
        [obs(2, 10, 1, Obs::Done(8)), obs(1, 10, 1, Obs::Done(6))],
    );
    assert_eq!(
        core.domain().take_log(),
        [
            "advance:2",
            "command:Mark(\"a\")",
            "command:Mark(\"b\")",
            "observation:2:Done(8)",
            "observation:1:Done(6)",
            "project",
        ]
    );

    // Events: outcome events in command order, then observation events;
    // sequences continue strictly by +1 from step 1.
    let last_of_first = first.events.last().unwrap().sequence;
    let sequences: Vec<u64> = second.events.iter().map(|e| e.sequence).collect();
    let expected: Vec<u64> = (last_of_first + 1..=last_of_first + 4).collect();
    assert_eq!(sequences, expected);
    assert_eq!(second.events[0].command_id, Some(CommandId(4)));
    assert!(matches!(second.events[0].event, CoreEvent::Accepted));
    assert_eq!(second.events[1].command_id, Some(CommandId(5)));
    assert!(matches!(
        second.events[2].event,
        CoreEvent::Domain(Ev::Finished { output: 8 })
    ));

    // Snapshot: revision +1 per changed step, through_sequence = last event.
    let s1 = first.snapshot.unwrap();
    let s2 = second.snapshot.unwrap();
    assert_eq!((s1.revision, s2.revision), (1, 2));
    assert_eq!(s1.through_sequence, last_of_first);
    assert_eq!(s2.through_sequence, *expected.last().unwrap());
    assert_eq!(s2.state.jobs[&10].status, Status::Done(6));

    // Step 3: nothing happens -> advance only, no projection, no revision.
    let idle = core.step([], []);
    assert!(idle.snapshot.is_none() && idle.events.is_empty());
    assert_eq!(core.domain().take_log(), ["advance:3"]);
}

#[test]
fn command_outcome_events_correlate_and_rejections_discard_output() {
    let mut core = Core::new(Jobs::default());
    let step = core.step([cmd(1, Cmd::Fail), cmd(2, Cmd::Ping)], []);
    assert_eq!(step.outcomes.len(), 2);
    let (id, result) = &step.outcomes[0];
    assert_eq!(*id, CommandId(1));
    assert_eq!(result.as_ref().unwrap_err().code, RejectCode::Domain(7));
    assert!(step.outcomes[1].1.is_ok());
    // The failed command's effect and `Doomed` event are gone.
    assert!(step.effects.is_empty());
    let kinds: Vec<_> = step
        .events
        .iter()
        .map(|e| (e.command_id, &e.event))
        .collect();
    assert!(
        matches!(kinds[0], (Some(CommandId(1)), CoreEvent::Rejected(r)) if r.code == RejectCode::Domain(7))
    );
    assert!(matches!(
        kinds[1],
        (Some(CommandId(2)), CoreEvent::Domain(Ev::Pong))
    ));
    assert!(matches!(
        kinds[2],
        (Some(CommandId(2)), CoreEvent::Accepted)
    ));
    assert_eq!(kinds.len(), 3);
    // The operation id the rejected command drew never left the kernel, so
    // it was handed back and is issued to the next accepted effect.
    let next = core.step([cmd(3, Cmd::Create(1)), cmd(4, Cmd::Start(1, 1))], []);
    assert_eq!(next.effects[0].operation_id, OperationId(1));
}

#[test]
fn stale_generation_observation_is_dropped_and_counted() {
    let mut core = Core::new(Jobs::default());
    let first = core.step([cmd(1, Cmd::Create(5)), cmd(2, Cmd::Start(5, 21))], []);
    let op = first.effects[0].operation_id.0;
    assert_eq!(first.effects[0].generation, Generation(1));
    // Recreate the job: generation 2. The generation-1 answer is stale.
    core.step([cmd(3, Cmd::Create(5))], []);
    core.domain().take_log();

    let step = core.step(
        [],
        [
            obs(op, 5, 1, Obs::Done(42)),   // stale generation
            obs(op, 99, 1, Obs::Done(1)),   // unknown subject
            obs(9_999, 5, 2, Obs::Done(1)), // never issued
            ObservationEnvelope {
                operation_id: None,
                subject: None,
                generation: Generation::default(),
                observation: Obs::Note("fresh"),
            },
        ],
    );
    assert_eq!(step.dropped.stale_generation, 1);
    assert_eq!(step.dropped.unknown_subject, 1);
    assert_eq!(step.dropped.unknown_operation, 1);
    assert_eq!(step.dropped.total(), 3);
    // Only the unsolicited note reached the domain.
    assert_eq!(
        core.domain().take_log(),
        ["advance:3", "observation:0:Note(\"fresh\")", "project"]
    );
    let snapshot = step.snapshot.unwrap();
    assert_eq!(snapshot.state.jobs[&5].status, Status::Idle);
    assert_eq!(snapshot.state.jobs[&5].generation, Generation(2));
    let stats = core.stats();
    assert_eq!(stats.observations_dropped.stale_generation, 1);
    assert_eq!(stats.observations_applied, 1);

    // A current-generation answer to a current operation applies.
    let start = core.step([cmd(4, Cmd::Start(5, 1))], []);
    let op2 = start.effects[0].operation_id.0;
    let done = core.step([], [obs(op2, 5, 2, Obs::Done(2))]);
    assert_eq!(done.dropped.total(), 0);
    assert_eq!(
        done.snapshot.unwrap().state.jobs[&5].status,
        Status::Done(2)
    );
}

#[test]
fn exhausted_operation_ids_reject_commands() {
    let mut core = Core::resume(
        Jobs::default(),
        CoreResume {
            next_operation_id: u64::MAX - 1,
            ..CoreResume::default()
        },
    );
    let step = core.step(
        [
            cmd(1, Cmd::Create(1)),
            cmd(2, Cmd::Start(1, 1)), // takes the last id
            cmd(3, Cmd::Ping),        // any command is refused now
        ],
        [],
    );
    assert!(step.outcomes[0].1.is_ok());
    assert!(step.outcomes[1].1.is_ok());
    assert_eq!(step.effects[0].operation_id, OperationId(u64::MAX - 1));
    let rejected = step.outcomes[2].1.as_ref().unwrap_err();
    assert_eq!(rejected.code, RejectCode::Exhausted);
    let snapshot = step.snapshot.unwrap();
    assert!(snapshot.health.operation_id_exhausted);
    assert!(!snapshot.health.is_healthy());
    // The rejection is still published as an event.
    assert!(
        step.events
            .iter()
            .any(|e| e.command_id == Some(CommandId(3))
                && matches!(&e.event, CoreEvent::Rejected(r) if r.code == RejectCode::Exhausted))
    );
    // Later steps keep refusing.
    let later = core.step([cmd(4, Cmd::Mark("x"))], []);
    assert_eq!(
        later.outcomes[0].1.as_ref().unwrap_err().code,
        RejectCode::Exhausted
    );
    assert_eq!(core.stats().commands_exhausted, 2);
}

#[test]
fn a_domain_hitting_the_last_operation_id_gets_exhausted() {
    let mut core = Core::resume(
        Jobs::default(),
        CoreResume {
            next_operation_id: u64::MAX,
            ..CoreResume::default()
        },
    );
    // Health is already down: the gate refuses before the domain runs.
    let step = core.step([cmd(1, Cmd::Create(1))], []);
    assert_eq!(
        step.outcomes[0].1.as_ref().unwrap_err().code,
        RejectCode::Exhausted
    );
    assert!(core.health().operation_id_exhausted);
}

#[test]
fn exhausted_event_sequence_rejects_commands() {
    let mut core = Core::resume(
        Jobs::default(),
        CoreResume {
            through_sequence: u64::MAX - 3,
            ..CoreResume::default()
        },
    );
    // Room for 3 events: Ping emits Pong + Accepted (2), the next command's
    // domain event does not fit beside its reserved outcome event.
    let step = core.step(
        [cmd(1, Cmd::Ping), cmd(2, Cmd::Ping), cmd(3, Cmd::Ping)],
        [],
    );
    assert!(step.outcomes[0].1.is_ok());
    assert_eq!(
        step.outcomes[1].1.as_ref().unwrap_err().code,
        RejectCode::Exhausted
    );
    assert_eq!(
        step.outcomes[2].1.as_ref().unwrap_err().code,
        RejectCode::Exhausted
    );
    // Pong, Accepted(1), Rejected(2) took the last three sequences; the third
    // command's outcome had no sequence left.
    assert_eq!(step.events.len(), 3);
    assert_eq!(step.events.last().unwrap().sequence, u64::MAX);
    assert_eq!(
        step.errors,
        [CoreError::OutcomeEventLost {
            command_id: CommandId(3)
        }]
    );
    let snapshot = step.snapshot.unwrap();
    assert_eq!(snapshot.through_sequence, u64::MAX);
    assert!(snapshot.health.event_sequence_exhausted);
}

#[test]
fn exhausted_revision_blocks_the_kernel() {
    let mut core = Core::resume(
        Jobs::default(),
        CoreResume {
            revision: u64::MAX - 1,
            ..CoreResume::default()
        },
    );
    // The last revision is published and carries the flag.
    let last = core.step([cmd(1, Cmd::Ping)], []);
    let snapshot = last.snapshot.unwrap();
    assert_eq!(snapshot.revision, u64::MAX);
    assert!(snapshot.health.revision_exhausted);
    // From now on: blocked. Commands rejected, observations dropped.
    let blocked = core.step(
        [cmd(2, Cmd::Ping)],
        [ObservationEnvelope {
            operation_id: None,
            subject: None,
            generation: Generation::default(),
            observation: Obs::Note("late"),
        }],
    );
    assert_eq!(
        blocked.outcomes[0].1.as_ref().unwrap_err().code,
        RejectCode::Exhausted
    );
    assert_eq!(blocked.dropped.blocked, 1);
    assert!(blocked.snapshot.is_none() && blocked.events.is_empty());
    assert_eq!(
        blocked.errors,
        [CoreError::Blocked {
            counter: Counter::Revision
        }]
    );
}

#[test]
fn resume_point_round_trips() {
    let mut core = Core::new(Jobs::default());
    core.step([cmd(1, Cmd::Create(1)), cmd(2, Cmd::Start(1, 1))], []);
    let point = core.resume_point();
    assert_eq!(point.revision, 1);
    assert_eq!(point.next_operation_id, 2);
    assert_eq!(point.logical_tick, 1);
    let restored = Core::resume(Jobs::default(), point);
    let initial = restored.initial_snapshot();
    assert_eq!(initial.revision, point.revision);
    assert_eq!(initial.through_sequence, point.through_sequence);
}

#[test]
fn operation_ids_of_a_rejected_command_are_unknown_and_handed_back() {
    let mut core = Core::new(Jobs::default());
    // `Fail` draws operation 1, then refuses: the id never left the kernel.
    let failed = core.step([cmd(1, Cmd::Create(3)), cmd(2, Cmd::Fail)], []);
    assert!(failed.effects.is_empty());
    assert_eq!(core.resume_point().next_operation_id, 1);

    // An observation naming the id only the rejected command saw is
    // dropped as an unknown operation, not applied.
    let probe = core.step([], [obs(1, 3, 1, Obs::Done(99))]);
    assert_eq!(probe.dropped.unknown_operation, 1);
    assert_eq!(core.stats().observations_applied, 0);
    assert!(probe.snapshot.is_none());

    // The id is issued again to the next accepted effect, and then its
    // observation applies.
    let started = core.step([cmd(3, Cmd::Start(3, 5))], []);
    assert_eq!(started.effects[0].operation_id, OperationId(1));
    let done = core.step([], [obs(1, 3, 1, Obs::Done(10))]);
    assert_eq!(done.dropped.total(), 0);
    assert_eq!(
        done.snapshot.unwrap().state.jobs[&3].status,
        Status::Done(10)
    );
}
