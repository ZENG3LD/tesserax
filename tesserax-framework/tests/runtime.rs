//! Runtime contract: dispatch -> event -> snapshot revision advance through
//! the port; effects run off the kernel thread and a slow one never holds
//! up a tick; refusals come back as observations.

mod common;

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Cmd, Ev, Jobs, Obs, Status, Work};
use tesserax::swc::{
    CoreEvent, EffectEnvelope, EventEnvelope, Generation, ObservationEnvelope, Port, SnapshotCache,
    Subscription,
};
use tesserax_framework::{
    Core, EffectTicket, ObservationSink, Refusal, Runtime, RuntimeConfig, ThreadExecutor,
    ThreadExecutorConfig,
};

const WAIT: Duration = Duration::from_secs(10);

fn fast_config() -> RuntimeConfig {
    RuntimeConfig {
        tick_period: Duration::from_millis(2),
        ..RuntimeConfig::default()
    }
}

fn refuse(_: EffectTicket, why: Refusal) -> Obs {
    Obs::Refused(why.to_string())
}

/// Receives events until `pred` matches one; returns everything seen.
fn recv_until(
    sub: &Subscription<Ev>,
    mut pred: impl FnMut(&EventEnvelope<Ev>) -> bool,
) -> Vec<EventEnvelope<Ev>> {
    let deadline = Instant::now() + WAIT;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "timed out; saw {seen:?}");
        if let Ok(event) = sub.recv_timeout(left) {
            let hit = pred(&event);
            seen.push(event);
            if hit {
                return seen;
            }
        }
    }
}

/// Polls the cache until `pred` holds for its state.
fn poll_until<P: Port<Cmd, Ev, common::State>>(
    cache: &mut SnapshotCache<common::State>,
    port: &P,
    mut pred: impl FnMut(&common::State) -> bool,
) {
    let deadline = Instant::now() + WAIT;
    loop {
        cache.poll(port);
        if pred(&cache.get().state) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "state never matched: {:?}",
            cache.get()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn dispatch_event_and_snapshot_revision_advance_end_to_end() {
    let executor =
        ThreadExecutor::new(ThreadExecutorConfig::default(), common::work, refuse).unwrap();
    let (runtime, handle) = Runtime::spawn(Jobs::default(), fast_config(), executor).unwrap();
    let events = handle.subscribe(64).unwrap();
    let mut cache = SnapshotCache::from_port(&handle);
    assert_eq!(cache.revision(), 0);

    let created = handle.dispatch(Cmd::Create(7)).unwrap();
    let seen = recv_until(&events, |e| {
        e.command_id == Some(created) && matches!(e.event, CoreEvent::Accepted)
    });
    assert!(seen.iter().any(|e| e.command_id == Some(created)
        && matches!(e.event, CoreEvent::Domain(Ev::Created { generation: 1 }))));
    assert!(cache.poll(&handle), "revision must advance after the event");
    let after_create = cache.revision();
    assert!(after_create >= 1);
    assert!(cache.get().through_sequence >= seen.last().unwrap().sequence);
    assert_eq!(cache.get().state.jobs[&7].status, Status::Idle);

    // Command -> effect on a worker -> observation -> event + new revision.
    let started = handle.dispatch(Cmd::Start(7, 21)).unwrap();
    recv_until(&events, |e| {
        matches!(e.event, CoreEvent::Domain(Ev::Finished { output: 42 }))
    });
    poll_until(&mut cache, &handle, |s| {
        s.jobs[&7].status == Status::Done(42)
    });
    assert!(cache.revision() > after_create);

    // Events arrive in strict sequence order, correlated to their command.
    let resync = handle.resync(0);
    let sequences: Vec<u64> = resync.events.iter().map(|e| e.sequence).collect();
    assert!(sequences.windows(2).all(|w| w[1] == w[0] + 1));
    assert!(resync.events.iter().any(|e| e.command_id == Some(started)
        && matches!(e.event, CoreEvent::Domain(Ev::Started { .. }))));

    let stats = runtime.stats();
    assert!(stats.core.commands_accepted >= 2);
    assert!(stats.core.observations_applied >= 1);
    let core = runtime.join().unwrap();
    assert_eq!(core.stats().effects, 1);
    // The port is gone with the runtime.
    assert!(handle.dispatch(Cmd::Ping).is_err());
}

#[test]
fn slow_executor_never_blocks_the_step() {
    // The only worker blocks until the test opens the gate.
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let gate = Mutex::new(gate_rx);
    let executor = ThreadExecutor::new(
        ThreadExecutorConfig {
            workers: 1,
            ..ThreadExecutorConfig::default()
        },
        move |effect: EffectEnvelope<Work>| {
            let _ = gate.lock().unwrap().recv();
            Obs::Done(effect.effect.input)
        },
        refuse,
    )
    .unwrap();
    let (runtime, handle) = Runtime::spawn(Jobs::default(), fast_config(), executor).unwrap();
    let events = handle.subscribe(256).unwrap();

    handle.dispatch(Cmd::Create(1)).unwrap();
    handle.dispatch(Cmd::Start(1, 5)).unwrap();
    recv_until(&events, |e| {
        matches!(e.event, CoreEvent::Domain(Ev::Started { .. }))
    });

    // While the work is stuck, the kernel keeps ticking and answering.
    let mut cache = SnapshotCache::from_port(&handle);
    for _ in 0..20 {
        let ping = handle.dispatch(Cmd::Ping).unwrap();
        recv_until(&events, |e| {
            e.command_id == Some(ping) && matches!(e.event, CoreEvent::Accepted)
        });
    }
    assert!(cache.poll(&handle));
    assert!(matches!(
        cache.get().state.jobs[&1].status,
        Status::Running(_)
    ));
    let ticks_while_blocked = runtime.stats().ticks;
    assert!(ticks_while_blocked >= 20);

    // Release the worker: its observation arrives in a later tick.
    gate_tx.send(()).unwrap();
    poll_until(&mut cache, &handle, |s| {
        s.jobs[&1].status == Status::Done(5)
    });
    runtime.join().unwrap();
}

#[test]
fn a_full_lane_is_answered_with_a_refusal_observation() {
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let (started_tx, started_rx) = mpsc::channel::<u64>();
    let gate = Mutex::new((gate_rx, started_tx));
    let executor = ThreadExecutor::new(
        ThreadExecutorConfig {
            workers: 1,
            queue_capacity: 1,
            ..ThreadExecutorConfig::default()
        },
        move |effect: EffectEnvelope<Work>| {
            let gate = gate.lock().unwrap();
            gate.1.send(effect.effect.input).unwrap();
            let _ = gate.0.recv();
            Obs::Done(effect.effect.input)
        },
        refuse,
    )
    .unwrap();
    let (handle, mut runtime) = Runtime::new(Core::new(Jobs::default()), fast_config(), executor);
    for s in 1..=3 {
        handle.dispatch(Cmd::Create(s)).unwrap();
    }
    handle.dispatch(Cmd::Start(1, 1)).unwrap();
    runtime.tick();
    // The only worker is now busy with job 1.
    assert_eq!(started_rx.recv_timeout(WAIT).unwrap(), 1);
    // Job 2 fills the one-slot lane; job 3 is refused at once, in the same
    // tick, without waiting for the worker.
    handle.dispatch(Cmd::Start(2, 2)).unwrap();
    handle.dispatch(Cmd::Start(3, 3)).unwrap();
    assert_eq!(runtime.tick().effects, 2);
    runtime.tick();
    let jobs = handle.snapshot().state.jobs.clone();
    assert_eq!(
        jobs[&3].status,
        Status::Refused("executor is full".to_owned())
    );
    assert!(matches!(jobs[&2].status, Status::Running(_)));

    gate_tx.send(()).unwrap();
    assert_eq!(started_rx.recv_timeout(WAIT).unwrap(), 2);
    gate_tx.send(()).unwrap();
    let deadline = Instant::now() + WAIT;
    loop {
        runtime.tick();
        let jobs = handle.snapshot().state.jobs.clone();
        if jobs[&1].status == Status::Done(1) && jobs[&2].status == Status::Done(2) {
            break;
        }
        assert!(Instant::now() < deadline, "{jobs:?}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn a_panicking_effect_is_answered_and_the_runtime_survives() {
    let executor = ThreadExecutor::new(
        ThreadExecutorConfig::default(),
        |effect: EffectEnvelope<Work>| {
            if effect.effect.input == 0 {
                panic!("boom");
            }
            Obs::Done(effect.effect.input)
        },
        refuse,
    )
    .unwrap();
    let (handle, mut runtime) = Runtime::new(Core::new(Jobs::default()), fast_config(), executor);
    handle.dispatch(Cmd::Create(1)).unwrap();
    handle.dispatch(Cmd::Start(1, 0)).unwrap();
    runtime.tick();
    let deadline = Instant::now() + WAIT;
    loop {
        runtime.tick();
        if matches!(&handle.snapshot().state.jobs[&1].status, Status::Refused(w) if w == "effect work panicked")
        {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn stale_answers_are_dropped_and_counted_by_the_runtime() {
    // A closure executor that parks every effect for the test to answer.
    let parked: Arc<Mutex<Vec<EffectTicket>>> = Arc::default();
    let park = Arc::clone(&parked);
    let executor = move |effect: EffectEnvelope<Work>, _: &ObservationSink<Obs>| {
        park.lock().unwrap().push(EffectTicket::of(&effect));
    };
    let (handle, mut runtime) = Runtime::new(Core::new(Jobs::default()), fast_config(), executor);
    let sink = runtime.observation_sink();
    handle.dispatch(Cmd::Create(3)).unwrap();
    handle.dispatch(Cmd::Start(3, 1)).unwrap();
    runtime.tick();
    let ticket = parked.lock().unwrap()[0];
    assert_eq!(ticket.generation, Generation(1));
    // Recreate before the answer lands.
    handle.dispatch(Cmd::Create(3)).unwrap();
    runtime.tick();
    sink.answer(ticket, Obs::Done(99)).unwrap();
    let report = runtime.tick();
    assert_eq!(report.observations, 1);
    assert_eq!(report.dropped.stale_generation, 1);
    assert_eq!(
        runtime.stats().core.observations_dropped.stale_generation,
        1
    );
    assert_eq!(handle.snapshot().state.jobs[&3].status, Status::Idle);

    // An unsolicited fact through the same sink applies.
    sink.submit(ObservationEnvelope {
        operation_id: None,
        subject: None,
        generation: Generation::default(),
        observation: Obs::Note("hello"),
    })
    .unwrap();
    runtime.tick();
    assert_eq!(handle.snapshot().state.notes, ["hello"]);
    assert_eq!(sink.stats().accepted, 2);
}

#[test]
fn inbox_is_bounded_and_closes_with_the_runtime() {
    let (_handle, mut runtime) = Runtime::new(
        Core::new(Jobs::default()),
        RuntimeConfig {
            observation_capacity: 2,
            max_observations_per_tick: 1,
            ..fast_config()
        },
        |_: EffectEnvelope<Work>, _: &ObservationSink<Obs>| {},
    );
    let sink = runtime.observation_sink();
    let note = |n| ObservationEnvelope {
        operation_id: None,
        subject: None,
        generation: Generation::default(),
        observation: Obs::Note(n),
    };
    sink.submit(note("a")).unwrap();
    sink.submit(note("b")).unwrap();
    let refused = sink.submit(note("c")).unwrap_err();
    assert_eq!(refused.reason, tesserax_framework::SinkError::Full);
    assert_eq!(sink.stats().refused_full, 1);
    // Bounded drain per tick.
    assert_eq!(runtime.tick().observations, 1);
    assert_eq!(runtime.tick().observations, 1);
    drop(runtime);
    assert!(sink.is_closed());
    let closed = sink.submit(note("d")).unwrap_err();
    assert_eq!(closed.reason, tesserax_framework::SinkError::Closed);
}

#[test]
fn effects_are_handed_out_before_the_publish_of_their_tick() {
    // The executor sees the snapshot as it was before this tick's publish.
    let (probe_tx, probe_rx) = mpsc::channel::<u64>();
    let slot: Arc<Mutex<Option<tesserax::swc::Handle<Cmd, Ev, common::State>>>> = Arc::default();
    let reader = Arc::clone(&slot);
    let executor = move |_: EffectEnvelope<Work>, _: &ObservationSink<Obs>| {
        let revision = reader.lock().unwrap().as_ref().unwrap().snapshot().revision;
        probe_tx.send(revision).unwrap();
    };
    let (handle, mut runtime) = Runtime::new(Core::new(Jobs::default()), fast_config(), executor);
    *slot.lock().unwrap() = Some(handle.clone());
    handle.dispatch(Cmd::Create(1)).unwrap();
    runtime.tick();
    let before = handle.snapshot().revision;
    handle.dispatch(Cmd::Start(1, 1)).unwrap();
    let report = runtime.tick();
    assert_eq!(probe_rx.recv().unwrap(), before);
    assert_eq!(report.revision, Some(before + 1));
}
