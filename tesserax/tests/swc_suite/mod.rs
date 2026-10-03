//! The SWC port contract, generic over [`Port`].
//!
//! Every test takes a [`Fixture`]: it opens a port of the given sizes and
//! returns the shell side (anything implementing [`Port`]) together with
//! the in-process [`KernelPort`] that drives it. The in-process `Handle`
//! is one fixture; a remote port serving the same kernel over a wire is
//! another, and must pass the same tests.
//!
//! What a remote port cannot show is kept, not dropped: with
//! [`Fixture::IN_PROCESS`] the tests also check what is only observable in
//! one process — events are queued by the time `publish` returns, and the
//! edge's `PublishReport` / `subscriber_count` see the subscriber's own
//! queue. Over a wire the same outcomes are awaited (bounded by [`WAIT`])
//! instead of read at once, and the edge counts are checked once the link
//! has settled.
//!
//! [`contract_suite!`] expands to one `#[test]` per contract rule for a
//! fixture.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tesserax::swc::{
    CommandEnvelope, CommandId, CoreEvent, DispatchError, EventEnvelope, Generation, KernelPort,
    Port, PortConfig, PublishError, PublishReport, RecvError, Snapshot, SnapshotCache,
    SubscribeError, Subscription,
};

pub type Cmd = u32;
pub type Ev = u64;
pub type State = u64;

/// Longest wait for something a remote port delivers asynchronously.
pub const WAIT: Duration = Duration::from_secs(10);
/// How long "nothing more arrives" is watched on a remote port.
pub const QUIET: Duration = Duration::from_millis(100);

/// A way to open a port: the shell side and the kernel side of one edge.
pub trait Fixture: 'static {
    /// The shell side under test.
    type Port: Port<Cmd, Ev, State> + Clone + Send + Sync + 'static;
    /// Keeps whatever serves the port alive (a server, a runtime).
    type Guard;
    /// The port is the in-process handle itself: delivery is synchronous
    /// with `publish` and the edge counts see the subscriber's queue.
    const IN_PROCESS: bool;
    /// Longest 10 000 refused dispatches may take. In process that is a
    /// pure queue check (1 s is generous); over a wire every call is one
    /// round trip, so the bound is round trips, still far below any
    /// blocking wait for a drain.
    const REFUSALS_BUDGET: Duration = Duration::from_secs(1);
    /// Opens a port with `cfg`.
    fn open(cfg: PortConfig) -> (Self::Port, KernelPort<Cmd, Ev, State>, Self::Guard);
}

pub fn cfg(ingress: usize, log: usize, subs: usize) -> PortConfig {
    PortConfig {
        ingress_capacity: ingress,
        event_log_capacity: log,
        max_subscribers: subs,
    }
}

fn event(sequence: u64) -> EventEnvelope<Ev> {
    EventEnvelope {
        sequence,
        command_id: None,
        subject: None,
        generation: Generation(0),
        event: CoreEvent::Domain(sequence),
    }
}

fn snapshot(revision: u64, through: u64) -> Snapshot<State> {
    Snapshot {
        revision,
        through_sequence: through,
        health: Default::default(),
        state: through,
    }
}

/// Publishes `count` events after `from`, one tick, revision = last sequence.
fn publish_range(kernel: &KernelPort<Cmd, Ev, State>, from: u64, count: u64) -> PublishReport {
    let events: Vec<_> = (from + 1..=from + count).map(event).collect();
    kernel
        .publish(events, snapshot(from + count, from + count))
        .expect("valid batch")
}

/// The next event: taken at once in process, awaited over a wire.
fn next<F: Fixture>(sub: &Subscription<Ev>) -> Result<EventEnvelope<Ev>, RecvError> {
    if F::IN_PROCESS {
        sub.try_recv()
    } else {
        sub.recv_timeout(WAIT)
    }
}

/// Exactly the events `expected` (by sequence) and nothing after them.
fn expect_sequences<F: Fixture>(sub: &Subscription<Ev>, expected: &[u64]) {
    if F::IN_PROCESS {
        let got: Vec<_> = sub.drain().into_iter().map(|e| e.sequence).collect();
        assert_eq!(got, expected);
    } else {
        let got: Vec<_> = expected
            .iter()
            .map(|_| sub.recv_timeout(WAIT).expect("event").sequence)
            .collect();
        assert_eq!(got, expected);
        expect_nothing_more::<F>(sub);
    }
}

/// No event is waiting (in process: right now; remote: for [`QUIET`]).
fn expect_nothing_more<F: Fixture>(sub: &Subscription<Ev>) {
    if F::IN_PROCESS {
        assert!(sub.is_empty());
    } else {
        assert_eq!(sub.recv_timeout(QUIET), Err(RecvError::Empty));
    }
}

/// Waits until `cond` holds (at once in process).
fn eventually<F: Fixture>(what: &str, mut cond: impl FnMut() -> bool) {
    if F::IN_PROCESS {
        assert!(cond(), "{what}");
        return;
    }
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

pub fn dispatch_returns_full_at_capacity_and_never_blocks<F: Fixture>() {
    let (handle, kernel, _guard) = F::open(cfg(4, 16, 4));
    for i in 0..4 {
        handle.dispatch(i).expect("room left");
    }
    let start = Instant::now();
    for i in 0..10_000 {
        assert_eq!(handle.dispatch(i), Err(DispatchError::Full));
    }
    assert!(
        start.elapsed() < F::REFUSALS_BUDGET,
        "10k refused dispatches took {:?}",
        start.elapsed()
    );

    let drained = kernel.drain_commands(2);
    assert_eq!(
        drained.iter().map(|c| c.command).collect::<Vec<_>>(),
        [0, 1]
    );
    handle.dispatch(4).expect("room after drain");
    handle.dispatch(5).expect("room after drain");
    assert_eq!(handle.dispatch(6), Err(DispatchError::Full));

    drop(kernel);
    assert_eq!(handle.dispatch(7), Err(DispatchError::Disconnected));
}

pub fn full_dispatch_returns_while_kernel_is_not_draining<F: Fixture>() {
    // A dispatcher on another thread must get `Full` back even though the
    // kernel never drains; the test would hang if dispatch blocked.
    let (handle, _kernel, _guard) = F::open(cfg(1, 16, 4));
    handle.dispatch(0).unwrap();
    let t = thread::spawn(move || handle.dispatch(1));
    assert_eq!(t.join().unwrap(), Err(DispatchError::Full));
}

pub fn command_ids_are_fresh_and_envelopes_keep_theirs<F: Fixture>() {
    let (handle, kernel, _guard) = F::open(cfg(8, 16, 4));
    let clone = handle.clone();
    let a = handle.dispatch(10).unwrap();
    let b = clone.dispatch(11).unwrap();
    assert_ne!(a, b);
    clone
        .dispatch_envelope(CommandEnvelope {
            id: CommandId(900),
            command: 12,
        })
        .unwrap();
    let ids: Vec<_> = kernel.drain_commands(8).into_iter().map(|c| c.id).collect();
    assert_eq!(ids, [a, b, CommandId(900)]);
}

pub fn slow_subscriber_is_disconnected_and_counted<F: Fixture>() {
    let (handle, kernel, _guard) = F::open(cfg(8, 64, 8));
    let fast = handle.subscribe(16).unwrap();
    let slow = handle.subscribe(2).unwrap();

    let report = publish_range(&kernel, 0, 3);
    if F::IN_PROCESS {
        assert_eq!(report.delivered, 3 + 2);
        assert_eq!(report.disconnected_slow, 1);
        assert_eq!(report.disconnected_closed, 0);
    }
    // In process at once; over a wire once the slow end has been cut
    // (where the cut happens — edge or client — is the transport's).
    eventually::<F>("the slow subscriber is cut", || {
        kernel.subscriber_count() == 1
    });

    // The slow subscriber keeps what it had, then learns it must resync.
    assert_eq!(next::<F>(&slow).unwrap().sequence, 1);
    assert_eq!(next::<F>(&slow).unwrap().sequence, 2);
    let marker = next::<F>(&slow).unwrap();
    assert_eq!(
        marker.event,
        CoreEvent::ResyncRequired {
            oldest_available: 1
        }
    );
    assert_eq!(
        marker.sequence, 3,
        "marker names the first undelivered sequence"
    );
    assert_eq!(next::<F>(&slow), Err(RecvError::Disconnected));

    expect_sequences::<F>(&fast, &[1, 2, 3]);

    // Later publishes no longer count the removed subscriber.
    let report = publish_range(&kernel, 3, 1);
    assert_eq!(report.delivered, 1);
    assert_eq!(report.disconnected_slow, 0);

    // Recovery path: resync from the last event it processed.
    let reply = handle.resync(2);
    assert!(!reply.gap);
    assert_eq!(
        reply.events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        [3, 4]
    );
}

pub fn dropped_subscriber_is_counted_as_closed<F: Fixture>() {
    let (handle, kernel, _guard) = F::open(cfg(8, 64, 8));
    let keep = handle.subscribe(8).unwrap();
    let gone = handle.subscribe(8).unwrap();
    drop(gone);
    if !F::IN_PROCESS {
        eventually::<F>("the dropped subscriber is gone", || {
            kernel.subscriber_count() == 1
        });
    }
    let report = publish_range(&kernel, 0, 2);
    assert_eq!(report.delivered, 2);
    // The dropped one is either pruned or counted closed, never delivered to.
    assert_eq!(report.disconnected_slow, 0);
    assert!(report.disconnected_closed <= 1);
    expect_sequences::<F>(&keep, &[1, 2]);
}

pub fn subscriber_limit_is_enforced_and_freed_on_drop<F: Fixture>() {
    let (handle, _kernel, _guard) = F::open(cfg(8, 16, 2));
    let a = handle.subscribe(4).unwrap();
    let _b = handle.subscribe(4).unwrap();
    assert!(matches!(
        handle.subscribe(4),
        Err(SubscribeError::TooManySubscribers)
    ));
    drop(a);
    let mut again = None;
    eventually::<F>("the dropped subscriber's slot is free", || {
        again = handle.subscribe(4).ok();
        again.is_some()
    });
}

pub fn resync_gap_is_true_exactly_when_after_is_below_oldest_minus_one_or_ahead<F: Fixture>() {
    let (handle, kernel, _guard) = F::open(cfg(8, 4, 4));

    // Empty log: oldest_available = last + 1 = 1; nothing is missing.
    let reply = handle.resync(0);
    assert_eq!(
        (reply.event_sequence, reply.oldest_available, reply.gap),
        (0, 1, false)
    );
    assert!(reply.events.is_empty());

    // Empty log, client ahead (e.g. it followed a kernel that restarted).
    let reply = handle.resync(3);
    assert!(reply.gap);
    assert!(reply.events.is_empty());

    publish_range(&kernel, 0, 10); // log keeps 7..=10
    for after in 0..=10_u64 {
        let reply = handle.resync(after);
        assert_eq!(reply.oldest_available, 7);
        assert_eq!(reply.event_sequence, 10);
        assert_eq!(
            reply.gap,
            after < reply.oldest_available - 1,
            "after = {after}"
        );
        assert_eq!(reply.gap, after < 6, "after = {after}");
        let seqs: Vec<_> = reply.events.iter().map(|e| e.sequence).collect();
        let expected: Vec<_> = (after.max(6) + 1..=10).collect();
        assert_eq!(seqs, expected, "after = {after}");
        assert_eq!(reply.snapshot.through_sequence, 10);
    }

    // Ahead of the log: gap, no events, snapshot to replace state with.
    for after in 11..=13_u64 {
        let reply = handle.resync(after);
        assert_eq!(reply.event_sequence, 10);
        assert!(reply.gap, "after = {after}");
        assert!(reply.events.is_empty(), "after = {after}");
        assert_eq!(reply.snapshot.through_sequence, 10);
    }
    // Exactly caught up is not a gap.
    assert!(!handle.resync(10).gap);
}

pub fn publish_refuses_bad_batches_and_changes_nothing<F: Fixture>() {
    let (handle, kernel, _guard) = F::open(cfg(8, 16, 4));
    let sub = handle.subscribe(8).unwrap();
    publish_range(&kernel, 0, 2);
    expect_sequences::<F>(&sub, &[1, 2]);

    assert_eq!(
        kernel.publish(vec![event(4)], snapshot(3, 4)),
        Err(PublishError::SequenceGap {
            expected_previous: 2,
            found: 4
        })
    );
    assert_eq!(
        kernel.publish(vec![event(3)], snapshot(3, 2)),
        Err(PublishError::ThroughSequenceMismatch {
            expected: 3,
            found: 2
        })
    );
    assert_eq!(
        kernel.publish(vec![], snapshot(1, 2)),
        Err(PublishError::RevisionRegressed {
            current: 2,
            found: 1
        })
    );
    let mut marker = event(3);
    marker.event = CoreEvent::ResyncRequired {
        oldest_available: 1,
    };
    assert_eq!(
        kernel.publish(vec![marker], snapshot(3, 3)),
        Err(PublishError::EdgeOnlyEvent { sequence: 3 })
    );

    assert_eq!(handle.snapshot().revision, 2);
    assert_eq!(handle.resync(0).event_sequence, 2);
    expect_nothing_more::<F>(&sub);

    // A snapshot-only tick is fine.
    kernel.publish(vec![], snapshot(3, 2)).unwrap();
    assert_eq!(handle.snapshot().revision, 3);
}

pub fn stress_publish_resync_snapshot_matches_log<F: Fixture>() {
    const READERS: usize = 8;
    const TICKS: u64 = 20_000;
    let (handle, kernel, _guard) = F::open(cfg(8, 256, 16));
    let done = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    let readers: Vec<_> = (0..READERS)
        .map(|r| {
            let handle = handle.clone();
            let done = Arc::clone(&done);
            thread::spawn(move || {
                let mut reads = 0_u64;
                let mut last_revision = 0;
                let mut after = r as u64;
                while !done.load(Ordering::Acquire) {
                    let reply = handle.resync(after);
                    let snap = &reply.snapshot;
                    assert_eq!(snap.through_sequence, reply.event_sequence);
                    if let Some(last) = reply.events.last() {
                        assert_eq!(last.sequence, snap.through_sequence);
                    }
                    assert_eq!(snap.state, snap.through_sequence);
                    assert!(snap.revision >= last_revision);
                    last_revision = snap.revision;

                    let lock_free = handle.snapshot();
                    assert_eq!(lock_free.state, lock_free.through_sequence);
                    assert!(lock_free.revision >= last_revision);

                    after = reply
                        .event_sequence
                        .saturating_sub((reads % 300) + r as u64);
                    reads += 1;
                }
                reads
            })
        })
        .collect();

    let mut sequence = 0;
    for tick in 1..=TICKS {
        let n = 1 + tick % 3;
        publish_range(&kernel, sequence, n);
        sequence += n;
    }
    done.store(true, Ordering::Release);
    let reads: u64 = readers.into_iter().map(|t| t.join().unwrap()).sum();

    assert!(reads > 0);
    assert_eq!(handle.snapshot().through_sequence, sequence);
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "stress took {:?}",
        start.elapsed()
    );
}

pub fn snapshot_cache_advances_only_on_new_revision<F: Fixture>() {
    let (handle, kernel, _guard) = F::open(cfg(8, 16, 4));
    let mut cache = SnapshotCache::from_port(&handle);
    assert_eq!(cache.revision(), 0);
    assert!(!cache.poll(&handle));

    publish_range(&kernel, 0, 2);
    assert!(cache.poll(&handle));
    assert_eq!(cache.get().state, 2);
    assert!(!cache.poll(&handle));

    // Works through a trait object as well (a remote port).
    let dyn_port: &dyn Port<Cmd, Ev, State> = &handle;
    publish_range(&kernel, 2, 1);
    assert!(cache.poll(dyn_port));
    assert_eq!(cache.revision(), 3);

    let reply = handle.resync(0);
    assert!(!cache.replace(reply.snapshot));
}

pub fn kernel_wait_wakes_on_dispatch_and_times_out<F: Fixture>() {
    let (handle, kernel, _guard) = F::open(cfg(8, 16, 4));
    let start = Instant::now();
    assert!(!kernel.wait(Duration::from_millis(20)));
    assert!(start.elapsed() >= Duration::from_millis(15));

    let h = handle.clone();
    let t = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        h.dispatch(7).unwrap();
    });
    let start = Instant::now();
    assert!(kernel.wait(Duration::from_secs(10)));
    assert!(start.elapsed() < Duration::from_secs(5));
    t.join().unwrap();
    // wait takes nothing
    assert_eq!(kernel.drain_commands(8).len(), 1);
}

pub fn dropping_the_kernel_disconnects_everyone<F: Fixture>() {
    let (handle, kernel, _guard) = F::open(cfg(8, 16, 4));
    let sub = handle.subscribe(4).unwrap();
    publish_range(&kernel, 0, 1);
    drop(kernel);
    assert_eq!(next::<F>(&sub).unwrap().sequence, 1);
    assert_eq!(next::<F>(&sub), Err(RecvError::Disconnected));
    assert_eq!(
        sub.recv_timeout(Duration::from_secs(5)),
        Err(RecvError::Disconnected)
    );
    let late = handle.subscribe(4).unwrap();
    assert_eq!(next::<F>(&late), Err(RecvError::Disconnected));
    assert_eq!(handle.dispatch(1), Err(DispatchError::Disconnected));
    // Snapshot and resync keep answering with the last published state.
    assert_eq!(handle.snapshot().through_sequence, 1);
    assert_eq!(handle.resync(0).events.len(), 1);
}

pub fn port_config_is_clamped<F: Fixture>() {
    let (handle, _kernel, _guard) = F::open(cfg(usize::MAX, 0, 0));
    // max_subscribers 0 is clamped to 1
    let _one = handle.subscribe(0).unwrap();
    assert!(handle.subscribe(1).is_err());
    // ingress huge is clamped to MAX_INGRESS_CAPACITY
    let mut accepted = 0;
    while handle.dispatch(0).is_ok() {
        accepted += 1;
    }
    assert_eq!(accepted, tesserax::swc::MAX_INGRESS_CAPACITY);
}

/// One `#[test]` per contract rule for fixture `$fixture`.
#[macro_export]
macro_rules! contract_suite {
    ($fixture:ty) => {
        $crate::contract_suite!(@tests $fixture;
            dispatch_returns_full_at_capacity_and_never_blocks,
            full_dispatch_returns_while_kernel_is_not_draining,
            command_ids_are_fresh_and_envelopes_keep_theirs,
            slow_subscriber_is_disconnected_and_counted,
            dropped_subscriber_is_counted_as_closed,
            subscriber_limit_is_enforced_and_freed_on_drop,
            resync_gap_is_true_exactly_when_after_is_below_oldest_minus_one_or_ahead,
            publish_refuses_bad_batches_and_changes_nothing,
            stress_publish_resync_snapshot_matches_log,
            snapshot_cache_advances_only_on_new_revision,
            kernel_wait_wakes_on_dispatch_and_times_out,
            dropping_the_kernel_disconnects_everyone,
            port_config_is_clamped,
        );
    };
    (@tests $fixture:ty; $($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                swc_suite::$name::<$fixture>();
            }
        )*
    };
}
