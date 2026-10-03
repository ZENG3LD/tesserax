//! [`Executor`]: where effects go, and [`ThreadExecutor`], the std-only one.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use tesserax::swc::EffectEnvelope;

use super::queue::{BoundedQueue, Refused};
use super::sink::{EffectTicket, ObservationSink};
use crate::kernel::Domain;

/// Runs the effects of one domain off the kernel.
///
/// [`run`](Self::run) is called on the runtime thread, once per effect, in
/// the order the kernel requested them, between the step and the publish of
/// the same tick. It must return at once: hand the effect to a thread, a
/// task or a queue, and deliver the result later through `sink` as an
/// observation carrying the effect's [`EffectTicket`] (same operation id,
/// subject and generation). An executor that cannot take an effect should
/// still answer it (a refusal observation) so the domain is not left
/// waiting.
///
/// Any `FnMut(EffectEnvelope<E>, &ObservationSink<O>)` closure is an
/// executor, which is how several executors are composed: match on the
/// effect and forward it.
pub trait Executor<D: Domain>: Send + 'static {
    /// Takes one effect; never blocks.
    fn run(&mut self, effect: EffectEnvelope<D::Effect>, sink: &ObservationSink<D::Observation>);
}

impl<D, F> Executor<D> for F
where
    D: Domain,
    F: FnMut(EffectEnvelope<D::Effect>, &ObservationSink<D::Observation>) + Send + 'static,
{
    fn run(&mut self, effect: EffectEnvelope<D::Effect>, sink: &ObservationSink<D::Observation>) {
        self(effect, sink)
    }
}

/// Why an executor answered an effect without running it to completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, thiserror::Error)]
pub enum Refusal {
    /// The executor's bounded queue (or in-flight limit) was full.
    #[error("executor is full")]
    Full,
    /// The executor's workers are gone.
    #[error("executor is closed")]
    Closed,
    /// The work panicked.
    #[error("effect work panicked")]
    Panicked,
}

/// Sizes of a [`ThreadExecutor`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ThreadExecutorConfig {
    /// Worker threads (lanes), at least 1.
    pub workers: usize,
    /// Effects each lane may hold waiting, at least 1. Past it an effect is
    /// answered with [`Refusal::Full`] at once.
    pub queue_capacity: usize,
    /// How long a worker waits for room in the observation inbox before the
    /// observation is dropped (and counted in the sink's stats).
    pub submit_timeout: Duration,
    /// Thread-name prefix.
    pub name: String,
}

impl Default for ThreadExecutorConfig {
    fn default() -> Self {
        Self {
            workers: 2,
            queue_capacity: 64,
            submit_timeout: Duration::from_secs(5),
            name: "tesserax-exec".to_owned(),
        }
    }
}

type Job<E, O> = (EffectEnvelope<E>, ObservationSink<O>);
type RefuseFn<O> = dyn Fn(EffectTicket, Refusal) -> O + Send + Sync;

/// Runs effects on a fixed set of OS threads.
///
/// Each worker has its own bounded lane. Effects about the same subject
/// always go to the same lane, so they run in the order the kernel issued
/// them; effects without a subject are spread round-robin. `work` turns an
/// effect into its observation (it may block: it runs on a worker thread);
/// `refuse` builds the observation for an effect that could not be run
/// (full lane, closed lane, panic in `work`).
///
/// Dropping the executor closes the lanes; workers finish what is queued
/// and exit on their own.
pub struct ThreadExecutor<E, O> {
    lanes: Vec<Arc<BoundedQueue<Job<E, O>>>>,
    refuse: Arc<RefuseFn<O>>,
    next_lane: usize,
    workers: Vec<JoinHandle<()>>,
}

impl<E, O> core::fmt::Debug for ThreadExecutor<E, O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadExecutor")
            .field("workers", &self.workers.len())
            .field(
                "queued",
                &self.lanes.iter().map(|l| l.len()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl<E: Send + 'static, O: Send + 'static> ThreadExecutor<E, O> {
    /// Starts the workers.
    pub fn new<W, R>(config: ThreadExecutorConfig, work: W, refuse: R) -> std::io::Result<Self>
    where
        W: Fn(EffectEnvelope<E>) -> O + Send + Sync + 'static,
        R: Fn(EffectTicket, Refusal) -> O + Send + Sync + 'static,
    {
        let work = Arc::new(work);
        let refuse: Arc<RefuseFn<O>> = Arc::new(refuse);
        let mut lanes: Vec<Arc<BoundedQueue<Job<E, O>>>> = Vec::new();
        let mut workers = Vec::new();
        for index in 0..config.workers.max(1) {
            let lane = Arc::new(BoundedQueue::<Job<E, O>>::new(config.queue_capacity));
            let worker_lane = Arc::clone(&lane);
            let work = Arc::clone(&work);
            let refuse = Arc::clone(&refuse);
            let timeout = config.submit_timeout;
            let spawned = std::thread::Builder::new()
                .name(format!("{}-{index}", config.name))
                .spawn(move || {
                    while let Some(jobs) = worker_lane.drain_wait(1) {
                        for (effect, sink) in jobs {
                            let ticket = EffectTicket::of(&effect);
                            let observation = catch_unwind(AssertUnwindSafe(|| work(effect)))
                                .unwrap_or_else(|_| refuse(ticket, Refusal::Panicked));
                            // A refusal is counted by the sink itself.
                            let _ = sink.submit_timeout(ticket.answer(observation), timeout);
                        }
                    }
                });
            match spawned {
                Ok(handle) => workers.push(handle),
                Err(error) => {
                    lane.close();
                    for lane in &lanes {
                        lane.close();
                    }
                    return Err(error);
                }
            }
            lanes.push(lane);
        }
        Ok(Self {
            lanes,
            refuse,
            next_lane: 0,
            workers,
        })
    }

    /// Effects waiting across all lanes (not counting those running).
    pub fn queued(&self) -> usize {
        self.lanes.iter().map(|l| l.len()).sum()
    }

    fn lane_for(&mut self, effect: &EffectEnvelope<E>) -> usize {
        match effect.subject {
            Some(subject) => (subject.0 % self.lanes.len() as u64) as usize,
            None => {
                let lane = self.next_lane % self.lanes.len();
                self.next_lane = self.next_lane.wrapping_add(1);
                lane
            }
        }
    }

    fn dispatch(&mut self, effect: EffectEnvelope<E>, sink: &ObservationSink<O>) {
        let lane = self.lane_for(&effect);
        let ticket = EffectTicket::of(&effect);
        let refusal = match self.lanes[lane].try_push((effect, sink.clone())) {
            Ok(()) => return,
            Err(Refused::Full(_)) => Refusal::Full,
            Err(Refused::Closed(_)) => Refusal::Closed,
        };
        // Non-blocking: this runs on the runtime thread.
        let _ = sink.answer(ticket, (self.refuse)(ticket, refusal));
    }
}

impl<E, O> Drop for ThreadExecutor<E, O> {
    fn drop(&mut self) {
        for lane in &self.lanes {
            lane.close();
        }
    }
}

impl<D: Domain> Executor<D> for ThreadExecutor<D::Effect, D::Observation> {
    fn run(&mut self, effect: EffectEnvelope<D::Effect>, sink: &ObservationSink<D::Observation>) {
        self.dispatch(effect, sink);
    }
}
