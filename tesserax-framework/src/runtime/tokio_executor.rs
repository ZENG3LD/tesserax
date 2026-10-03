//! [`TokioExecutor`] (feature `tokio`): effects as tasks on a tokio runtime.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tesserax::swc::EffectEnvelope;

use super::executor::{Executor, Refusal};
use super::sink::{EffectTicket, ObservationSink, Offer};
use crate::kernel::Domain;

/// Bounds of a [`TokioExecutor`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TokioExecutorConfig {
    /// Effects running at once; past it an effect is answered with
    /// [`Refusal::Full`] at once.
    pub max_in_flight: usize,
    /// How long a finished task keeps retrying a full observation inbox
    /// before the observation is dropped (counted by the sink).
    pub submit_timeout: Duration,
}

impl Default for TokioExecutorConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 1_024,
            submit_timeout: Duration::from_secs(5),
        }
    }
}

/// Runs each effect as a task on a tokio runtime the caller owns.
///
/// `work` turns an effect into a future of its observation; `refuse` builds
/// the observation for an effect that could not run (in-flight limit
/// reached, runtime shut down, task panicked). The kernel thread only
/// spawns; it never enters the tokio runtime otherwise.
pub struct TokioExecutor<E, O, W, R> {
    handle: tokio::runtime::Handle,
    work: W,
    refuse: Arc<R>,
    config: TokioExecutorConfig,
    in_flight: Arc<AtomicUsize>,
    _types: core::marker::PhantomData<fn(E) -> O>,
}

impl<E, O, W, R> core::fmt::Debug for TokioExecutor<E, O, W, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokioExecutor")
            .field("config", &self.config)
            .field("in_flight", &self.in_flight.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<E, O, W, R, F> TokioExecutor<E, O, W, R>
where
    E: Send + 'static,
    O: Send + 'static,
    W: Fn(EffectEnvelope<E>) -> F + Send + 'static,
    F: Future<Output = O> + Send + 'static,
    R: Fn(EffectTicket, Refusal) -> O + Send + Sync + 'static,
{
    /// An executor spawning onto `handle`.
    pub fn new(
        handle: tokio::runtime::Handle,
        config: TokioExecutorConfig,
        work: W,
        refuse: R,
    ) -> Self {
        Self {
            handle,
            work,
            refuse: Arc::new(refuse),
            config,
            in_flight: Arc::new(AtomicUsize::new(0)),
            _types: core::marker::PhantomData,
        }
    }

    /// Effects running right now.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    fn dispatch(&mut self, effect: EffectEnvelope<E>, sink: &ObservationSink<O>) {
        let ticket = EffectTicket::of(&effect);
        let limit = self.config.max_in_flight.max(1);
        let claimed = self
            .in_flight
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < limit).then_some(n + 1)
            });
        if claimed.is_err() {
            let _ = sink.answer(ticket, (self.refuse)(ticket, Refusal::Full));
            return;
        }
        let future = (self.work)(effect);
        let handle = self.handle.clone();
        let refuse = Arc::clone(&self.refuse);
        let in_flight = Arc::clone(&self.in_flight);
        let sink = sink.clone();
        let timeout = self.config.submit_timeout;
        // The inner task isolates a panic in `work`; the outer one reports.
        self.handle.spawn(async move {
            let observation = match handle.spawn(future).await {
                Ok(observation) => observation,
                Err(error) if error.is_panic() => refuse(ticket, Refusal::Panicked),
                Err(_) => refuse(ticket, Refusal::Closed),
            };
            in_flight.fetch_sub(1, Ordering::AcqRel);
            let deadline = Instant::now() + timeout;
            let mut envelope = ticket.answer(observation);
            loop {
                match sink.offer(envelope) {
                    Offer::Taken | Offer::Closed => break,
                    Offer::Full(back) => {
                        if Instant::now() >= deadline {
                            sink.give_up();
                            break;
                        }
                        envelope = back;
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            }
        });
    }
}

impl<D, W, R, F> Executor<D> for TokioExecutor<D::Effect, D::Observation, W, R>
where
    D: Domain,
    W: Fn(EffectEnvelope<D::Effect>) -> F + Send + 'static,
    F: Future<Output = D::Observation> + Send + 'static,
    R: Fn(EffectTicket, Refusal) -> D::Observation + Send + Sync + 'static,
{
    fn run(&mut self, effect: EffectEnvelope<D::Effect>, sink: &ObservationSink<D::Observation>) {
        self.dispatch(effect, sink);
    }
}
