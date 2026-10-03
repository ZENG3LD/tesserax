//! The runtime: the shell that owns a [`Core`] and drives it.
//!
//! Role: shell. It owns the kernel, the kernel side of the port
//! ([`KernelPort`]), the observation inbox and the [`Executor`]. A product
//! keeps only the [`Handle`] (and, if it wants to stop the kernel, the
//! [`RuntimeHandle`]).
//!
//! # One tick (fixed order)
//!
//! 1. drain up to `max_observations_per_tick` observations from the inbox;
//! 2. drain up to `max_commands_per_tick` commands from the port;
//! 3. [`Core::step`] (the kernel's own five phases);
//! 4. hand every effect to the executor, in request order (never blocks);
//! 5. publish the step's events and snapshot through the port.
//!
//! [`Runtime::start`] runs ticks on a dedicated thread: it parks on the
//! port until a command arrives or `tick_period` has passed since the last
//! tick, so a command is picked up at once and an observation within one
//! period. [`Runtime::tick`] runs one tick on the caller's thread, for tests
//! and for hosts that bring their own loop.

mod executor;
mod queue;
mod sink;

#[cfg(feature = "store")]
mod persist;
#[cfg(feature = "tokio")]
mod tokio_executor;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tesserax::publish::Published;
use tesserax::swc::{
    CommandId, CoreHealth, Handle, KernelPort, PortConfig, PublishReport, Reject, bounded_port_from,
};

use crate::kernel::{Core, CoreError, CoreStats, Domain, ObservationDrops};

pub use executor::{Executor, Refusal, ThreadExecutor, ThreadExecutorConfig};
#[cfg(feature = "store")]
pub use persist::{PersistConfig, PersistExecutor, PersistOutcome};
pub use sink::{EffectTicket, ObservationSink, SinkError, SinkRejected, SinkStats};
#[cfg(feature = "tokio")]
pub use tokio_executor::{TokioExecutor, TokioExecutorConfig};

/// The in-process [`Handle`] of a domain's port.
pub type DomainHandle<D> =
    Handle<<D as Domain>::Command, <D as Domain>::Event, <D as Domain>::State>;

/// Tempo and bounds of one runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RuntimeConfig {
    /// Longest pause between two ticks when no command arrives.
    pub tick_period: Duration,
    /// Commands taken per tick (at least 1).
    pub max_commands_per_tick: usize,
    /// Observations taken per tick (at least 1).
    pub max_observations_per_tick: usize,
    /// Observations the inbox holds before the sink refuses more; keep it
    /// above the number of effects that can be in flight.
    pub observation_capacity: usize,
    /// Sizes of the port.
    pub port: PortConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            tick_period: Duration::from_millis(16),
            max_commands_per_tick: 256,
            max_observations_per_tick: 256,
            observation_capacity: 4_096,
            port: PortConfig::default(),
        }
    }
}

/// What one [`Runtime::tick`] did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TickReport {
    /// Command outcomes, in arrival order.
    pub outcomes: Vec<(CommandId, Result<(), Reject>)>,
    /// Observations drained and handed to the kernel.
    pub observations: usize,
    /// Of those, dropped by the kernel.
    pub dropped: ObservationDrops,
    /// Effects handed to the executor.
    pub effects: usize,
    /// Events published.
    pub events: usize,
    /// Revision published this tick, if any.
    pub revision: Option<u64>,
    /// The port's delivery report, if something was published.
    pub publish: Option<PublishReport>,
    /// What the kernel could not do.
    pub errors: Vec<CoreError>,
    /// The port refused the publish (a kernel invariant was broken).
    pub publish_error: Option<tesserax::swc::PublishError>,
}

/// Cumulative counters of a runtime, published every tick just before the
/// port publish (so they are never older than the visible snapshot).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct RuntimeStats {
    /// Ticks run.
    pub ticks: u64,
    /// The kernel's own counts.
    pub core: CoreStats,
    /// Counter health.
    pub health: CoreHealth,
    /// Last published revision.
    pub revision: u64,
    /// Last published event sequence.
    pub through_sequence: u64,
    /// Subscribers the port cut off as too slow.
    pub slow_subscribers_cut: u64,
    /// Publishes the port refused.
    pub publish_errors: u64,
    /// Observation inbox counters.
    pub sink: SinkStats,
}

/// Why the runtime could not start or stop cleanly.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The runtime thread could not be spawned.
    #[error("runtime thread could not be spawned: {0}")]
    Spawn(#[source] std::io::Error),
    /// The runtime thread panicked (a domain reducer or an executor's
    /// `run` panicked); the port is disconnected.
    #[error("runtime thread panicked")]
    Panicked,
}

/// Owns one kernel and drives it; see the [module](self) for the tick.
pub struct Runtime<D: Domain, X> {
    core: Core<D>,
    port: KernelPort<D::Command, D::Event, D::State>,
    executor: X,
    inbox: Arc<sink::Inbox<D::Observation>>,
    sink: ObservationSink<D::Observation>,
    config: RuntimeConfig,
    stats: RuntimeStats,
    published: Arc<Published<RuntimeStats>>,
    _close: CloseOnDrop<D::Observation>,
}

impl<D: Domain, X> core::fmt::Debug for Runtime<D, X> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Runtime")
            .field("core", &self.core)
            .field("config", &self.config)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl<D: Domain, X: Executor<D>> Runtime<D, X> {
    /// Builds a runtime over `core`; returns the handle products keep. The
    /// port starts from [`Core::initial_snapshot`].
    pub fn new(core: Core<D>, config: RuntimeConfig, executor: X) -> (DomainHandle<D>, Self) {
        let (handle, port) = bounded_port_from(config.port, core.initial_snapshot());
        let inbox = Arc::new(sink::Inbox::new(config.observation_capacity));
        let sink = ObservationSink::new(Arc::clone(&inbox));
        let stats = RuntimeStats {
            health: core.health(),
            revision: core.resume_point().revision,
            through_sequence: core.resume_point().through_sequence,
            ..RuntimeStats::default()
        };
        let runtime = Self {
            core,
            port,
            executor,
            inbox: Arc::clone(&inbox),
            sink,
            config,
            stats,
            published: Arc::new(Published::new(stats)),
            _close: CloseOnDrop(Arc::clone(&inbox)),
        };
        (handle, runtime)
    }

    /// Builds a runtime over a fresh core of `domain` and starts it on its
    /// own thread.
    pub fn spawn(
        domain: D,
        config: RuntimeConfig,
        executor: X,
    ) -> Result<(RuntimeHandle<D>, DomainHandle<D>), RuntimeError> {
        let (handle, runtime) = Self::new(Core::new(domain), config, executor);
        Ok((runtime.start()?, handle))
    }

    /// A sink for unsolicited observations (facts a shell learns without an
    /// effect: a peer went away, a timer outside the kernel fired).
    pub fn observation_sink(&self) -> ObservationSink<D::Observation> {
        self.sink.clone()
    }

    /// The kernel (read only).
    pub fn core(&self) -> &Core<D> {
        &self.core
    }

    /// Cumulative counters.
    pub fn stats(&self) -> RuntimeStats {
        self.stats
    }

    /// Runs one tick on the calling thread (see the [module](self)).
    pub fn tick(&mut self) -> TickReport {
        // 1-2: drain, bounded.
        let observations = self
            .inbox
            .drain(self.config.max_observations_per_tick.max(1));
        let commands = self
            .port
            .drain_commands(self.config.max_commands_per_tick.max(1));
        let mut report = TickReport {
            observations: observations.len(),
            ..TickReport::default()
        };

        // 3: the kernel step.
        let step = self.core.step(commands, observations);

        // 4: effects off the kernel, in request order.
        report.effects = step.effects.len();
        for effect in step.effects {
            self.executor.run(effect, &self.sink);
        }

        // Counters first, so a reader who sees this tick's snapshot also
        // sees counters at least this new.
        let resume = self.core.resume_point();
        self.stats.ticks += 1;
        self.stats.core = self.core.stats();
        self.stats.health = self.core.health();
        self.stats.revision = resume.revision;
        self.stats.through_sequence = resume.through_sequence;
        self.stats.sink = self.inbox.stats();
        self.published.store(self.stats);

        // 5: publish.
        report.events = step.events.len();
        if let Some(snapshot) = step.snapshot {
            let revision = snapshot.revision;
            match self.port.publish(step.events, snapshot) {
                Ok(publish) => {
                    if publish.disconnected_slow > 0 {
                        self.stats.slow_subscribers_cut += publish.disconnected_slow as u64;
                        self.published.store(self.stats);
                    }
                    report.revision = Some(revision);
                    report.publish = Some(publish);
                }
                Err(error) => {
                    self.stats.publish_errors += 1;
                    self.published.store(self.stats);
                    report.publish_error = Some(error);
                }
            }
        }
        report.outcomes = step.outcomes;
        report.dropped = step.dropped;
        report.errors = step.errors;
        report
    }

    /// Moves the runtime onto its own thread and starts ticking.
    pub fn start(self) -> Result<RuntimeHandle<D>, RuntimeError> {
        let stop = Arc::new(AtomicBool::new(false));
        let published = Arc::clone(&self.published);
        let sink = self.sink.clone();
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("tesserax-kernel".to_owned())
            .spawn(move || self.run_until(&thread_stop))
            .map_err(RuntimeError::Spawn)?;
        Ok(RuntimeHandle {
            stop,
            thread: Some(thread),
            stats: published,
            sink,
        })
    }

    fn run_until(mut self, stop: &AtomicBool) -> Core<D> {
        let period = self.config.tick_period;
        let mut last = Instant::now();
        while !stop.load(Ordering::Acquire) {
            let elapsed = last.elapsed();
            if elapsed < period {
                self.port.wait(period - elapsed);
            }
            if stop.load(Ordering::Acquire) {
                break;
            }
            last = Instant::now();
            self.tick();
        }
        self.core
    }
}

/// Closes the observation inbox when the runtime goes away, so executor
/// threads waiting for room give up and later submits are refused.
struct CloseOnDrop<O>(Arc<sink::Inbox<O>>);

impl<O> Drop for CloseOnDrop<O> {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Control of a runtime running on its own thread.
///
/// Dropping it asks the runtime to stop (without waiting); the port then
/// disconnects every [`Handle`].
pub struct RuntimeHandle<D: Domain> {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Core<D>>>,
    stats: Arc<Published<RuntimeStats>>,
    sink: ObservationSink<D::Observation>,
}

impl<D: Domain> core::fmt::Debug for RuntimeHandle<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RuntimeHandle")
            .field("stats", &*self.stats.load())
            .finish_non_exhaustive()
    }
}

impl<D: Domain> RuntimeHandle<D> {
    /// Counters as of the last tick (lock-free read).
    pub fn stats(&self) -> RuntimeStats {
        *self.stats.load()
    }

    /// A sink for unsolicited observations.
    pub fn observation_sink(&self) -> ObservationSink<D::Observation> {
        self.sink.clone()
    }

    /// Asks the runtime to stop after the current tick (within one
    /// `tick_period`). Commands still queued are not run.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Stops the runtime, waits for its thread and returns the kernel (for
    /// [`Core::resume_point`] and persistence).
    pub fn join(mut self) -> Result<Core<D>, RuntimeError> {
        self.stop();
        match self.thread.take() {
            Some(thread) => thread.join().map_err(|_| RuntimeError::Panicked),
            None => Err(RuntimeError::Panicked),
        }
    }
}

impl<D: Domain> Drop for RuntimeHandle<D> {
    fn drop(&mut self) {
        self.stop();
    }
}
