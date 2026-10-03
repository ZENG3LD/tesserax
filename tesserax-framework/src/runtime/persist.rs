//! [`PersistExecutor`] (feature `store`): effects become durable writes;
//! the observation is the flush acknowledgement.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tesserax::swc::EffectEnvelope;
use tesserax_store::{BatchConfig, BatchWriter, Db, WriteOp};

use super::executor::{Executor, Refusal};
use super::queue::{BoundedQueue, Refused};
use super::sink::{EffectTicket, ObservationSink};
use crate::kernel::Domain;

/// What happened to the write of one effect.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PersistOutcome {
    /// Committed: a durability barrier passed after the write ran.
    Persisted,
    /// Not durable: the write returned this error (and was rolled back
    /// alone), or it never ran.
    Failed(String),
    /// The write ran, but a batch commit in the same flush window failed
    /// or the barrier did not answer, so durability is not known. Treat as
    /// "check before retrying".
    Uncertain,
    /// The write was not enqueued.
    Refused(Refusal),
}

/// Bounds of a [`PersistExecutor`].
#[derive(Clone, Copy, Debug)]
pub struct PersistConfig {
    /// Shape of the executor's own [`BatchWriter`].
    pub batch: BatchConfig,
    /// Writes awaiting their acknowledgement; past it an effect is answered
    /// with `Refused(Full)` before anything is enqueued.
    pub pending_capacity: usize,
    /// How long the flusher waits for room in the observation inbox.
    pub submit_timeout: Duration,
}

impl Default for PersistConfig {
    fn default() -> Self {
        Self {
            batch: BatchConfig::default(),
            pending_capacity: 4_096,
            submit_timeout: Duration::from_secs(5),
        }
    }
}

struct Pending<O> {
    ticket: EffectTicket,
    ran: Arc<OnceLock<Result<(), String>>>,
    sink: ObservationSink<O>,
}

type AckFn<O> = dyn Fn(EffectTicket, PersistOutcome) -> O + Send + Sync;

/// Turns each effect into one [`WriteOp`] on its own [`BatchWriter`] and
/// answers it after a durability barrier.
///
/// `encode` runs on the runtime thread and must only build the operation
/// (a closure over the effect's data), not touch the database. The one
/// operation of an effect runs under its own savepoint, so an effect is
/// written entirely or not at all. A flusher thread collects the pending
/// effects, calls [`BatchWriter::barrier`] once for all of them and hands
/// each an acknowledgement built by `ack` — the kernel learns "persisted"
/// only after the commit, as an observation with the effect's ticket.
pub struct PersistExecutor<E, O> {
    writer: BatchWriter,
    encode: Box<dyn FnMut(EffectEnvelope<E>) -> WriteOp + Send>,
    ack: Arc<AckFn<O>>,
    pending: Arc<BoundedQueue<Pending<O>>>,
    op_errors: Arc<AtomicU64>,
}

impl<E, O> core::fmt::Debug for PersistExecutor<E, O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PersistExecutor")
            .field("writer", &self.writer.stats())
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl<E: Send + 'static, O: Send + 'static> PersistExecutor<E, O> {
    /// Starts a batch writer over `db` and the flusher thread.
    pub fn new<Enc, Ack>(
        db: &Db,
        config: PersistConfig,
        encode: Enc,
        ack: Ack,
    ) -> std::io::Result<Self>
    where
        Enc: FnMut(EffectEnvelope<E>) -> WriteOp + Send + 'static,
        Ack: Fn(EffectTicket, PersistOutcome) -> O + Send + Sync + 'static,
    {
        let writer = db.batch_writer(config.batch);
        let ack: Arc<AckFn<O>> = Arc::new(ack);
        let pending = Arc::new(BoundedQueue::<Pending<O>>::new(config.pending_capacity));
        let op_errors = Arc::new(AtomicU64::new(0));
        let flusher = Flusher {
            writer: writer.clone(),
            ack: Arc::clone(&ack),
            pending: Arc::clone(&pending),
            op_errors: Arc::clone(&op_errors),
            timeout: config.submit_timeout,
        };
        std::thread::Builder::new()
            .name("tesserax-persist".to_owned())
            .spawn(move || flusher.run())?;
        Ok(Self {
            writer,
            encode: Box::new(encode),
            ack,
            pending,
            op_errors,
        })
    }

    /// Counters of the executor's batch writer.
    pub fn writer_stats(&self) -> tesserax_store::BatchStats {
        self.writer.stats()
    }

    fn refuse(&self, sink: &ObservationSink<O>, ticket: EffectTicket, refusal: Refusal) {
        let _ = sink.answer(ticket, (self.ack)(ticket, PersistOutcome::Refused(refusal)));
    }

    fn dispatch(&mut self, effect: EffectEnvelope<E>, sink: &ObservationSink<O>) {
        let ticket = EffectTicket::of(&effect);
        if self.pending.is_closed() {
            return self.refuse(sink, ticket, Refusal::Closed);
        }
        // Only this thread pushes, so room seen here is still there below.
        if self.pending.len() >= self.pending.capacity() {
            return self.refuse(sink, ticket, Refusal::Full);
        }
        let op = (self.encode)(effect);
        let ran = Arc::new(OnceLock::new());
        let cell = Arc::clone(&ran);
        let op_errors = Arc::clone(&self.op_errors);
        let wrapped: WriteOp = Box::new(move |conn| {
            let result = op(conn);
            if result.is_err() {
                op_errors.fetch_add(1, Ordering::AcqRel);
            }
            let _ = cell.set(result.as_ref().map(|_| ()).map_err(|e| e.to_string()));
            result
        });
        if let Err(error) = self.writer.send(wrapped) {
            let refusal = match error {
                tesserax_store::EnqueueError::Full { .. } => Refusal::Full,
                _ => Refusal::Closed,
            };
            return self.refuse(sink, ticket, refusal);
        }
        let entry = Pending {
            ticket,
            ran,
            sink: sink.clone(),
        };
        if let Err(Refused::Full(entry) | Refused::Closed(entry)) = self.pending.try_push(entry) {
            // The write is queued but nobody will acknowledge it.
            let _ = entry
                .sink
                .answer(ticket, (self.ack)(ticket, PersistOutcome::Uncertain));
        }
    }
}

impl<E, O> Drop for PersistExecutor<E, O> {
    fn drop(&mut self) {
        self.pending.close();
    }
}

impl<D: Domain> Executor<D> for PersistExecutor<D::Effect, D::Observation> {
    fn run(&mut self, effect: EffectEnvelope<D::Effect>, sink: &ObservationSink<D::Observation>) {
        self.dispatch(effect, sink);
    }
}

struct Flusher<O> {
    writer: BatchWriter,
    ack: Arc<AckFn<O>>,
    pending: Arc<BoundedQueue<Pending<O>>>,
    op_errors: Arc<AtomicU64>,
    timeout: Duration,
}

impl<O> Flusher<O> {
    /// Operations the writer lost with a whole failed batch, as far as can
    /// be told now: failures it counted minus failures our operations
    /// reported. Read `failed` first; `op_errors` only grows, so this never
    /// over-counts (a batch still running can make it lag).
    fn lost_so_far(&self) -> u64 {
        let failed = self.writer.stats().failed;
        failed.saturating_sub(self.op_errors.load(Ordering::Acquire))
    }

    fn run(self) {
        let mut lost_seen = self.lost_so_far();
        while let Some(group) = self.pending.drain_wait(usize::MAX) {
            let barrier_ok = self.writer.barrier();
            // A whole batch was lost since the last group: the writes of this
            // group that ran may be among the lost ones.
            let lost_now = self.lost_so_far();
            let batch_lost = lost_now > lost_seen;
            lost_seen = lost_seen.max(lost_now);
            for p in group {
                let outcome = match p.ran.get() {
                    Some(Err(message)) => PersistOutcome::Failed(message.clone()),
                    None => PersistOutcome::Failed("write did not run".to_owned()),
                    Some(Ok(())) if barrier_ok && !batch_lost => PersistOutcome::Persisted,
                    Some(Ok(())) => PersistOutcome::Uncertain,
                };
                let observation = (self.ack)(p.ticket, outcome);
                let _ = p
                    .sink
                    .submit_timeout(p.ticket.answer(observation), self.timeout);
            }
        }
    }
}
