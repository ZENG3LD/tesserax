//! [`BatchWriter`] — the standard hot-write path over [`Db`].
//!
//! Producers enqueue write closures and never wait for the disk inside a
//! business tick; one worker thread drains the queue and commits ONE
//! transaction per batch — `max_ops` operations or `flush_window` of quiet,
//! whichever comes first. Readers go through [`Db::read`] or a
//! [`crate::ReadPool`] (WAL), unaffected by the writer.
//!
//! - Every operation of a batch runs under its own `SAVEPOINT`: one failing
//!   operation is rolled back alone, the batch continues.
//! - [`BatchWriter::barrier`] is a durability point: it returns once
//!   everything enqueued before it is committed (snapshots, shutdown).
//! - Queue order is database order (one worker, FIFO).
//! - The queue is bounded: at most [`BatchConfig::queue_capacity`]
//!   operations may be pending (enqueued and not yet committed or failed,
//!   including the batch the worker is committing). [`BatchWriter::send`]
//!   never blocks; past the bound it answers [`EnqueueError::Full`], drops
//!   the operation and counts it in [`BatchStats::rejected_full`]. The
//!   depth is visible in [`BatchWriter::stats`] (`queue_depth`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use tracing::warn;

use crate::db::Db;

/// One write operation. Runs on the worker inside the batch transaction;
/// it must not open its own transaction (its `SAVEPOINT` isolates it).
pub type WriteOp = Box<dyn FnOnce(&Connection) -> rusqlite::Result<()> + Send>;

/// Elapsed batch-commit time past which the worker logs one `warn!` (label =
/// the writer's own [`Db::label`]) and counts toward
/// [`BatchStats::slow_batches`]. Same bar
/// [`crate::read_pool::DEFAULT_SLOW_QUERY_THRESHOLD`] uses on the read
/// side, for the same reason: worth a look, not yet an incident.
pub const DEFAULT_SLOW_BATCH_THRESHOLD: Duration = Duration::from_millis(250);

/// Default [`BatchConfig::queue_capacity`]: 65 536 pending operations
/// (256 full default batches) — minutes of backlog at ordinary write
/// rates, a bounded amount of memory when the disk stalls.
pub const DEFAULT_QUEUE_CAPACITY: usize = 64 * 1024;

/// Batch shape: operations per transaction, the quiet window, the queue
/// bound.
#[derive(Clone, Copy, Debug)]
pub struct BatchConfig {
    /// Most operations in one commit.
    pub max_ops: usize,
    /// How long to wait for more operations before committing.
    pub flush_window: Duration,
    /// Slow-commit threshold — see [`DEFAULT_SLOW_BATCH_THRESHOLD`].
    pub slow_batch_threshold: Duration,
    /// Most operations pending at once (at least 1); see
    /// [`DEFAULT_QUEUE_CAPACITY`].
    pub queue_capacity: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_ops: 256,
            flush_window: Duration::from_millis(50),
            slow_batch_threshold: DEFAULT_SLOW_BATCH_THRESHOLD,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
        }
    }
}

/// Why [`BatchWriter::send`] refused an operation. The operation is
/// dropped either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnqueueError {
    /// `capacity` operations are already pending; counted in
    /// [`BatchStats::rejected_full`]. Retry later or shed the write.
    #[error("batch writer queue full ({capacity} pending)")]
    Full {
        /// The configured [`BatchConfig::queue_capacity`].
        capacity: usize,
    },
    /// The worker thread is gone; counted in [`BatchStats::failed`].
    #[error("batch writer worker is gone")]
    Closed,
}

/// Snapshot of the worker's counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct BatchStats {
    /// Operations [`BatchWriter::send`] accepted into the queue (or tried
    /// to hand to a worker that was gone).
    pub enqueued: u64,
    /// Operations [`BatchWriter::send`] refused with
    /// [`EnqueueError::Full`] (not part of `enqueued`).
    pub rejected_full: u64,
    /// Operations committed.
    pub committed: u64,
    /// Operations rolled back, dropped with a failed batch, or refused
    /// because the worker was gone.
    pub failed: u64,
    /// Batches committed.
    pub batches: u64,
    /// Operations in the last committed batch.
    pub last_batch_ops: u64,
    /// Commit time of the last batch.
    pub last_batch_dur: Duration,
    /// Committed batches whose commit took at least
    /// [`BatchConfig::slow_batch_threshold`] — each one also logged one
    /// `warn!` naming the writer's own label, op count, and elapsed time.
    pub slow_batches: u64,
}

impl BatchStats {
    /// Operations waiting in the queue (approximate under concurrency).
    pub fn queue_depth(&self) -> u64 {
        self.enqueued.saturating_sub(self.committed + self.failed)
    }
}

#[derive(Default, Debug)]
struct StatsInner {
    enqueued: AtomicU64,
    rejected_full: AtomicU64,
    /// Accepted and not yet committed / failed; bounded by the capacity.
    pending: AtomicU64,
    committed: AtomicU64,
    failed: AtomicU64,
    batches: AtomicU64,
    last_batch_ops: AtomicU64,
    last_batch_micros: AtomicU64,
    slow_batches: AtomicU64,
}

enum Cmd {
    Op(WriteOp),
    Barrier(mpsc::Sender<()>),
}

/// Cheaply clonable handle to the write queue. Dropping the last handle
/// stops the worker: the channel closes, the remainder is flushed, the
/// thread exits.
#[derive(Clone)]
pub struct BatchWriter {
    tx: mpsc::Sender<Cmd>,
    stats: Arc<StatsInner>,
    capacity: usize,
}

impl BatchWriter {
    /// Starts the worker over `db` (the same physical connection and mutex;
    /// the worker holds the lock only while committing a batch).
    pub fn new(db: Db, cfg: BatchConfig) -> Self {
        let (tx, rx) = mpsc::channel::<Cmd>();
        let stats = Arc::new(StatsInner::default());
        let worker_stats = stats.clone();
        let label = db.label().to_string();
        std::thread::Builder::new()
            .name(format!("tesserax-batch-{label}"))
            .spawn(move || run(db, cfg, rx, worker_stats))
            .expect("batch writer thread spawn");
        Self {
            tx,
            stats,
            capacity: cfg.queue_capacity.max(1),
        }
    }

    /// Enqueues an operation. Never blocks: when
    /// [`BatchConfig::queue_capacity`] operations are already pending it
    /// answers [`EnqueueError::Full`] at once and drops `op`.
    pub fn send(&self, op: WriteOp) -> Result<(), EnqueueError> {
        let cap = self.capacity as u64;
        let claimed = self
            .stats
            .pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |p| {
                (p < cap).then_some(p + 1)
            });
        if claimed.is_err() {
            self.stats.rejected_full.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueError::Full {
                capacity: self.capacity,
            });
        }
        self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
        if self.tx.send(Cmd::Op(op)).is_err() {
            self.stats.pending.fetch_sub(1, Ordering::AcqRel);
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
            warn!("batch writer worker is gone — op dropped");
            return Err(EnqueueError::Closed);
        }
        Ok(())
    }

    /// The configured queue bound.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Durability point: `true` once everything enqueued before it is
    /// committed; `false` if the worker is gone or silent for 30 s.
    pub fn barrier(&self) -> bool {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(Cmd::Barrier(tx)).is_err() {
            return false;
        }
        rx.recv_timeout(Duration::from_secs(30)).is_ok()
    }

    /// [`Self::barrier`] for async contexts (runs under `spawn_blocking`).
    pub async fn barrier_async(&self) -> bool {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.barrier())
            .await
            .unwrap_or(false)
    }

    /// Current counters.
    pub fn stats(&self) -> BatchStats {
        BatchStats {
            enqueued: self.stats.enqueued.load(Ordering::Relaxed),
            rejected_full: self.stats.rejected_full.load(Ordering::Relaxed),
            committed: self.stats.committed.load(Ordering::Relaxed),
            failed: self.stats.failed.load(Ordering::Relaxed),
            batches: self.stats.batches.load(Ordering::Relaxed),
            last_batch_ops: self.stats.last_batch_ops.load(Ordering::Relaxed),
            last_batch_dur: Duration::from_micros(
                self.stats.last_batch_micros.load(Ordering::Relaxed),
            ),
            slow_batches: self.stats.slow_batches.load(Ordering::Relaxed),
        }
    }
}

impl Db {
    /// Starts a [`BatchWriter`] over this store's writer connection.
    pub fn batch_writer(&self, cfg: BatchConfig) -> BatchWriter {
        BatchWriter::new(self.clone(), cfg)
    }
}

fn run(db: Db, cfg: BatchConfig, rx: mpsc::Receiver<Cmd>, stats: Arc<StatsInner>) {
    let mut ops: Vec<WriteOp> = Vec::with_capacity(cfg.max_ops.min(1024));
    let mut barriers: Vec<mpsc::Sender<()>> = Vec::new();
    'outer: while let Ok(first) = rx.recv() {
        match first {
            Cmd::Op(op) => ops.push(op),
            Cmd::Barrier(b) => {
                barriers.push(b);
                flush(&db, &cfg, &mut ops, &mut barriers, &stats);
            }
        }
        loop {
            if ops.len() >= cfg.max_ops {
                flush(&db, &cfg, &mut ops, &mut barriers, &stats);
            }
            match rx.recv_timeout(cfg.flush_window) {
                Ok(Cmd::Op(op)) => ops.push(op),
                Ok(Cmd::Barrier(b)) => {
                    barriers.push(b);
                    flush(&db, &cfg, &mut ops, &mut barriers, &stats);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    flush(&db, &cfg, &mut ops, &mut barriers, &stats);
                    break 'outer;
                }
            }
        }
        flush(&db, &cfg, &mut ops, &mut barriers, &stats);
    }
}

/// One transaction per batch; each operation under a SAVEPOINT, so a
/// failure is contained to that operation.
fn flush(
    db: &Db,
    cfg: &BatchConfig,
    ops: &mut Vec<WriteOp>,
    barriers: &mut Vec<mpsc::Sender<()>>,
    stats: &StatsInner,
) {
    if !ops.is_empty() {
        let started = Instant::now();
        let n = ops.len() as u64;
        let mut committed = 0u64;
        let mut failed = 0u64;
        let res = db.write_blocking(|conn| {
            let tx = conn.transaction()?;
            for op in ops.drain(..) {
                tx.execute_batch("SAVEPOINT batch_op")?;
                match op(&tx) {
                    Ok(()) => {
                        tx.execute_batch("RELEASE batch_op")?;
                        committed += 1;
                    }
                    Err(e) => {
                        tx.execute_batch("ROLLBACK TO batch_op")?;
                        tx.execute_batch("RELEASE batch_op")?;
                        failed += 1;
                        warn!(error = %e, "batch op failed — rolled back, batch continues");
                    }
                }
            }
            tx.commit()
        });
        match res {
            Ok(()) => {
                let elapsed = started.elapsed();
                stats.committed.fetch_add(committed, Ordering::Relaxed);
                stats.failed.fetch_add(failed, Ordering::Relaxed);
                stats.batches.fetch_add(1, Ordering::Relaxed);
                stats.last_batch_ops.store(n, Ordering::Relaxed);
                stats
                    .last_batch_micros
                    .store(elapsed.as_micros() as u64, Ordering::Relaxed);
                if elapsed >= cfg.slow_batch_threshold {
                    stats.slow_batches.fetch_add(1, Ordering::Relaxed);
                    warn!(label = %db.label(), ops = n, elapsed_ms = elapsed.as_millis() as u64, "slow batch commit");
                }
            }
            Err(e) => {
                // The batch did not commit (transaction / savepoint error):
                // every operation of it counts as lost.
                stats.failed.fetch_add(n, Ordering::Relaxed);
                warn!(error = %e, "batch transaction failed — whole batch dropped");
            }
        }
        // Counters first, then free the slots, so a producer that sees room
        // also sees the batch accounted for.
        stats.pending.fetch_sub(n, Ordering::AcqRel);
    }
    for b in barriers.drain(..) {
        let _ = b.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DbConfig;
    use crate::migrations::{Migration, MigrationRunner};

    fn file_db(name: &str) -> (Db, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "tesserax-store-batch-test-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("batch.db");
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&DbConfig::new(&path)).unwrap();
        (db, dir)
    }

    async fn count_rows(db: &Db) -> i64 {
        db.read(|c| c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn batch_commits_all_ops() {
        let (db, dir) = file_db("all");
        db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "t",
            "CREATE TABLE t (n INTEGER PRIMARY KEY);",
        )]))
        .await
        .unwrap();
        let w = db.batch_writer(BatchConfig::default());
        for i in 0..10 {
            w.send(Box::new(move |c| {
                c.execute("INSERT INTO t VALUES (?1)", [i])?;
                Ok(())
            }))
            .unwrap();
        }
        assert!(w.barrier_async().await);
        assert_eq!(count_rows(&db).await, 10);
        let s = w.stats();
        assert_eq!(s.committed, 10);
        assert!(s.batches >= 1);
        assert_eq!(s.queue_depth(), 0);
        drop(w);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn batch_failing_op_isolated_by_savepoint() {
        let (db, dir) = file_db("iso");
        db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "t",
            "CREATE TABLE t (n INTEGER PRIMARY KEY);",
        )]))
        .await
        .unwrap();
        let w = db.batch_writer(BatchConfig {
            max_ops: 256,
            flush_window: Duration::from_millis(200),
            ..BatchConfig::default()
        });
        w.send(Box::new(|c| {
            c.execute("INSERT INTO t VALUES (1)", [])?;
            Ok(())
        }))
        .unwrap();
        w.send(Box::new(|c| {
            c.execute("INSERT INTO t VALUES (1)", [])?; // duplicate PK: fails
            Ok(())
        }))
        .unwrap();
        w.send(Box::new(|c| {
            c.execute("INSERT INTO t VALUES (2)", [])?;
            Ok(())
        }))
        .unwrap();
        assert!(w.barrier_async().await);
        assert_eq!(count_rows(&db).await, 2);
        let s = w.stats();
        assert_eq!(s.committed, 2);
        assert_eq!(s.failed, 1);
        drop(w);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn batch_barrier_async_works() {
        let (db, dir) = file_db("async");
        db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "t",
            "CREATE TABLE t (n INTEGER PRIMARY KEY);",
        )]))
        .await
        .unwrap();
        let w = db.batch_writer(BatchConfig::default());
        w.send(Box::new(|c| {
            c.execute("INSERT INTO t VALUES (7)", [])?;
            Ok(())
        }))
        .unwrap();
        assert!(w.barrier_async().await);
        assert_eq!(count_rows(&db).await, 1);
        drop(w);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A batch commit slower than `slow_batch_threshold` must count toward
    /// [`BatchStats::slow_batches`] — the write-side half of the
    /// slow-query-log instrument (see [`crate::read_pool`] for the
    /// read-side half).
    #[tokio::test]
    async fn slow_batch_commit_is_counted() {
        let (db, dir) = file_db("slow-batch");
        db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "t",
            "CREATE TABLE t (n INTEGER PRIMARY KEY);",
        )]))
        .await
        .unwrap();
        let w = db.batch_writer(BatchConfig {
            max_ops: 256,
            flush_window: Duration::from_millis(20),
            slow_batch_threshold: Duration::from_millis(1),
            ..BatchConfig::default()
        });
        w.send(Box::new(|c| {
            // Comfortably over the 1ms threshold, comfortably under the
            // 20ms flush window (so this lands in its own batch rather
            // than being split by a max_ops flush mid-sleep).
            std::thread::sleep(Duration::from_millis(15));
            c.execute("INSERT INTO t VALUES (1)", [])?;
            Ok(())
        }))
        .unwrap();
        assert!(w.barrier_async().await);
        let s = w.stats();
        assert_eq!(
            s.batches, 1,
            "one batch, so slow_batches can only be 0 or 1"
        );
        assert_eq!(
            s.slow_batches, 1,
            "a 15ms commit against a 1ms threshold must count as slow"
        );
        drop(w);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The mirror case: a batch comfortably under the threshold must NOT
    /// be counted, so the counter tracks slowness rather than every batch.
    #[tokio::test]
    async fn fast_batch_commit_is_not_counted_as_slow() {
        let (db, dir) = file_db("fast-batch");
        db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "t",
            "CREATE TABLE t (n INTEGER PRIMARY KEY);",
        )]))
        .await
        .unwrap();
        let w = db.batch_writer(BatchConfig {
            max_ops: 256,
            flush_window: Duration::from_millis(20),
            slow_batch_threshold: Duration::from_secs(10),
            ..BatchConfig::default()
        });
        w.send(Box::new(|c| {
            c.execute("INSERT INTO t VALUES (1)", [])?;
            Ok(())
        }))
        .unwrap();
        assert!(w.barrier_async().await);
        let s = w.stats();
        assert_eq!(
            s.slow_batches, 0,
            "a fast commit against a 10s threshold must not count as slow"
        );
        drop(w);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Fill to capacity -> `Full` (never blocks, counted); drain -> accepts
    /// again.
    #[tokio::test]
    async fn bounded_queue_full_then_drains() {
        let (db, dir) = file_db("bounded");
        db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "t",
            "CREATE TABLE t (n INTEGER PRIMARY KEY);",
        )]))
        .await
        .unwrap();
        const CAP: usize = 4;
        let w = db.batch_writer(BatchConfig {
            queue_capacity: CAP,
            flush_window: Duration::from_millis(5),
            ..BatchConfig::default()
        });
        assert_eq!(w.capacity(), CAP);
        // The first op holds the worker inside its batch until released,
        // so nothing drains while the queue fills.
        let (release, gate) = mpsc::channel::<()>();
        let (started_tx, started) = mpsc::channel::<()>();
        w.send(Box::new(move |c| {
            let _ = started_tx.send(());
            let _ = gate.recv_timeout(Duration::from_secs(10));
            c.execute("INSERT INTO t VALUES (0)", [])?;
            Ok(())
        }))
        .unwrap();
        started.recv_timeout(Duration::from_secs(10)).unwrap();
        for i in 1..CAP as i64 {
            w.send(Box::new(move |c| {
                c.execute("INSERT INTO t VALUES (?1)", [i])?;
                Ok(())
            }))
            .unwrap();
        }
        let t0 = Instant::now();
        let full = w.send(Box::new(|_| Ok(())));
        assert_eq!(full, Err(EnqueueError::Full { capacity: CAP }));
        assert!(t0.elapsed() < Duration::from_secs(1), "send must not block");
        assert_eq!(w.send(Box::new(|_| Ok(()))), full);
        let s = w.stats();
        assert_eq!(s.rejected_full, 2);
        assert_eq!(s.enqueued, CAP as u64);
        assert_eq!(s.queue_depth(), CAP as u64);

        release.send(()).unwrap();
        assert!(w.barrier_async().await);
        assert_eq!(count_rows(&db).await, CAP as i64);
        assert_eq!(w.stats().queue_depth(), 0);
        w.send(Box::new(|c| {
            c.execute("INSERT INTO t VALUES (100)", [])?;
            Ok(())
        }))
        .unwrap();
        assert!(w.barrier_async().await);
        assert_eq!(count_rows(&db).await, CAP as i64 + 1);
        assert_eq!(w.stats().rejected_full, 2);
        drop(w);
        let _ = std::fs::remove_dir_all(dir);
    }
}
