//! [`ReadPool`] — a bounded set of INDEPENDENT read connections to one WAL
//! file: the read side for any store whose reads outgrow the single
//! mutexed connection [`crate::Db`] hands out.
//!
//! **Measured** on a 6.7 GB store before this pattern existed: [`crate::Db`]
//! is one physical connection behind one `Mutex`, and `Db::read` is
//! `spawn_blocking` + a blocking lock on it, so every read queued behind
//! that one lock. Consequences, all measured:
//!
//! - a configured concurrency of 4 never held: four workers serialised at
//!   their first store read;
//! - one window read (a full scan, 1.37 s at 833 k rows) held the GLOBAL
//!   read lock for its whole duration, so no other stage could proceed;
//! - upstream throughput measured 12 % of its budget, the rest spent
//!   waiting on this lock.
//!
//! Shape, and why each part is load-bearing:
//!
//! - N INDEPENDENT `rusqlite::Connection`s to the same WAL file. Readers do
//!   not block each other or the writer under WAL; the only thing that ever
//!   did was the mutex.
//! - A `Semaphore` sized to the pool, so `read` awaits a free connection
//!   rather than opening an unbounded number under load.
//! - Connections are created LAZILY and kept in an idle stack — a process
//!   that never reads concurrently never pays for more than one. ONE
//!   connection is opened eagerly at [`ReadPool::open`] so a bad path or an
//!   unreadable file fails at construction, not on the first query.
//! - Every connection carries the same pragmas ([`apply_read_pragmas`]);
//!   without them the page cache sits at SQLite's 2 MiB default against
//!   multi-GB databases.
//! - A connection whose closure PANICS is dropped rather than returned to
//!   the idle stack: a panic can leave a statement mid-iteration, and the
//!   pool must not hand that state to the next caller. The next `read`
//!   opens a fresh one.
//! - Encrypted stores (feature `cipher-native`) are opened through
//!   [`ReadPoolConfig::from_config`], which keys every connection first.
//!
//! **The per-connection page-cache size is a DERIVED value, not a
//! constant**: [`DEFAULT_READ_CACHE_BUDGET_KIB`] states a TOTAL the whole
//! pool may spend, and [`per_connection_read_cache_kib`] divides it by the
//! pool's own size, floored at [`READ_CACHE_FLOOR_KIB`]. An earlier flat
//! per-connection constant, sized separately from the pool size, meant
//! raising the pool size raised real memory right along with it, unbounded
//! (24 × 128 MiB of private page cache before holding a single row).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use tokio::sync::Semaphore;
use tracing::warn;

use crate::config::DbConfig;
use crate::db::DbError;

/// Floor under which a per-connection page-cache budget refuses to go, in
/// the negative-KiB form `cache_size` wants. SQLite's own default is -2000
/// (2 MiB), and this pattern exists because 2 MiB was the difference between
/// 376 and 5,640 rows/s on a measured store's writer — so the floor sits
/// well above that default rather than at it. A pool wide enough to drive
/// `total_budget_kib / pool_size` under this floor gets the floor instead:
/// at that point a wider pool spends more TOTAL memory than the budget
/// states, which is the explicit trade this module makes rather than handing
/// every connection a cache too small to hold even one hot index page.
pub const READ_CACHE_FLOOR_KIB: i64 = 8_192; // 8 MiB

/// TOTAL page-cache budget the whole read pool may spend, in KiB —
/// POSITIVE, unlike the pragma value itself, because this is a sum across
/// N connections rather than one connection's own `cache_size` setting.
/// [`per_connection_read_cache_kib`] divides this by the pool's actual size
/// to get the number each connection is opened with, floored at
/// [`READ_CACHE_FLOOR_KIB`]. This is the fix for the defect an earlier
/// flat PER-CONNECTION constant had: 128 MiB ×
/// [`DEFAULT_READ_POOL_SIZE`] every time the pool grew, and nobody had ever
/// multiplied the two numbers together on purpose.
///
/// **Sized for an 8 GiB host**: 1 GiB for the whole read pool leaves room for the writer
/// connection's own unmultiplied cache, the mmap window's page-cache
/// pressure ([`MMAP_SIZE_BYTES`] — NOT counted against this budget: it is
/// shared through the OS page cache across connections rather than
/// multiplied per connection), the OS, and the rest of the process.
/// Deliberately conservative rather than a tight fit. Settable per call at
/// [`ReadPool::open`], alongside the pool size it is divided by — the two
/// must move together, which is why they are one constructor argument pair
/// rather than two independent globals.
pub const DEFAULT_READ_CACHE_BUDGET_KIB: i64 = 1024 * 1024; // 1 GiB total

/// Divides the pool's total budget across `pool_size` connections and
/// floors the result — the arithmetic [`DEFAULT_READ_CACHE_BUDGET_KIB`]'s
/// own doc describes. Returns the value already in the NEGATIVE-KiB form
/// `cache_size` wants, so nothing downstream has to remember the sign
/// convention a second time.
///
/// Public so a caller that opens an ad-hoc read-shaped connection to the
/// same file (e.g. [`crate::Checkpointer`]) sizes it with the SAME
/// arithmetic rather than inventing a second, independent division.
pub fn per_connection_read_cache_kib(total_budget_kib: i64, pool_size: usize) -> i64 {
    let pool_size = pool_size.max(1) as i64;
    let per_connection = (total_budget_kib / pool_size).max(READ_CACHE_FLOOR_KIB);
    -per_connection
}

/// Bytes of the database file each read connection may memory-map. Shared
/// through the OS page cache across connections, so this is not multiplied
/// by the pool size in real memory — that claim is correct for ADDRESS
/// SPACE and for file-backed pages, and it is why this constant is NOT
/// folded into [`DEFAULT_READ_CACHE_BUDGET_KIB`]'s divide.
///
/// **Left at the measured store's value, deliberately, against an open
/// question — not because the question is closed.** 4 GiB of mmap window
/// against a very large store still drives real page-cache pressure on a
/// small host and competes with the private caches above for the same
/// physical RAM, even though the window itself is shared rather than
/// multiplied per connection. Re-sizing it needs a measurement
/// (resident-set / page-cache pressure under load on the actual target
/// host, and whether Windows, Linux and macOS evict mapped-but-cold pages
/// under memory pressure the same way), not a guess.
pub const MMAP_SIZE_BYTES: i64 = 4 * 1024 * 1024 * 1024;

/// Milliseconds a reader waits on a lock before `SQLITE_BUSY`. Readers
/// under WAL contend only with a checkpointer, and that window is short.
pub(crate) const READ_BUSY_TIMEOUT_MS: i64 = 15_000;

/// Default concurrent readers. Raised from 8 to 24 against a measurement:
/// once the expensive stages of a measured workload stopped being
/// upstream-bound, what remained was pure store reads (two stages at 58 % and
/// 41 % of an interval, no upstream call in flight), each bounded at 4 by
/// its own config and competing for a pool of 8 that also served a metrics
/// poller.
///
/// SQLite in WAL mode admits any number of concurrent readers; a reader
/// blocks only against a checkpointer, and the routine checkpoint this
/// crate ships ([`crate::Checkpointer`]) is PASSIVE and takes no writer
/// lock. So the ceiling here is memory — each connection carries its own
/// page cache — not correctness. 24 leaves every stage room to run at its
/// configured bound with slots to spare.
///
/// **Since [`DEFAULT_READ_CACHE_BUDGET_KIB`], raising this number no longer
/// raises the pool's total memory.** It thins each connection's own share
/// of a fixed total instead — [`per_connection_read_cache_kib`] divides the
/// budget by whatever the pool is opened with.
pub const DEFAULT_READ_POOL_SIZE: usize = 24;

/// Default per-call read deadline for [`ReadPool::read`] and
/// [`ReadPool::read_labeled`] — override per call via
/// [`ReadPool::read_with_deadline`], or pool-wide via
/// [`ReadPoolConfig::default_read_deadline`]. 30s: the measured
/// worst-case LEGITIMATE read — a full window scan, 1.37s at 833k rows
/// (this module's own top doc) — sits
/// roughly 20x under this bound, so a query that genuinely needs this
/// long is already deep in "something is wrong" territory, not routine
/// cache-miss jitter on a bigger-than-usual scan. Enforced with
/// `Connection::get_interrupt_handle()` fired by a timer racing the query
/// (see [`ReadPool::read_with_deadline`]'s own doc for why this is safe
/// to fire even after the statement has already finished).
pub const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(30);

/// Elapsed time past which a labeled read logs one `warn!` and counts
/// toward [`ReadKindMetric::slow_calls`] — see [`ReadPool::read_labeled`]
/// and [`ReadPool::read_with_deadline`]. 250ms: the measured
/// worst case (1.37s, see [`DEFAULT_READ_DEADLINE`]) is more than 5x this
/// bar, so a call that trips it is already well past ordinary variance
/// for a pool sized ([`DEFAULT_READ_POOL_SIZE`]'s own doc) for point
/// lookups and small scans, without this becoming noisy on every
/// larger-but-fine query.
pub const DEFAULT_SLOW_QUERY_THRESHOLD: Duration = Duration::from_millis(250);

/// Every pragma a read connection carries, in one place so the pool and any
/// caller that needs an ad-hoc read connection to the same file
/// ([`crate::Checkpointer`] is exactly that) cannot drift apart.
/// `cache_size_kib` is the connection's own share of the pool's total
/// budget — already computed by [`per_connection_read_cache_kib`], already
/// in the negative-KiB form the pragma wants, and never a raw constant this
/// function reads for itself. That is exactly the property that keeps the
/// pool size from being able to multiply it back into a surprise.
pub fn apply_read_pragmas(conn: &Connection, cache_size_kib: i64) -> Result<(), DbError> {
    // Not a mode change on an already-WAL file — asserting it here means a
    // pool connection opened before any writer exists still lands in WAL
    // rather than creating a rollback journal beside the store.
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(DbError::Pragma)?;
    conn.pragma_update(None, "busy_timeout", READ_BUSY_TIMEOUT_MS)
        .map_err(DbError::Pragma)?;
    conn.pragma_update(None, "cache_size", cache_size_kib)
        .map_err(DbError::Pragma)?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(DbError::Pragma)?;
    // Best-effort: a platform or build that refuses mmap is slower, not
    // wrong, and must not fail the whole open.
    let _ = conn.pragma_update(None, "mmap_size", MMAP_SIZE_BYTES);
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(DbError::Pragma)?;
    Ok(())
}

fn open_read_connection(cfg: &DbConfig, cache_size_kib: i64) -> Result<Connection, DbError> {
    let conn = cfg.open_connection(false)?;
    apply_read_pragmas(&conn, cache_size_kib)?;
    Ok(conn)
}

/// One label's own call count / total wall time / rows returned — the
/// in-flight accumulator [`ReadMetricsInner::snapshot`] turns into
/// [`ReadKindMetric`] on read.
#[derive(Default, Clone, Copy)]
struct ReadKindStat {
    calls: u64,
    exec_micros: u64,
    rows: u64,
    slow_calls: u64,
}

/// One query SITE's counters, as reported by [`ReadPool::metrics_snapshot`].
#[derive(Debug, Clone)]
pub struct ReadKindMetric {
    /// The stable call-site name passed to [`ReadPool::read_labeled`].
    pub label: String,
    /// How many times the site ran, success or failure.
    pub calls: u64,
    /// Total wall seconds across all calls — the WHOLE call (semaphore
    /// wait, the `spawn_blocking` hop, and the query itself) as one number:
    /// at these call rates an `Instant::now()` pair around the call is
    /// cheap, while a per-row clock inside a result loop is not; and the
    /// point of the instrument is accounting for where wall time went, so
    /// splitting wait-vs-execute would add a second clock for no decision
    /// a caller ever had to make.
    pub exec_secs: f64,
    /// Rows the site's `rows_of` reported across all calls (0 on failure).
    pub rows: u64,
    /// Calls whose elapsed time reached or exceeded the pool's own
    /// `slow_query_threshold` at call time (see
    /// [`DEFAULT_SLOW_QUERY_THRESHOLD`]). Each one also logged one
    /// `warn!` naming this label, its elapsed time, and the SQL text when
    /// the caller supplied one to [`ReadPool::read_labeled`].
    pub slow_calls: u64,
}

/// Snapshot of every labeled query site's own counters since the pool
/// opened. `by_label` is sorted by label.
#[derive(Debug, Clone, Default)]
pub struct ReadPoolMetrics {
    /// One entry per label, sorted by label.
    pub by_label: Vec<ReadKindMetric>,
}

/// Per-label accumulators behind a plain `Mutex<HashMap<..>>` — cheap at
/// these call rates (`Instant::now()` around a query, never a per-row
/// clock), and never has to be kept in sync with any method list by hand.
#[derive(Default)]
struct ReadMetricsInner {
    per_label: Mutex<HashMap<&'static str, ReadKindStat>>,
}

impl ReadMetricsInner {
    /// Records one call's counters and returns whether it was slow
    /// (`elapsed >= slow_threshold`) — the caller uses that to decide
    /// whether to log the one `warn!` this instrument promises.
    fn record(
        &self,
        label: &'static str,
        elapsed: Duration,
        rows: u64,
        slow_threshold: Duration,
    ) -> bool {
        let is_slow = elapsed >= slow_threshold;
        let mut guard = self
            .per_label
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = guard.entry(label).or_default();
        entry.calls += 1;
        entry.exec_micros += elapsed.as_micros() as u64;
        entry.rows += rows;
        if is_slow {
            entry.slow_calls += 1;
        }
        is_slow
    }

    fn snapshot(&self) -> ReadPoolMetrics {
        let guard = self
            .per_label
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut by_label: Vec<ReadKindMetric> = guard
            .iter()
            .map(|(&label, stat)| ReadKindMetric {
                label: label.to_string(),
                calls: stat.calls,
                exec_secs: stat.exec_micros as f64 / 1_000_000.0,
                rows: stat.rows,
                slow_calls: stat.slow_calls,
            })
            .collect();
        by_label.sort_by(|a, b| a.label.cmp(&b.label));
        ReadPoolMetrics { by_label }
    }
}

/// A bounded set of independent read connections to one SQLite WAL file.
pub struct ReadPool {
    cfg: DbConfig,
    permits: Arc<Semaphore>,
    idle: Arc<Mutex<Vec<Connection>>>,
    metrics: ReadMetricsInner,
    /// This pool's own per-connection share of its total budget — computed
    /// once at [`Self::open`] and applied to every connection it ever
    /// opens, including the ones opened lazily under load, so a connection
    /// opened on its first busy read carries the exact same budget as the
    /// eager one opened at construction.
    cache_size_kib: i64,
    /// Deadline [`Self::read`] and [`Self::read_labeled`] enforce when the
    /// caller doesn't state its own (see [`Self::read_with_deadline`]).
    default_read_deadline: Duration,
    /// Elapsed time past which a labeled read logs a slow-query `warn!`
    /// and counts toward [`ReadKindMetric::slow_calls`].
    slow_query_threshold: Duration,
}

impl ReadPool {
    /// Opens ONE connection eagerly — so a bad path or an unreadable file
    /// fails here, at construction, exactly like the `pool`-gated
    /// `DbPool` does, rather than on the first query deep inside a phase.
    /// The rest of the pool is created lazily, under load.
    ///
    /// `total_read_cache_budget_kib` is divided by `size` (see
    /// [`per_connection_read_cache_kib`]) BEFORE that first connection
    /// opens — the total and the pool size are settable together, here, and
    /// nowhere else, so a caller cannot change one without the other
    /// silently reflowing.
    pub fn open(
        path: impl Into<PathBuf>,
        size: usize,
        total_read_cache_budget_kib: i64,
    ) -> Result<Self, DbError> {
        Self::open_internal(
            DbConfig::Path(path.into()),
            size,
            total_read_cache_budget_kib,
            DEFAULT_READ_DEADLINE,
            DEFAULT_SLOW_QUERY_THRESHOLD,
        )
    }

    /// Shared constructor behind [`Self::open`] and [`ReadPoolConfig::open`]
    /// — the only place pool size, cache budget, default deadline and slow
    /// threshold come together, so the two entry points can never disagree
    /// about how a knob is applied.
    fn open_internal(
        cfg: DbConfig,
        size: usize,
        total_read_cache_budget_kib: i64,
        default_read_deadline: Duration,
        slow_query_threshold: Duration,
    ) -> Result<Self, DbError> {
        if cfg.is_in_memory() {
            return Err(DbError::NeedsFile("a read pool"));
        }
        let size = size.max(1);
        let cache_size_kib = per_connection_read_cache_kib(total_read_cache_budget_kib, size);
        let first = open_read_connection(&cfg, cache_size_kib)?;
        Ok(ReadPool {
            cfg,
            permits: Arc::new(Semaphore::new(size)),
            idle: Arc::new(Mutex::new(vec![first])),
            metrics: ReadMetricsInner::default(),
            cache_size_kib,
            default_read_deadline,
            slow_query_threshold,
        })
    }

    /// This pool's own applied per-connection page-cache budget, in the
    /// negative-KiB form `PRAGMA cache_size` reports it in. What a
    /// [`crate::Checkpointer`] sharing this pool's file should size itself
    /// against — the store's one extra read-shaped connection outside the
    /// pool carries the same per-connection number a pool reader does,
    /// rather than reintroducing a second, unrelated constant for it.
    pub fn per_connection_cache_kib(&self) -> i64 {
        self.cache_size_kib
    }

    /// This pool's own default per-call read deadline — see
    /// [`DEFAULT_READ_DEADLINE`] / [`ReadPoolConfig::default_read_deadline`].
    pub fn default_read_deadline(&self) -> Duration {
        self.default_read_deadline
    }

    /// This pool's own slow-query warn threshold — see
    /// [`DEFAULT_SLOW_QUERY_THRESHOLD`] / [`ReadPoolConfig::slow_query_threshold`].
    pub fn slow_query_threshold(&self) -> Duration {
        self.slow_query_threshold
    }

    /// Runs `f` on a pooled connection, off the async runtime. Same
    /// signature shape as [`crate::Db::read`] so call sites move over
    /// unchanged. Bounded by [`Self::default_read_deadline`] — a runaway
    /// statement still returns (as [`DbError::Deadline`]) rather than
    /// holding this connection, and this call's future, forever. Not
    /// instrumented (no label) — see [`Self::read_labeled`] for the
    /// counted, slow-logged path.
    pub async fn read<F, T>(&self, f: F) -> Result<T, DbError>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.checkout_and_run(UNLABELED_READ, self.default_read_deadline, f)
            .await
    }

    /// [`Self::read`], instrumented per query SITE and bounded by
    /// [`Self::default_read_deadline`] (use [`Self::read_with_deadline`]
    /// for a per-call override). `label` is a stable name for the call
    /// site (one per read method that wires through this), never derived
    /// from the query text or the row type. `sql`, when `Some`, rides
    /// along on the slow-query `warn!` line only — never on the metrics
    /// row, which stays keyed by `label` alone. `rows_of` runs AFTER the
    /// query returns, on the already-materialised `&T` — never inside the
    /// query's own result loop (see [`ReadKindMetric::exec_secs`] for why).
    /// `Instant::now()` wraps the WHOLE call (semaphore wait, the
    /// `spawn_blocking` hop, and the query itself). Recorded even on `Err`
    /// (rows land at `0`): a failing read still spent wall clock this
    /// instrument exists to account for.
    pub async fn read_labeled<F, T>(
        &self,
        label: &'static str,
        sql: Option<&'static str>,
        rows_of: impl FnOnce(&T) -> u64,
        f: F,
    ) -> Result<T, DbError>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let start = Instant::now();
        let result = self
            .checkout_and_run(label, self.default_read_deadline, f)
            .await;
        let elapsed = start.elapsed();
        let rows = result.as_ref().map(rows_of).unwrap_or(0);
        let is_slow = self
            .metrics
            .record(label, elapsed, rows, self.slow_query_threshold);
        if is_slow {
            match sql {
                Some(sql) => warn!(
                    label,
                    elapsed_ms = elapsed.as_millis() as u64,
                    sql,
                    "slow read"
                ),
                None => warn!(label, elapsed_ms = elapsed.as_millis() as u64, "slow read"),
            }
        }
        result
    }

    /// [`Self::read_labeled`] with a per-call deadline instead of this
    /// pool's own [`Self::default_read_deadline`] — for a call site the
    /// caller knows must finish faster (or is willing to let run longer)
    /// than the pool-wide default. Enforced with
    /// `Connection::get_interrupt_handle()` fired by a timer racing the
    /// query: on timeout the running statement is interrupted (returns to
    /// the pool healthy — SQLite's own `sqlite3_interrupt()` contract
    /// guarantees the connection itself is never corrupted by this) and
    /// the call resolves to [`DbError::Deadline`]. Dropping the returned
    /// future before it resolves ALSO interrupts the statement — see
    /// the private interrupt-on-drop guard — so a cancelled caller never leaves
    /// a runaway query behind. `rows` is always `0` in the metrics row for
    /// calls through this method (no `rows_of` in this signature); use
    /// [`Self::read_labeled`] when row-count accounting matters.
    pub async fn read_with_deadline<F, T>(
        &self,
        label: &'static str,
        deadline: Duration,
        f: F,
    ) -> Result<T, DbError>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let start = Instant::now();
        let result = self.checkout_and_run(label, deadline, f).await;
        let elapsed = start.elapsed();
        let is_slow = self
            .metrics
            .record(label, elapsed, 0, self.slow_query_threshold);
        if is_slow {
            warn!(label, elapsed_ms = elapsed.as_millis() as u64, "slow read");
        }
        result
    }

    /// Checks out a connection (reusing an idle one or opening lazily,
    /// exactly like the pre-deadline [`Self::read`] always did), runs `f`
    /// on it under `spawn_blocking`, and races that against `deadline`.
    ///
    /// On timeout: fires [`rusqlite::InterruptHandle::interrupt`] on the
    /// connection's own currently-running statement, then AWAITS the same
    /// `spawn_blocking` task to its actual completion — bounded by how
    /// promptly SQLite's own VM notices the interrupt (checked between
    /// opcodes, so effectively immediate for anything but a single opaque
    /// native call) — before returning [`DbError::Deadline`]. The
    /// connection still comes back to the idle stack: an interrupted
    /// statement leaves the connection itself intact, never corrupted.
    ///
    /// [`InterruptOnDrop`] additionally guarantees that if THIS future is
    /// dropped (the caller cancelled, e.g. by wrapping the call in its own
    /// `tokio::time::timeout` or dropping a request future) before either
    /// branch above resolves, the same interrupt fires from `Drop` — a
    /// cancelled caller never leaves the statement running unobserved.
    async fn checkout_and_run<F, T>(
        &self,
        label: &'static str,
        deadline: Duration,
        f: F,
    ) -> Result<T, DbError>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        // Held until the connection is back on the idle stack — the permit
        // IS the accounting for "how many connections are checked out".
        let _permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DbError::Pool("read pool closed".to_string()))?;

        let pooled = self
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop();
        let conn = match pooled {
            Some(conn) => conn,
            None => open_read_connection(&self.cfg, self.cache_size_kib)?,
        };

        let guard = InterruptOnDrop::armed(conn.get_interrupt_handle());
        let query_started = Instant::now();

        // The connection travels INTO the blocking task and back out with
        // the result, so a panicking closure drops it instead of returning
        // a mid-statement connection to the pool (`JoinError` below).
        let mut join = tokio::task::spawn_blocking(move || {
            let result = f(&conn);
            (conn, result)
        });

        let (joined, timed_out) = tokio::select! {
            res = &mut join => (res, false),
            _ = tokio::time::sleep(deadline) => {
                guard.fire();
                (join.await, true)
            }
        };
        // Past this point the blocking task has fully returned, so nothing
        // of ours is running for a late `Drop` to interrupt — disarm
        // rather than fire one more (harmless, but pointless) interrupt.
        guard.disarm();

        match joined {
            Ok((conn, result)) => {
                self.idle
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(conn);
                if timed_out {
                    Err(DbError::Deadline {
                        label: label.to_string(),
                        elapsed: query_started.elapsed(),
                    })
                } else {
                    result.map_err(DbError::Query)
                }
            }
            Err(err) => Err(DbError::Join(err)),
        }
    }

    /// A snapshot of every labeled query site's own counters since this
    /// pool opened.
    pub fn metrics_snapshot(&self) -> ReadPoolMetrics {
        self.metrics.snapshot()
    }
}

/// Label [`ReadPool::read`] records [`DbError::Deadline`] under — the
/// plain path has no caller-supplied label (see [`ReadPool::read_labeled`]
/// for one that does), and this call never touches the metrics table, so
/// the constant exists only to make a timeout's error message readable.
const UNLABELED_READ: &str = "(unlabeled read)";

/// Fires [`rusqlite::InterruptHandle::interrupt`] if dropped while still
/// armed — i.e. if the async fn holding it is cancelled (its future
/// dropped) before reaching [`Self::disarm`]. Safe to fire unconditionally
/// on drop, including after the statement it was meant to guard has
/// already finished cleanly: SQLite's own contract for
/// `sqlite3_interrupt()` states plainly that "a call ... that occurs when
/// there are no running SQL statements is a no-op and has no effect on
/// SQL statements that are started after the ... call returns" — so a
/// stray fire here can never bleed into whatever query the NEXT caller
/// runs on this same connection once it is back in the idle stack.
struct InterruptOnDrop {
    handle: Option<rusqlite::InterruptHandle>,
}

impl InterruptOnDrop {
    fn armed(handle: rusqlite::InterruptHandle) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    /// Interrupts the connection's currently running statement, if any.
    fn fire(&self) {
        if let Some(handle) = self.handle.as_ref() {
            handle.interrupt();
        }
    }

    /// Consumes the guard without firing. Call this once execution is past
    /// the only point where the enclosing future could still be dropped
    /// mid-query — anything later is synchronous code that cannot be
    /// interrupted by cancellation.
    fn disarm(mut self) {
        self.handle = None;
    }
}

impl Drop for InterruptOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.interrupt();
        }
    }
}

/// Ties every read-pool tuning knob together — pool size, total cache
/// budget, default per-call read deadline, and the slow-query warn
/// threshold — so a consumer sets them as one unit instead of independent
/// constructor arguments that can silently drift apart (exactly the
/// defect [`DEFAULT_READ_CACHE_BUDGET_KIB`]'s own doc describes for
/// budget vs pool size, before that fix). Builder style: setters take
/// and return `self`, construction happens in one terminal call: every field starts at a sane, documented default;
/// override only the ones a consumer's own measurement justifies.
#[derive(Clone, Debug)]
pub struct ReadPoolConfig {
    cfg: DbConfig,
    pool_size: usize,
    total_cache_budget_kib: i64,
    default_read_deadline: Duration,
    slow_query_threshold: Duration,
}

impl ReadPoolConfig {
    /// Starts from this crate's measured defaults —
    /// [`DEFAULT_READ_POOL_SIZE`], [`DEFAULT_READ_CACHE_BUDGET_KIB`],
    /// [`DEFAULT_READ_DEADLINE`], [`DEFAULT_SLOW_QUERY_THRESHOLD`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::from_config(DbConfig::Path(path.into()))
    }

    /// [`Self::new`] for any file-backed [`DbConfig`] — the way to open a
    /// read pool on an encrypted store (every connection is keyed first).
    /// An in-memory config is refused at [`Self::open`].
    pub fn from_config(cfg: DbConfig) -> Self {
        Self {
            cfg,
            pool_size: DEFAULT_READ_POOL_SIZE,
            total_cache_budget_kib: DEFAULT_READ_CACHE_BUDGET_KIB,
            default_read_deadline: DEFAULT_READ_DEADLINE,
            slow_query_threshold: DEFAULT_SLOW_QUERY_THRESHOLD,
        }
    }

    /// Concurrent reader ceiling — see [`DEFAULT_READ_POOL_SIZE`]'s own
    /// doc for how to size this against a consumer's own concurrency
    /// bounds.
    pub fn pool_size(mut self, pool_size: usize) -> Self {
        self.pool_size = pool_size;
        self
    }

    /// TOTAL page-cache budget across the whole pool, in KiB — see
    /// [`DEFAULT_READ_CACHE_BUDGET_KIB`] for the arithmetic this divides
    /// by [`Self::pool_size`].
    pub fn total_cache_budget_kib(mut self, kib: i64) -> Self {
        self.total_cache_budget_kib = kib;
        self
    }

    /// See [`DEFAULT_READ_DEADLINE`].
    pub fn default_read_deadline(mut self, deadline: Duration) -> Self {
        self.default_read_deadline = deadline;
        self
    }

    /// See [`DEFAULT_SLOW_QUERY_THRESHOLD`].
    pub fn slow_query_threshold(mut self, threshold: Duration) -> Self {
        self.slow_query_threshold = threshold;
        self
    }

    /// Opens the pool. Fails eagerly exactly like [`ReadPool::open`] — one
    /// connection is opened synchronously here so a bad path or an
    /// unreadable file surfaces at construction.
    pub fn open(self) -> Result<ReadPool, DbError> {
        ReadPool::open_internal(
            self.cfg,
            self.pool_size,
            self.total_cache_budget_kib,
            self.default_read_deadline,
            self.slow_query_threshold,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::OptionalExtension;
    use std::path::Path;

    fn temp_path(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tesserax_store_read_pool_{tag}_{}_{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        let _ = std::fs::remove_file(PathBuf::from(&wal));
        let mut shm = path.as_os_str().to_os_string();
        shm.push("-shm");
        let _ = std::fs::remove_file(PathBuf::from(&shm));
    }

    #[tokio::test]
    async fn pragmas_are_applied_to_every_connection_the_pool_hands_out() {
        let path = temp_path("pragmas");
        let pool = Arc::new(ReadPool::open(&path, 4, DEFAULT_READ_CACHE_BUDGET_KIB).expect("open"));
        let expected = per_connection_read_cache_kib(DEFAULT_READ_CACHE_BUDGET_KIB, 4);
        // Four concurrent reads force four distinct connections into
        // existence, and each must answer with the pool's own cache size.
        // Spawned tasks (not a sequential loop): the reads must overlap or
        // they would all reuse the one eager connection.
        let mut handles = Vec::new();
        for _ in 0..4 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                pool.read(|conn| conn.query_row("PRAGMA cache_size", [], |r| r.get::<_, i64>(0)))
                    .await
                    .expect("read")
            }));
        }
        for handle in handles {
            let value = handle.await.expect("join");
            assert_eq!(
                value, expected,
                "every pooled connection carries the pool's own page-cache budget"
            );
        }
        drop(pool);
        cleanup(&path);
    }

    /// The property [`READ_CACHE_FLOOR_KIB`]/[`DEFAULT_READ_CACHE_BUDGET_KIB`]
    /// exist to guarantee, and the one an earlier flat constant was missing
    /// entirely: the TOTAL page cache the pool spends must not scale with
    /// pool size, only the per-connection SHARE of one fixed total does.
    /// Reads `PRAGMA cache_size` back off a LIVE connection so this proves
    /// what SQLite actually applied, not merely what the arithmetic computed.
    #[tokio::test]
    async fn total_applied_read_cache_across_the_pool_is_bounded_by_the_budget_regardless_of_pool_size()
     {
        let budget_kib = DEFAULT_READ_CACHE_BUDGET_KIB;
        for &pool_size in &[8usize, 32usize] {
            let path = temp_path(&format!("budget-bound-{pool_size}"));
            let pool = Arc::new(ReadPool::open(&path, pool_size, budget_kib).expect("open"));

            // Force `pool_size` distinct connections into existence, and
            // read each one's REAL applied `cache_size` back rather than
            // trusting the arithmetic alone.
            let mut handles = Vec::new();
            for _ in 0..pool_size {
                let pool = pool.clone();
                handles.push(tokio::spawn(async move {
                    pool.read(|conn| {
                        conn.query_row("PRAGMA cache_size", [], |r| r.get::<_, i64>(0))
                    })
                    .await
                    .expect("read")
                }));
            }
            let mut reported = Vec::with_capacity(pool_size);
            for handle in handles {
                reported.push(handle.await.expect("join"));
            }

            // `cache_size` reports NEGATIVE KiB when set that way (SQLite's
            // own convention) — convert explicitly rather than asserting on
            // the raw negative number.
            for &value in &reported {
                assert!(
                    value < 0,
                    "pool_size={pool_size}: cache_size must be reported negative-as-KiB, got {value}"
                );
            }
            let applied_kib_per_conn = reported[0].unsigned_abs();
            for &value in &reported {
                assert_eq!(
                    value.unsigned_abs(),
                    applied_kib_per_conn,
                    "pool_size={pool_size}: every connection in one pool must carry the same per-connection share"
                );
            }

            let total_applied_kib = applied_kib_per_conn * pool_size as u64;
            assert!(
                total_applied_kib <= budget_kib as u64,
                "pool_size={pool_size}: total applied read cache ({total_applied_kib} KiB) must not exceed the budget ({budget_kib} KiB)"
            );

            drop(pool);
            cleanup(&path);
        }
    }

    /// The other half of the same property, from the opposite direction: a
    /// pool wide enough that `budget / pool_size` would fall under
    /// [`READ_CACHE_FLOOR_KIB`] gets the floor, not a cache too small to be
    /// useful — the documented trade [`READ_CACHE_FLOOR_KIB`]'s own doc
    /// states explicitly (the floor wins over the budget once triggered).
    #[tokio::test]
    async fn a_pool_too_wide_for_its_budget_floors_the_per_connection_cache_rather_than_starving_it()
     {
        let path = temp_path("budget-floor");
        // Budget of 8 MiB total split across 16 connections would compute
        // 512 KiB each, well under the 8 MiB floor.
        let pool = ReadPool::open(&path, 16, READ_CACHE_FLOOR_KIB).expect("open");
        let applied = pool
            .read(|conn| conn.query_row("PRAGMA cache_size", [], |r| r.get::<_, i64>(0)))
            .await
            .expect("read");
        assert_eq!(
            applied.unsigned_abs(),
            READ_CACHE_FLOOR_KIB as u64,
            "an under-budget pool must floor, not starve"
        );
        drop(pool);
        cleanup(&path);
    }

    #[tokio::test]
    async fn reads_run_concurrently_rather_than_serialising_on_one_connection() {
        let path = temp_path("concurrency");
        let pool = Arc::new(ReadPool::open(&path, 4, DEFAULT_READ_CACHE_BUDGET_KIB).expect("open"));
        pool.read(|conn| conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)"))
            .await
            .expect("ddl");

        // Each reader sleeps INSIDE its blocking closure; on a single
        // mutexed connection these would sum, on a pool they overlap.
        let started = std::time::Instant::now();
        // COLLECTED, not a lazy `Map`: iterating the map inside the join
        // loop would spawn each task only when the previous one had already
        // been awaited to completion, and this test would then measure its
        // own laziness rather than the pool's concurrency.
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    pool.read(|conn| {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        conn.query_row("SELECT count(*) FROM t", [], |r| r.get::<_, i64>(0))
                    })
                    .await
                    .expect("read")
                })
            })
            .collect();
        for handle in readers {
            handle.await.expect("join");
        }
        assert!(
            started.elapsed() < std::time::Duration::from_millis(600),
            "four 200 ms reads must overlap, not serialise (took {:?})",
            started.elapsed()
        );
        drop(pool);
        cleanup(&path);
    }

    // ── read-path per-label instrumentation ──────────────────────────────

    /// A real query, labeled, must land exactly one call with nonzero
    /// elapsed time and the right row count in the snapshot — the minimum
    /// proof this instrument works before any call site relies on it.
    #[tokio::test]
    async fn read_labeled_records_one_call_nonzero_duration_and_the_reported_row_count() {
        let path = temp_path("labeled-basic");
        let pool = ReadPool::open(&path, 4, DEFAULT_READ_CACHE_BUDGET_KIB).expect("open");
        pool.read(|conn| {
            conn.execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t VALUES (1), (2), (3);",
            )
        })
        .await
        .expect("ddl+seed");

        let rows: Vec<i64> = pool
            .read_labeled(
                "count_rows_for_test",
                None,
                |v: &Vec<i64>| v.len() as u64,
                |conn| {
                    // A real (if tiny) bit of work inside the query itself,
                    // so `exec_secs` has something genuine to measure rather
                    // than racing the clock's own resolution.
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    let mut stmt = conn.prepare("SELECT id FROM t ORDER BY id")?;
                    stmt.query_map([], |r| r.get::<_, i64>(0))?.collect()
                },
            )
            .await
            .expect("labeled read");
        assert_eq!(rows, vec![1, 2, 3]);

        let snapshot = pool.metrics_snapshot();
        assert_eq!(snapshot.by_label.len(), 1, "exactly one label recorded");
        let entry = &snapshot.by_label[0];
        assert_eq!(entry.label, "count_rows_for_test");
        assert_eq!(entry.calls, 1, "exactly one call recorded");
        assert_eq!(
            entry.rows, 3,
            "the row count `rows_of` reported must reach the snapshot"
        );
        assert!(
            entry.exec_secs > 0.0,
            "a query that slept 5ms must show nonzero exec_secs, got {}",
            entry.exec_secs
        );

        drop(pool);
        cleanup(&path);
    }

    /// Two distinct labels accumulate independently, and repeated calls
    /// under the SAME label sum rather than overwrite — proves the
    /// per-label map, not just the single-call shape above.
    #[tokio::test]
    async fn read_labeled_accumulates_separately_per_label_and_sums_repeated_calls() {
        let path = temp_path("labeled-accumulate");
        let pool = ReadPool::open(&path, 4, DEFAULT_READ_CACHE_BUDGET_KIB).expect("open");
        pool.read(|conn| conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);"))
            .await
            .expect("ddl");

        for _ in 0..3 {
            let _: Option<i64> = pool
                .read_labeled(
                    "point_lookup",
                    None,
                    |v: &Option<i64>| v.is_some() as u64,
                    |conn| {
                        conn.query_row("SELECT id FROM t WHERE id = 999", [], |r| r.get(0))
                            .optional()
                    },
                )
                .await
                .expect("labeled read");
        }
        let _: Vec<i64> = pool
            .read_labeled(
                "full_scan",
                None,
                |v: &Vec<i64>| v.len() as u64,
                |conn| {
                    let mut stmt = conn.prepare("SELECT id FROM t")?;
                    stmt.query_map([], |r| r.get::<_, i64>(0))?.collect()
                },
            )
            .await
            .expect("labeled read");

        let snapshot = pool.metrics_snapshot();
        assert_eq!(snapshot.by_label.len(), 2, "two distinct labels");
        // Sorted by label — `full_scan` before `point_lookup`.
        assert_eq!(snapshot.by_label[0].label, "full_scan");
        assert_eq!(snapshot.by_label[0].calls, 1);
        assert_eq!(snapshot.by_label[0].rows, 0, "empty table, empty result");
        assert_eq!(snapshot.by_label[1].label, "point_lookup");
        assert_eq!(
            snapshot.by_label[1].calls, 3,
            "three calls under the same label must sum, not overwrite"
        );
        assert_eq!(
            snapshot.by_label[1].rows, 0,
            "no row 999 exists, every lookup reports zero rows found"
        );

        drop(pool);
        cleanup(&path);
    }

    /// A failing query still counts as a call, at zero rows — the same
    /// discipline `read_labeled`'s own doc states: a failing read still
    /// spent wall clock this instrument exists to account for.
    #[tokio::test]
    async fn read_labeled_counts_a_failing_call_at_zero_rows() {
        let path = temp_path("labeled-failure");
        let pool = ReadPool::open(&path, 4, DEFAULT_READ_CACHE_BUDGET_KIB).expect("open");

        let result: Result<Vec<i64>, DbError> = pool
            .read_labeled(
                "query_missing_table",
                None,
                |v: &Vec<i64>| v.len() as u64,
                |conn| {
                    let mut stmt = conn.prepare("SELECT id FROM this_table_does_not_exist")?;
                    stmt.query_map([], |r| r.get::<_, i64>(0))?.collect()
                },
            )
            .await;
        assert!(result.is_err(), "querying a nonexistent table must fail");

        let snapshot = pool.metrics_snapshot();
        assert_eq!(snapshot.by_label.len(), 1);
        assert_eq!(
            snapshot.by_label[0].calls, 1,
            "a failing call is still a call"
        );
        assert_eq!(snapshot.by_label[0].rows, 0);

        drop(pool);
        cleanup(&path);
    }

    // ── read deadlines ────────────────────────────────────────────────────

    /// A recursive CTE with a huge bound is the standard "runaway read"
    /// shape for this test: SQLite's own VM checks for an interrupt
    /// between opcodes, so a query built of many cheap steps notices one
    /// almost immediately, unlike a query blocked on a single opaque
    /// native call. Pool size 1 forces the health-check read at the end to
    /// reuse the EXACT SAME connection the deadline'd query ran on.
    #[tokio::test]
    async fn read_with_deadline_interrupts_a_runaway_query_and_the_connection_is_reusable_after() {
        let path = temp_path("deadline-interrupt");
        let pool = ReadPool::open(&path, 1, DEFAULT_READ_CACHE_BUDGET_KIB).expect("open");
        pool.read(|conn| conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);"))
            .await
            .expect("ddl");

        let start = Instant::now();
        let result: Result<i64, DbError> = pool
            .read_with_deadline("runaway_recursive_scan", Duration::from_millis(50), |conn| {
                conn.query_row(
                    "WITH RECURSIVE slow(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM slow WHERE x < 100000000) \
                     SELECT count(*) FROM slow",
                    [],
                    |r| r.get::<_, i64>(0),
                )
            })
            .await;
        match &result {
            Err(DbError::Deadline { label, elapsed }) => {
                assert_eq!(label, "runaway_recursive_scan");
                assert!(*elapsed >= Duration::from_millis(50));
            }
            other => panic!("expected DbError::Deadline, got {other:?}"),
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the interrupt must cut a 100M-step recursive scan short, not let it run to completion (took {:?})",
            start.elapsed()
        );

        // The connection must come back HEALTHY: an interrupted statement
        // never corrupts the connection (SQLite's own documented
        // guarantee), so a plain read right after must succeed cleanly —
        // on the pool's own single connection, since pool size is 1.
        let count: i64 = pool
            .read(|conn| conn.query_row("SELECT count(*) FROM t", [], |r| r.get(0)))
            .await
            .expect("connection must still answer after an interrupted deadline read");
        assert_eq!(count, 0);

        drop(pool);
        cleanup(&path);
    }

    /// Dropping the CALLER'S future (not the pool's own deadline) must
    /// also stop the statement — proven here by a Rust-level counter a
    /// custom SQL scalar function bumps on every recursive step: if the
    /// counter is still climbing well after the future was dropped, the
    /// statement kept running unobserved, which is exactly what
    /// `InterruptOnDrop` exists to prevent.
    #[tokio::test]
    async fn dropping_the_future_interrupts_the_statement_instead_of_leaving_it_running() {
        let path = temp_path("deadline-drop-cancel");
        let pool = Arc::new(ReadPool::open(&path, 2, DEFAULT_READ_CACHE_BUDGET_KIB).expect("open"));
        let step_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let pool_for_task = pool.clone();
        let counter_for_fn = step_count.clone();
        let handle = tokio::spawn(async move {
            pool_for_task
                .read_with_deadline(
                    "cancelled_before_its_own_deadline",
                    Duration::from_secs(30), // far beyond this test's own bound — cancellation must be what stops it, not the deadline
                    move |conn| {
                        conn.create_scalar_function(
                            "tick",
                            0,
                            rusqlite::functions::FunctionFlags::default(),
                            move |_| {
                                counter_for_fn.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                Ok(0i64)
                            },
                        )?;
                        conn.query_row(
                            "WITH RECURSIVE slow(x) AS (SELECT tick() UNION ALL SELECT tick() FROM slow WHERE x < 100000000) \
                             SELECT count(*) FROM slow",
                            [],
                            |r| r.get::<_, i64>(0),
                        )
                    },
                )
                .await
        });

        // Let the blocking task actually start running the query before
        // cancelling it.
        tokio::time::sleep(Duration::from_millis(80)).await;
        handle.abort();
        let joined = handle.await;
        assert!(
            joined.is_err(),
            "the aborted task must resolve as cancelled, not as a completed read"
        );

        // `sqlite3_interrupt()` only takes effect at the VM's NEXT check
        // between opcodes, so a step already in flight the instant
        // `.abort()` fires can still land — a brief settle wait absorbs
        // that one-off race before taking the first sample. The real
        // proof is the SECOND comparison: two samples taken well after
        // the abort, both past the settle window, must be equal, i.e. the
        // growth RATE has dropped to zero rather than merely being small.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let settled = step_count.load(std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let after_further_waiting = step_count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            settled, after_further_waiting,
            "the recursive query kept advancing after the caller's future was dropped — \
             the statement was not actually interrupted"
        );

        drop(pool);
        cleanup(&path);
    }

    // ── slow-query log / metrics ──────────────────────────────────────────

    /// A call slower than the pool's own `slow_query_threshold` counts as
    /// slow (and, at the same call site, logs the one `warn!` this
    /// instrument promises); a call comfortably under it does not.
    #[tokio::test]
    async fn slow_reads_are_counted_separately_from_fast_ones() {
        let path = temp_path("slow-query-metrics");
        let pool = ReadPoolConfig::new(&path)
            .pool_size(2)
            .slow_query_threshold(Duration::from_millis(20))
            .open()
            .expect("open");

        let _: i64 = pool
            .read_labeled(
                "fast_lookup",
                None,
                |v: &i64| *v as u64,
                |conn| conn.query_row("SELECT 1", [], |r| r.get(0)),
            )
            .await
            .expect("fast read");

        let _: i64 = pool
            .read_labeled(
                "slow_lookup",
                Some("SELECT 1 -- deliberately slowed for the test"),
                |v: &i64| *v as u64,
                |conn| {
                    std::thread::sleep(Duration::from_millis(40));
                    conn.query_row("SELECT 1", [], |r| r.get(0))
                },
            )
            .await
            .expect("slow read");

        let snapshot = pool.metrics_snapshot();
        assert_eq!(snapshot.by_label.len(), 2);
        let fast = snapshot
            .by_label
            .iter()
            .find(|m| m.label == "fast_lookup")
            .expect("fast_lookup entry");
        let slow = snapshot
            .by_label
            .iter()
            .find(|m| m.label == "slow_lookup")
            .expect("slow_lookup entry");
        assert_eq!(
            fast.slow_calls, 0,
            "a call well under the threshold must not count as slow"
        );
        assert_eq!(
            slow.slow_calls, 1,
            "a call over the threshold must count as slow exactly once"
        );

        drop(pool);
        cleanup(&path);
    }

    // ── ReadPoolConfig ────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_pool_config_applies_every_knob_it_sets() {
        let path = temp_path("config-builder");
        let pool_size = 3usize;
        let budget_kib = READ_CACHE_FLOOR_KIB * (pool_size as i64); // exact fit, no flooring
        let deadline = Duration::from_secs(7);
        let threshold = Duration::from_millis(11);

        let pool = ReadPoolConfig::new(&path)
            .pool_size(pool_size)
            .total_cache_budget_kib(budget_kib)
            .default_read_deadline(deadline)
            .slow_query_threshold(threshold)
            .open()
            .expect("open");

        assert_eq!(pool.default_read_deadline(), deadline);
        assert_eq!(pool.slow_query_threshold(), threshold);
        assert_eq!(pool.per_connection_cache_kib(), -(READ_CACHE_FLOOR_KIB));

        drop(pool);
        cleanup(&path);
    }
}
