//! [`DbPool`] — N interchangeable SQLite connections (feature `pool`).
//!
//! No `r2d2`, no `deadpool`: both pin their own `rusqlite`, which conflicts
//! with this crate's at the `links = "sqlite3"` layer. The pool is small
//! and fully diagnosable.
//!
//! **Read-only by default.** Every connection of a pool made with
//! [`DbPool::open`] / [`DbPool::open_with_size`] runs with
//! `PRAGMA query_only = ON`: a write through it fails, and
//! [`DbPool::write`] / [`DbPool::run_migrations`] answer
//! [`DbError::ReadOnlyPool`] without touching SQLite. Writes belong to the
//! one writer, [`crate::Db`] (+ [`crate::BatchWriter`]).
//!
//! A caller that knowingly wants N interchangeable *writers* (SQLite's file
//! lock arbitrating between them, `busy_timeout` 5 s) opens the pool with
//! [`DbPool::open_with_writes`]. That one constructor is the whole opt-in:
//! there is no config type to carry a flag, the choice is visible and
//! greppable at the call site, and an existing pool can never be flipped
//! to writable.
//!
//! Internals:
//!   - idle connections in a `Vec` under a `std::sync::Mutex` (held for a
//!     push / pop only, never across an await);
//!   - a `tokio::sync::Semaphore` with `max_size` permits gates checkout;
//!   - [`DbPool::acquire`] returns a [`DbConnection`] RAII guard; dropping it
//!     returns the connection;
//!   - one connection is opened eagerly at `open` (bad path or bad key fails
//!     at boot), the rest lazily up to `max_size`.
//!
//! Surface: `acquire().await` for multi-statement work, `read` / `write`
//! one-shot closures under `spawn_blocking`, `run_migrations`, `stats`.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::info;

use crate::config::DbConfig;
use crate::db::DbError;
use crate::migrations::MigrationRunner;

/// Configured maximum on-going checkouts.
const DEFAULT_MAX_SIZE: usize = 8;

/// A pool of interchangeable SQLite connections. Cheap to clone.
#[derive(Clone)]
pub struct DbPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    cfg: DbConfig,
    label: Arc<str>,
    /// Idle connections waiting for the next acquirer.
    idle: Mutex<Vec<Connection>>,
    /// Permits — `max_size` of them. Acquiring a permit gates the wait
    /// for an actual connection slot.
    permits: Arc<Semaphore>,
    max_size: usize,
    /// Opened with [`DbPool::open_with_writes`].
    writes: bool,
}

impl DbPool {
    /// Open a read-only pool with a default size of 8 connections.
    pub fn open(cfg: &DbConfig) -> Result<Self, DbError> {
        Self::open_with_size(cfg, DEFAULT_MAX_SIZE)
    }

    /// Open a read-only pool with `max_size` connections
    /// (`PRAGMA query_only = ON` on each). The pool primes one connection
    /// eagerly to validate pragmas + file openability; the rest are
    /// created on demand. Writes go through [`crate::Db`].
    pub fn open_with_size(cfg: &DbConfig, max_size: usize) -> Result<Self, DbError> {
        Self::open_inner(cfg, max_size, false)
    }

    /// Open a pool whose `max_size` connections may all write, SQLite's
    /// file lock arbitrating between them. This breaks the one-writer rule
    /// on purpose; use it only when that is what you want, otherwise write
    /// through [`crate::Db`].
    pub fn open_with_writes(cfg: &DbConfig, max_size: usize) -> Result<Self, DbError> {
        Self::open_inner(cfg, max_size, true)
    }

    fn open_inner(cfg: &DbConfig, max_size: usize, writes: bool) -> Result<Self, DbError> {
        if cfg.is_in_memory() {
            // Every connection to `:memory:` is a separate database.
            return Err(DbError::NeedsFile("a connection pool"));
        }
        let max_size = max_size.max(1);
        // Open + configure one connection up-front. Catches bad path /
        // bad key at boot rather than first checkout.
        let primer = open_connection(cfg, writes)?;
        let label = cfg.label();
        info!(path = %label, size = max_size, writes, "db pool opened");

        let inner = PoolInner {
            cfg: cfg.clone(),
            label: Arc::from(label.as_str()),
            idle: Mutex::new(vec![primer]),
            permits: Arc::new(Semaphore::new(max_size)),
            max_size,
            writes,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The store's label.
    pub fn label(&self) -> &str {
        &self.inner.label
    }

    /// Total slots configured.
    pub fn max_size(&self) -> usize {
        self.inner.max_size
    }

    /// True for a pool opened with [`Self::open_with_writes`].
    pub fn allows_writes(&self) -> bool {
        self.inner.writes
    }

    fn check_writable(&self, what: &'static str) -> Result<(), DbError> {
        if self.inner.writes {
            Ok(())
        } else {
            Err(DbError::ReadOnlyPool(what))
        }
    }

    /// Acquire a connection. Awaits if all slots are checked out.
    pub async fn acquire(&self) -> Result<DbConnection, DbError> {
        let permit = self
            .inner
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| DbError::Pool(format!("semaphore closed: {e}")))?;
        // Try to reuse an idle connection; otherwise lazily open a new
        // one (we hold a permit so we're under max_size).
        let conn_opt = {
            let mut idle = self.inner.idle.lock().expect("pool idle mutex poisoned");
            idle.pop()
        };
        let conn = if let Some(c) = conn_opt {
            c
        } else {
            // Open under spawn_blocking so we don't park the runtime.
            let cfg = self.inner.cfg.clone();
            let writes = self.inner.writes;
            tokio::task::spawn_blocking(move || open_connection(&cfg, writes)).await??
        };
        Ok(DbConnection {
            conn: Some(conn),
            pool: self.inner.clone(),
            _permit: permit,
        })
    }

    /// Async read — wrapper over `acquire().await` + `spawn_blocking`.
    pub async fn read<F, T>(&self, f: F) -> Result<T, DbError>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let mut guard = self.acquire().await?;
        let conn = guard.take_for_blocking();
        let pool = self.inner.clone();
        let (result, conn) = tokio::task::spawn_blocking(move || {
            let r = f(&conn);
            (r, conn)
        })
        .await?;
        // Hand the connection back to the pool ourselves; the original
        // guard was emptied.
        pool.return_connection(conn);
        // Drop guard releases the permit only — connection already
        // re-homed.
        drop(guard);
        result.map_err(DbError::Query)
    }

    /// Async write — same as [`Self::read`] but the closure gets `&mut`.
    /// Only on a pool opened with [`Self::open_with_writes`]; otherwise
    /// [`DbError::ReadOnlyPool`].
    pub async fn write<F, T>(&self, f: F) -> Result<T, DbError>
    where
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.check_writable("write")?;
        let mut guard = self.acquire().await?;
        let mut conn = guard.take_for_blocking();
        let pool = self.inner.clone();
        let (result, conn) = tokio::task::spawn_blocking(move || {
            let r = f(&mut conn);
            (r, conn)
        })
        .await?;
        pool.return_connection(conn);
        drop(guard);
        result.map_err(DbError::Query)
    }

    /// Run migrations under one checked-out connection. Only on a pool
    /// opened with [`Self::open_with_writes`] (a read-only store migrates
    /// through [`crate::Db::run_migrations`]); otherwise
    /// [`DbError::ReadOnlyPool`].
    pub async fn run_migrations(&self, runner: MigrationRunner) -> Result<(), DbError> {
        self.check_writable("run_migrations")?;
        let mut guard = self.acquire().await?;
        let mut conn = guard.take_for_blocking();
        let pool = self.inner.clone();
        let (res, conn) = tokio::task::spawn_blocking(move || {
            let r = runner.run(&mut conn);
            (r, conn)
        })
        .await?;
        pool.return_connection(conn);
        drop(guard);
        res.map_err(DbError::Migration)
    }

    /// Snapshot stats — current idle count + permit availability.
    pub fn stats(&self) -> PoolStats {
        let idle = self.inner.idle.lock().expect("idle mutex poisoned").len();
        PoolStats {
            max_size: self.inner.max_size,
            idle,
            available_permits: self.inner.permits.available_permits(),
        }
    }
}

impl PoolInner {
    fn return_connection(&self, conn: Connection) {
        // std::sync::Mutex over a Vec — held for microseconds during
        // push/pop, never across an await. Safe to use from both async
        // and blocking contexts.
        let mut idle = self.idle.lock().expect("pool idle mutex poisoned");
        // Cap idle vec at max_size as defence-in-depth; if somehow we
        // exceeded it we drop the excess.
        if idle.len() < self.max_size {
            idle.push(conn);
        }
    }
}

/// Pool occupancy snapshot.
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Configured slots.
    pub max_size: usize,
    /// Open connections waiting in the idle stack.
    pub idle: usize,
    /// Slots not checked out right now.
    pub available_permits: usize,
}

/// RAII guard returned by [`DbPool::acquire`]. Derefs to `Connection`. On drop,
/// returns the connection to the pool and releases the semaphore
/// permit.
pub struct DbConnection {
    conn: Option<Connection>,
    pool: Arc<PoolInner>,
    _permit: OwnedSemaphorePermit,
}

impl DbConnection {
    /// Take ownership of the underlying `Connection`. Used internally
    /// by the async `read`/`write` paths so they can move the conn
    /// into a spawn_blocking. Callers MUST manually return the conn
    /// via the pool — direct consumer code should NEVER call this.
    fn take_for_blocking(&mut self) -> Connection {
        self.conn.take().expect("connection already taken")
    }
}

impl std::ops::Deref for DbConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn
            .as_ref()
            .expect("connection taken without being returned")
    }
}

impl std::ops::DerefMut for DbConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn
            .as_mut()
            .expect("connection taken without being returned")
    }
}

impl Drop for DbConnection {
    fn drop(&mut self) {
        if let Some(c) = self.conn.take() {
            self.pool.return_connection(c);
        }
    }
}

fn open_connection(cfg: &DbConfig, writes: bool) -> Result<Connection, DbError> {
    // Each pooled connection is an independent physical connection, so each
    // gets its own key (first statement) and its own pragmas.
    let conn = cfg.open_connection(true)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(DbError::Pragma)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(DbError::Pragma)?;
    conn.pragma_update(None, "busy_timeout", 5_000)
        .map_err(DbError::Pragma)?;
    if !writes {
        conn.pragma_update(None, "query_only", "ON")
            .map_err(DbError::Pragma)?;
    }
    tracing::debug!(path = %cfg.label(), writes, "pool connection opened");
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Migration;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tesserax-store-pool-{}-{}-{}.db",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[tokio::test]
    async fn opens_and_runs_migrations() {
        let path = temp_path("migrate");
        let pool = DbPool::open_with_writes(&DbConfig::new(&path), 4).unwrap();
        pool.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "users",
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);",
        )]))
        .await
        .unwrap();

        pool.write(|c| {
            c.execute("INSERT INTO users (id, name) VALUES (1, 'alice')", [])?;
            Ok(())
        })
        .await
        .unwrap();

        let name: String = pool
            .read(|c| c.query_row("SELECT name FROM users WHERE id = 1", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(name, "alice");

        drop(pool);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn pragmas_applied_per_connection() {
        let path = temp_path("pragma");
        let pool = DbPool::open_with_size(&DbConfig::new(&path), 2).unwrap();
        let fk: u32 = pool
            .read(|c| c.query_row("PRAGMA foreign_keys", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(fk, 1);
        let bt: i64 = pool
            .read(|c| c.query_row("PRAGMA busy_timeout", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(bt, 5000);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn acquire_guard_returns_to_pool_on_drop() {
        let path = temp_path("guard");
        let pool = DbPool::open_with_writes(&DbConfig::new(&path), 2).unwrap();
        pool.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "init",
            "CREATE TABLE t (n INTEGER);",
        )]))
        .await
        .unwrap();

        {
            let _g = pool.acquire().await.unwrap();
            // Stats reflect the checkout.
            let s = pool.stats();
            assert!(s.available_permits < s.max_size);
        }
        // After drop the permit is back.
        let s = pool.stats();
        assert_eq!(s.available_permits, s.max_size);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn max_size_caps_concurrent_acquires() {
        let path = temp_path("cap");
        let pool = DbPool::open_with_size(&DbConfig::new(&path), 2).unwrap();
        let g1 = pool.acquire().await.unwrap();
        let g2 = pool.acquire().await.unwrap();

        // Third must time out trying.
        let third =
            tokio::time::timeout(std::time::Duration::from_millis(120), pool.acquire()).await;
        assert!(third.is_err(), "third acquire should have timed out");

        drop(g1);
        // Now a third succeeds quickly.
        let g3 = tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(g2);
        drop(g3);
        drop(pool);
        let _ = std::fs::remove_file(&path);
    }

    /// Stress: 200 concurrent acquire futures against a pool of 8 —
    /// every future gets its turn, none exceeds the cap, total time
    /// scales with serialization (not catastrophic).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stress_concurrent_acquire_never_exceeds_max_size() {
        let path = temp_path("stress");
        const POOL_SIZE: usize = 8;
        const TASKS: usize = 200;

        let pool =
            std::sync::Arc::new(DbPool::open_with_size(&DbConfig::new(&path), POOL_SIZE).unwrap());

        let max_observed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let in_flight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let start = std::time::Instant::now();
        let mut futs = Vec::with_capacity(TASKS);
        for _ in 0..TASKS {
            let p = pool.clone();
            let maxo = max_observed.clone();
            let infl = in_flight.clone();
            futs.push(tokio::spawn(async move {
                let _g = p.acquire().await.unwrap();
                let cur = infl.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                let prev = maxo.load(std::sync::atomic::Ordering::SeqCst);
                if cur > prev {
                    maxo.store(cur, std::sync::atomic::Ordering::SeqCst);
                }
                // Tiny "work" hold so we actually saturate the pool.
                tokio::time::sleep(std::time::Duration::from_micros(200)).await;
                infl.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }));
        }
        for f in futs {
            f.await.unwrap();
        }
        let elapsed = start.elapsed();

        let observed = max_observed.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            observed <= POOL_SIZE,
            "max concurrent in-flight was {observed}, exceeds pool size {POOL_SIZE}"
        );
        // 200 tasks * 200us hold / 8 slots ≈ 5ms theoretical; allow 5s
        // for everything (spawn overhead, ext lock, runtime variance).
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "pool stress took {elapsed:?}"
        );

        drop(pool);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn writes_and_reads_share_state() {
        let path = temp_path("share");
        let pool = DbPool::open_with_writes(&DbConfig::new(&path), 4).unwrap();
        pool.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "kv",
            "CREATE TABLE kv (k TEXT PRIMARY KEY, v INTEGER);",
        )]))
        .await
        .unwrap();

        for i in 0..10 {
            pool.write(move |c| {
                c.execute(
                    "INSERT INTO kv (k, v) VALUES (?1, ?2)",
                    rusqlite::params![format!("k{i}"), i],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        }
        let n: u32 = pool
            .read(|c| c.query_row("SELECT count(*) FROM kv", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(n, 10);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn default_pool_is_read_only() {
        let path = temp_path("ro");
        let cfg = DbConfig::new(&path);
        let db = crate::Db::open(&cfg).unwrap();
        db.write(|c| {
            c.execute_batch("CREATE TABLE t (n INTEGER); INSERT INTO t VALUES (1);")?;
            Ok(())
        })
        .await
        .unwrap();

        let pool = DbPool::open_with_size(&cfg, 2).unwrap();
        assert!(!pool.allows_writes());
        // Reads work.
        let n: i64 = pool
            .read(|c| c.query_row("SELECT count(*) FROM t", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(n, 1);
        // The write helpers refuse up front.
        let err = pool
            .write(|c| c.execute("INSERT INTO t VALUES (2)", []))
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::ReadOnlyPool("write")), "{err}");
        let err = pool
            .run_migrations(MigrationRunner::new(vec![]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DbError::ReadOnlyPool("run_migrations")),
            "{err}"
        );
        // A write through a checked-out connection fails in SQLite, on
        // the primed connection and on a lazily opened one alike.
        let a = pool.acquire().await.unwrap();
        let b = pool.acquire().await.unwrap();
        for conn in [&a, &b] {
            assert!(conn.execute("INSERT INTO t VALUES (3)", []).is_err());
            assert!(conn.execute_batch("CREATE TABLE u (n INTEGER)").is_err());
        }
        drop((a, b));
        let n: i64 = pool
            .read(|c| c.query_row("SELECT count(*) FROM t", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(n, 1, "nothing was written");
        drop((pool, db));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn opt_in_pool_writes() {
        let path = temp_path("rw");
        let pool = DbPool::open_with_writes(&DbConfig::new(&path), 2).unwrap();
        assert!(pool.allows_writes());
        pool.write(|c| c.execute_batch("CREATE TABLE t (n INTEGER)"))
            .await
            .unwrap();
        {
            let g = pool.acquire().await.unwrap();
            g.execute("INSERT INTO t VALUES (7)", []).unwrap();
        }
        let n: i64 = pool
            .read(|c| c.query_row("SELECT sum(n) FROM t", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(n, 7);
        let _ = std::fs::remove_file(&path);
    }
}
