//! [`Db`] — the single writer connection of a store.
//!
//! One physical connection behind one mutex. SQLite serialises writers at
//! the file level anyway (WAL admits N readers and one writer), so a second
//! writer connection buys contention, not throughput. Reads that outgrow
//! this one connection move to a [`crate::ReadPool`]; hot writes move to a
//! [`crate::BatchWriter`] over this same connection.
//!
//! [`Db::read`] and [`Db::write`] hop to `tokio::task::spawn_blocking`, so
//! async handlers never park the runtime on SQLite. The `*_blocking`
//! methods are for plain OS threads (batch worker, audit writer, sync
//! binaries); called on a tokio worker thread they panic by design.

use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use tokio::sync::Mutex;
use tracing::info;

use crate::config::DbConfig;
use crate::migrations::MigrationRunner;
use crate::writer_pragmas::{WriterPragmaConfig, apply_writer_pragmas};

/// Errors of the SQLite layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DbError {
    /// The database file could not be opened.
    #[error("open {path}: {source}")]
    Open {
        /// The path (or `:memory:`).
        path: String,
        /// SQLite's error.
        source: rusqlite::Error,
    },
    /// A pragma applied at open failed.
    #[error("pragma init: {0}")]
    Pragma(rusqlite::Error),
    /// A migration failed; nothing of the pass was committed.
    #[error("migration: {0}")]
    Migration(rusqlite::Error),
    /// A query failed.
    #[error("query: {0}")]
    Query(#[from] rusqlite::Error),
    /// The blocking worker panicked or was cancelled.
    #[error("worker panicked: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// Pool checkout / construction failure.
    #[error("pool: {0}")]
    Pool(String),
    /// A write helper (named here) was called on a read-only `DbPool`
    /// (feature `pool`); writes go through [`Db`], or open the pool with
    /// `DbPool::open_with_writes`.
    #[error("{0} on a read-only pool: write through Db, or open the pool with open_with_writes")]
    ReadOnlyPool(&'static str),
    /// A read ran past its deadline and was interrupted. The connection is
    /// unharmed (SQLite's `sqlite3_interrupt()` contract) and is already
    /// back in the pool when this error reaches the caller.
    #[error("read '{label}' exceeded its deadline after {elapsed:?}")]
    Deadline {
        /// Call-site label of the read.
        label: String,
        /// Time from checkout to the interrupt taking effect.
        elapsed: Duration,
    },
    /// The operation needs a file-backed store and was given `:memory:`.
    #[error("{0} needs a file-backed store")]
    NeedsFile(&'static str),
    /// The file is not a database under the given key (wrong key, or a
    /// plaintext / foreign file opened as encrypted).
    #[error("file is not a database (wrong key or not a SQLite file)")]
    NotADatabase,
    /// The key source failed to produce a key.
    #[cfg(feature = "cipher-native")]
    #[error("key source: {0}")]
    KeySource(#[from] tesserax_secrets::keysource::KeySourceError),
}

/// Cheaply clonable handle to the writer connection. Clones share the one
/// connection and its mutex.
#[derive(Clone)]
pub struct Db {
    inner: Arc<Mutex<Connection>>,
    label: Arc<str>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").field("label", &self.label).finish()
    }
}

impl Db {
    /// Opens the store: key first (encrypted configs), then `journal_mode =
    /// WAL`, the default writer pragma budget ([`WriterPragmaConfig`]) and
    /// `foreign_keys = ON`. Does NOT run migrations — see
    /// [`Self::run_migrations`].
    pub fn open(cfg: &DbConfig) -> Result<Self, DbError> {
        Self::open_with_writer_pragmas(cfg, &WriterPragmaConfig::default())
    }

    /// [`Self::open`] with a caller-chosen writer pragma budget.
    pub fn open_with_writer_pragmas(
        cfg: &DbConfig,
        pragmas: &WriterPragmaConfig,
    ) -> Result<Self, DbError> {
        let conn = cfg.open_connection(true)?;
        let label = cfg.label();

        // WAL and the rest of the writer budget only mean something for a
        // file; `busy_timeout` and `cache_size` are per-connection either way.
        if !cfg.is_in_memory() {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(DbError::Pragma)?;
            apply_writer_pragmas(&conn, pragmas)?;
        } else {
            conn.pragma_update(None, "busy_timeout", pragmas.busy_timeout_ms)
                .map_err(DbError::Pragma)?;
            conn.pragma_update(None, "cache_size", pragmas.cache_size_kib)
                .map_err(DbError::Pragma)?;
        }
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(DbError::Pragma)?;

        info!(path = %label, "db opened");
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
            label: Arc::from(label.as_str()),
        })
    }

    /// The store's label (path, `:memory:`, or path + `(encrypted)`).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Applies pending migrations off the async runtime.
    pub async fn run_migrations(&self, runner: MigrationRunner) -> Result<(), DbError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.blocking_lock();
            runner.run(&mut guard)
        })
        .await?
        .map_err(DbError::Migration)
    }

    /// Applies pending migrations on the calling (non-async) thread. Waits
    /// for the writer lock.
    pub fn run_migrations_blocking(&self, runner: MigrationRunner) -> Result<(), DbError> {
        let mut guard = self.inner.blocking_lock();
        runner.run(&mut guard).map_err(DbError::Migration)
    }

    /// Runs `f` with a shared reference to the connection under
    /// `spawn_blocking`.
    pub async fn read<F, T>(&self, f: F) -> Result<T, DbError>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let guard = inner.blocking_lock();
            f(&guard)
        })
        .await?
        .map_err(DbError::Query)
    }

    /// Runs `f` with a mutable reference (it may open its own transaction)
    /// under `spawn_blocking`.
    pub async fn write<F, T>(&self, f: F) -> Result<T, DbError>
    where
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.blocking_lock();
            f(&mut guard)
        })
        .await?
        .map_err(DbError::Query)
    }

    /// Runs `f` only if the writer lock is free right now.
    ///
    /// # Panics
    ///
    /// Panics when the lock is held (use [`Self::write_blocking`] to wait,
    /// or [`Self::write`] in async code).
    pub fn blocking<F, T>(&self, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&mut Connection) -> rusqlite::Result<T>,
    {
        let mut guard = self.inner.try_lock().expect(
            "Db::blocking called while the writer lock is held; use write_blocking or write",
        );
        f(&mut guard)
    }

    /// Blocking read for plain OS threads: waits on the writer lock.
    ///
    /// # Panics
    ///
    /// Panics when called on a tokio runtime thread.
    pub fn read_blocking<F, T>(&self, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T>,
    {
        let guard = self.inner.blocking_lock();
        f(&guard)
    }

    /// Blocking write for plain OS threads: waits on the writer lock.
    ///
    /// # Panics
    ///
    /// Panics when called on a tokio runtime thread.
    pub fn write_blocking<F, T>(&self, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&mut Connection) -> rusqlite::Result<T>,
    {
        let mut guard = self.inner.blocking_lock();
        f(&mut guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migration;

    fn mem_db() -> Db {
        Db::open(&DbConfig::in_memory()).unwrap()
    }

    fn temp_file(tag: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tesserax-store-db-{tag}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        path
    }

    fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[tokio::test]
    async fn in_memory_open_and_pragmas() {
        let db = mem_db();
        let fk: u32 = db
            .read(|c| c.query_row("PRAGMA foreign_keys;", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(fk, 1);
        assert_eq!(db.label(), ":memory:");
    }

    #[tokio::test]
    async fn read_and_write_helpers_roundtrip() {
        let db = mem_db();
        db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "users",
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);",
        )]))
        .await
        .unwrap();

        db.write(|c| {
            c.execute("INSERT INTO users (id, name) VALUES (1, 'alice')", [])?;
            c.execute("INSERT INTO users (id, name) VALUES (2, 'bob')", [])?;
            Ok(())
        })
        .await
        .unwrap();

        let names: Vec<String> = db
            .read(|c| {
                c.prepare("SELECT name FROM users ORDER BY id")?
                    .query_map([], |r| r.get::<_, String>(0))?
                    .collect()
            })
            .await
            .unwrap();
        assert_eq!(names, vec!["alice".to_owned(), "bob".to_owned()]);
    }

    #[tokio::test]
    async fn file_open_creates_parent_dir() {
        let root = temp_file("nested");
        let path = root.join("nested").join("dir").join("app.db");
        let _ = std::fs::remove_dir_all(&root);

        let db = Db::open(&DbConfig::new(&path)).unwrap();
        db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "init",
            "CREATE TABLE t (n INTEGER);",
        )]))
        .await
        .unwrap();
        db.write(|c| c.execute("INSERT INTO t VALUES (42)", []).map(|_| ()))
            .await
            .unwrap();
        drop(db);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn blocking_helpers_work_off_runtime() {
        let db = mem_db();
        db.run_migrations_blocking(MigrationRunner::new(vec![Migration::new(
            1,
            "t",
            "CREATE TABLE t (n INTEGER);",
        )]))
        .unwrap();
        db.write_blocking(|c| c.execute("INSERT INTO t VALUES (1)", []).map(|_| ()))
            .unwrap();
        let n: i64 = db
            .read_blocking(|c| c.query_row("SELECT count(*) FROM t", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(n, 1);
        let n: i64 = db
            .blocking(|c| c.query_row("SELECT count(*) FROM t", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(n, 1);
    }

    /// Every pragma the default budget states is applied and reads back.
    #[tokio::test]
    async fn writer_pragmas_are_applied_and_read_back() {
        let path = temp_file("writer-pragmas");
        let defaults = WriterPragmaConfig::default();
        let db = Db::open(&DbConfig::new(&path)).unwrap();

        let q = |sql: &'static str| {
            let db = db.clone();
            async move {
                db.read(move |c| c.query_row(sql, [], |r| r.get::<_, i64>(0)))
                    .await
                    .unwrap()
            }
        };
        assert_eq!(q("PRAGMA busy_timeout").await, defaults.busy_timeout_ms);
        assert_eq!(q("PRAGMA cache_size").await, defaults.cache_size_kib);
        assert_eq!(q("PRAGMA synchronous").await, 1, "NORMAL reports as 1");
        assert_eq!(
            q("PRAGMA journal_size_limit").await,
            defaults.journal_size_limit_bytes
        );
        assert_eq!(
            q("PRAGMA wal_autocheckpoint").await,
            defaults.wal_autocheckpoint_pages
        );
        let mode: String = db
            .read(|c| c.query_row("PRAGMA journal_mode", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(mode, "wal");

        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn open_with_writer_pragmas_applies_a_caller_chosen_budget() {
        let path = temp_file("writer-pragmas-custom");
        let custom = WriterPragmaConfig {
            busy_timeout_ms: 1_234,
            cache_size_kib: -4_096,
            journal_size_limit_bytes: 16 * 1024 * 1024,
            wal_autocheckpoint_pages: 500,
        };
        let db = Db::open_with_writer_pragmas(&DbConfig::new(&path), &custom).unwrap();
        let busy: i64 = db
            .read(|c| c.query_row("PRAGMA busy_timeout", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(busy, 1_234);
        let cache: i64 = db
            .read(|c| c.query_row("PRAGMA cache_size", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(cache, -4_096);
        drop(db);
        cleanup(&path);
    }
}
