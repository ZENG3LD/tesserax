//! [`Checkpointer`] — a dedicated connection used for NOTHING but
//! `PRAGMA wal_checkpoint`, behind a `tokio::sync::Mutex`.
//!
//! Two measured failure modes of an earlier store justify both its
//! existence and its calling policy:
//!
//! **(a) TRUNCATE must not travel through the writer's queue.** That store
//! used to route its checkpoint through the batch writer's own job
//! queue (`WriteJob::WalTruncate`) so it would serialise with in-flight
//! batches for free. That is exactly backwards for the case that matters:
//! a WAL only grows without bound when the writer cannot keep up, and when
//! the writer cannot keep up its queue is FULL — so the checkpoint queued
//! behind up to 200 000 rows and could not run at the one moment it was
//! needed. Measured on that store before the split: `queued = 200 005`,
//! WAL 1.74 GB, not one checkpoint completed. A separate connection can
//! issue the checkpoint immediately. SQLite arbitrates: TRUNCATE waits for
//! readers and for the write lock, bounded by this connection's own
//! `busy_timeout` ([`crate::read_pool::apply_read_pragmas`], 15 s), and
//! returns `busy = 1` with the frames it managed rather than failing.
//! Serialising with the batch writer was never a correctness requirement —
//! only a convenience.
//!
//! **(b) TRUNCATE must not be the ROUTINE, timer-driven call either.** Its
//! "waits for readers and for the write lock" reads as harmless right up
//! until the wait is long: a live run against an 11 GB store measured an
//! operator's ordinary read query holding the TRUNCATE's writer-lock wait
//! past the writer's own `busy_timeout`; the very next batch commit
//! returned `SQLITE_BUSY`, and the writer poisoned itself 22 minutes into
//! the run. PASSIVE is the SQLite mode built for the routine case: it
//! checkpoints whatever frames it can WITHOUT waiting on any reader or on
//! the write lock, and simply leaves the rest in the log rather than
//! blocking for them. It can never be the cause of a busy writer the way
//! TRUNCATE can, at the cost of sometimes doing less work per call —
//! exactly the trade a routine, frequent, timer-driven call should make.
//!
//! **Policy:** the host calls [`Checkpointer::checkpoint_passive`] on its
//! routine timer, and escalates to [`Checkpointer::checkpoint_truncate`]
//! only when the WAL is MEASURED to actually be large — `frames_in_log`
//! from the PASSIVE return value, or the on-disk `-wal` size — or on an
//! explicit on-demand request (a backup barrier, graceful shutdown).
//! TRUNCATE keeps the job it was actually built for: bounding a WAL that
//! PASSIVE alone cannot keep bounded because it defers to any reader
//! indefinitely (that store's WAL once reached 57.8 GB under a
//! stalled reader, and recovering it on the next start took minutes).

use std::path::Path;

use rusqlite::Connection;

use crate::config::DbConfig;
use crate::db::DbError;
use crate::read_pool::apply_read_pragmas;

/// A connection used for nothing but `PRAGMA wal_checkpoint` — see this
/// module's doc for why it cannot share the writer's queue, and why the
/// routine call is PASSIVE rather than TRUNCATE.
///
/// Not `Clone` on purpose: there is exactly ONE checkpoint connection per
/// store (the mutex serialises concurrent callers).
pub struct Checkpointer {
    conn: tokio::sync::Mutex<Connection>,
}

impl Checkpointer {
    /// Opens its own connection to `path` — a SEPARATE connection from any
    /// writer or [`crate::ReadPool`] the file already has, so a failure
    /// here is a failure to OPEN, not a surprise on the first checkpoint.
    ///
    /// `cache_size_kib` should be the SAME per-connection share the store's
    /// read pool computed for itself — pass
    /// [`crate::ReadPool::per_connection_cache_kib`] when a `ReadPool`
    /// exists, or [`crate::read_pool::per_connection_read_cache_kib`]
    /// against the intended pool size when it does not — rather than a
    /// second, independent constant.
    pub fn open(path: impl AsRef<Path>, cache_size_kib: i64) -> Result<Self, DbError> {
        Self::open_config(&DbConfig::Path(path.as_ref().to_path_buf()), cache_size_kib)
    }

    /// [`Self::open`] for any file-backed [`DbConfig`] — the way to
    /// checkpoint an encrypted store (the key is applied first on this
    /// connection too). An in-memory config is refused: it has no WAL.
    pub fn open_config(cfg: &DbConfig, cache_size_kib: i64) -> Result<Self, DbError> {
        if cfg.is_in_memory() {
            return Err(DbError::NeedsFile("a checkpointer"));
        }
        let conn = cfg.open_connection(false)?;
        apply_read_pragmas(&conn, cache_size_kib)?;
        Ok(Self {
            conn: tokio::sync::Mutex::new(conn),
        })
    }

    /// `PRAGMA wal_checkpoint(PASSIVE)` — the routine checkpoint the host's
    /// timer should call. Checkpoints whatever frames it can WITHOUT
    /// waiting on any reader or on the write lock, and leaves the rest in
    /// the log. See this module's doc, incident (b), for the run that
    /// proved why TRUNCATE must not hold this role.
    ///
    /// Returns `(busy, frames_in_log, frames_checkpointed)` straight from
    /// the pragma. `busy` is always `0` for PASSIVE (it never waits, so it
    /// is never refused), and `frames_in_log` is the read a caller uses to
    /// decide whether to escalate to [`Self::checkpoint_truncate`].
    pub async fn checkpoint_passive(&self) -> Result<(i64, i64, i64), DbError> {
        let conn = self.conn.lock().await;
        conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(DbError::Query)
    }

    /// `PRAGMA wal_checkpoint(TRUNCATE)` — checkpoints and then truncates
    /// the WAL to zero bytes. Waits for readers and for the write lock,
    /// bounded by this connection's own `busy_timeout`, and returns
    /// `busy = 1` with the frames it managed rather than failing.
    ///
    /// Call this ONLY when the WAL is measured to actually be large
    /// (`frames_in_log` from [`Self::checkpoint_passive`], or the `-wal`
    /// file's on-disk size), or on an explicit on-demand request — a backup
    /// barrier, a graceful shutdown. Never on a routine timer: this module's
    /// doc, incident (b), is the run where a timer-driven TRUNCATE poisoned
    /// the writer.
    ///
    /// Returns `(busy, frames_in_log, frames_checkpointed)` straight from
    /// the pragma, identically to [`Self::checkpoint_passive`].
    pub async fn checkpoint_truncate(&self) -> Result<(i64, i64, i64), DbError> {
        let conn = self.conn.lock().await;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(DbError::Query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_pool::{DEFAULT_READ_CACHE_BUDGET_KIB, per_connection_read_cache_kib};
    use std::path::PathBuf;

    fn temp_path(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tesserax_store_checkpointer_{tag}_{}_{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn sidecar(path: &Path, suffix: &str) -> PathBuf {
        let mut s = path.as_os_str().to_os_string();
        s.push(suffix);
        PathBuf::from(s)
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(sidecar(path, "-wal"));
        let _ = std::fs::remove_file(sidecar(path, "-shm"));
    }

    /// A bad path fails AT OPEN, not on the first checkpoint — the same
    /// eager-failure property [`crate::ReadPool::open`] guarantees.
    #[tokio::test]
    async fn open_fails_eagerly_on_an_unopenable_path() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tesserax_store_checkpointer_no_such_dir_{}",
            std::process::id()
        ));
        path.push("nested");
        path.push("db.sqlite");
        let result = Checkpointer::open(
            &path,
            per_connection_read_cache_kib(DEFAULT_READ_CACHE_BUDGET_KIB, 4),
        );
        assert!(
            result.is_err(),
            "a path under a nonexistent directory must fail at open"
        );
    }

    /// The policy this type exists to serve, exercised end to end: PASSIVE
    /// is never busy even with the writer still open, and TRUNCATE — called
    /// once the other connections are gone, exactly as the escalation policy
    /// prescribes — shrinks the WAL file itself.
    #[tokio::test]
    async fn passive_never_busy_and_truncate_after_readers_gone_shrinks_the_wal() {
        let path = temp_path("wal");
        // One plain writer connection seeds a WAL with real frames. ONE
        // transaction: 500 separate commits could cross the 1000-page
        // `wal_autocheckpoint` default and let SQLite checkpoint inline,
        // muddying what this test measures.
        let mut writer = Connection::open(&path).expect("open writer");
        writer
            .pragma_update(None, "journal_mode", "WAL")
            .expect("wal");
        writer
            .execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);")
            .expect("ddl");
        let tx = writer.transaction().expect("begin");
        for i in 0..500 {
            tx.execute("INSERT INTO t (v) VALUES (?1)", [format!("row-{i}")])
                .expect("insert");
        }
        tx.commit().expect("commit");

        let checkpointer = Checkpointer::open(
            &path,
            per_connection_read_cache_kib(DEFAULT_READ_CACHE_BUDGET_KIB, 4),
        )
        .expect("open checkpointer");

        let (busy, frames_in_log, frames_checkpointed) =
            checkpointer.checkpoint_passive().await.expect("passive");
        assert_eq!(busy, 0, "PASSIVE never waits, so it is never refused");
        assert!(
            frames_in_log > 0,
            "fresh writes must sit in the WAL, got frames_in_log={frames_in_log}"
        );
        assert!(frames_checkpointed <= frames_in_log);

        let wal = sidecar(&path, "-wal");
        let wal_before = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
        assert!(
            wal_before > 0,
            "the WAL file must exist and be non-empty before TRUNCATE"
        );

        // TRUNCATE's escalation condition per the module policy: no readers
        // or writers left to wait on, so it completes fully and truncates.
        drop(writer);
        let (busy, _, _) = checkpointer.checkpoint_truncate().await.expect("truncate");
        assert_eq!(
            busy, 0,
            "with no other connection on the file, TRUNCATE is not refused"
        );
        let wal_after = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
        assert!(
            wal_after < wal_before,
            "TRUNCATE must shrink the WAL ({wal_before} -> {wal_after})"
        );

        drop(checkpointer);
        cleanup(&path);
    }
}
