//! Versioned schema migrations.
//!
//! Each `Migration` is a `(version, label, sql)` triple. Versions are
//! `u32` and must be strictly monotonically increasing in the collection
//! handed to [`MigrationRunner`]. The runner keeps a `schema_migrations`
//! table tracking which versions have been applied; re-running is
//! idempotent.
//!
//! Pattern:
//!
//! ```no_run
//! use tesserax_store::{Db, DbConfig, Migration, MigrationRunner};
//!
//! # fn main() -> Result<(), tesserax_store::DbError> {
//! let migrations = vec![
//!     Migration::new(1, "initial", "
//!         CREATE TABLE users (
//!             id INTEGER PRIMARY KEY,
//!             name TEXT NOT NULL
//!         );
//!     "),
//!     Migration::new(2, "add_email", "ALTER TABLE users ADD COLUMN email TEXT;"),
//! ];
//! let db = Db::open(&DbConfig::new("app.db"))?;
//! db.run_migrations_blocking(MigrationRunner::new(migrations))?;
//! # Ok(())
//! # }
//! ```
//!
//! The table name `schema_migrations` and its columns are a frozen on-disk
//! format.

use rusqlite::Connection;
use tracing::info;

/// One schema step: applied once, in version order.
#[derive(Debug, Clone)]
pub struct Migration {
    /// Strictly increasing version number.
    pub version: u32,
    /// Human-readable name, recorded beside the version.
    pub label: String,
    /// SQL batch executed inside the migration transaction.
    pub sql: String,
}

impl Migration {
    /// A migration step.
    pub fn new(version: u32, label: impl Into<String>, sql: impl Into<String>) -> Self {
        Self {
            version,
            label: label.into(),
            sql: sql.into(),
        }
    }
}

/// Applies the pending subset of an ordered migration list.
#[derive(Debug, Clone)]
pub struct MigrationRunner {
    migrations: Vec<Migration>,
}

impl MigrationRunner {
    /// Creates a runner.
    ///
    /// # Panics
    ///
    /// Panics unless versions are strictly increasing, so an ordering
    /// mistake fails loudly at boot.
    pub fn new(migrations: Vec<Migration>) -> Self {
        for w in migrations.windows(2) {
            assert!(
                w[0].version < w[1].version,
                "migrations must be in strictly increasing version order: \
                 v{} ({:?}) ≮ v{} ({:?})",
                w[0].version,
                w[0].label,
                w[1].version,
                w[1].label,
            );
        }
        Self { migrations }
    }

    /// Apply all pending migrations against the connection. Tracks applied
    /// versions in `schema_migrations(version, label, applied_at)`.
    ///
    /// The whole pass runs in one `BEGIN EXCLUSIVE` transaction so two
    /// instances starting concurrently don't race on the
    /// `schema_migrations` table. Loser observes `SQLITE_BUSY` and the
    /// caller retries / accepts that another process is migrating.
    ///
    /// `busy_timeout` is bumped to 30s while we hold the exclusive lock so
    /// the second instance waits rather than failing immediately. The
    /// previous busy_timeout is restored on return.
    pub fn run(self, conn: &mut Connection) -> rusqlite::Result<()> {
        // Save current busy_timeout so we can restore it. Default is 0
        // (no waiting); we want 30s while the exclusive lock is held.
        let prev_busy_ms: i64 = conn
            .query_row("PRAGMA busy_timeout;", [], |r| r.get(0))
            .unwrap_or(0);
        conn.pragma_update(None, "busy_timeout", 30_000)?;

        let result = (|| -> rusqlite::Result<()> {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;

            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                     version INTEGER PRIMARY KEY,
                     label TEXT NOT NULL,
                     applied_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );",
            )?;

            for m in self.migrations {
                let already: Option<u32> = tx
                    .query_row(
                        "SELECT version FROM schema_migrations WHERE version = ?1",
                        [m.version],
                        |r| r.get(0),
                    )
                    .ok();
                if already.is_some() {
                    continue;
                }
                tx.execute_batch(&m.sql)?;
                tx.execute(
                    "INSERT INTO schema_migrations (version, label) VALUES (?1, ?2)",
                    rusqlite::params![m.version, m.label],
                )?;
                info!(version = m.version, label = %m.label, "applied migration");
            }

            tx.commit()?;
            Ok(())
        })();

        // Restore busy_timeout regardless of success / failure.
        let _ = conn.pragma_update(None, "busy_timeout", prev_busy_ms);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    #[should_panic(expected = "strictly increasing")]
    fn out_of_order_panics() {
        let _ = MigrationRunner::new(vec![
            Migration::new(2, "b", "SELECT 1;"),
            Migration::new(1, "a", "SELECT 1;"),
        ]);
    }

    #[test]
    fn applies_migrations_once() {
        let mut conn = mem();
        let runner = MigrationRunner::new(vec![
            Migration::new(1, "users", "CREATE TABLE users (id INTEGER PRIMARY KEY);"),
            Migration::new(
                2,
                "add_name",
                "ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT '';",
            ),
        ]);
        runner.run(&mut conn).unwrap();

        // schema_migrations records both:
        let rows: Vec<(u32, String)> = conn
            .prepare("SELECT version, label FROM schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, vec![(1, "users".into()), (2, "add_name".into())]);

        // users table exists with both columns:
        conn.execute("INSERT INTO users (id, name) VALUES (1, 'alice')", [])
            .unwrap();

        // Re-running the SAME runner is a no-op (idempotent).
        let runner = MigrationRunner::new(vec![
            Migration::new(1, "users", "SELECT 1;"), // sql ignored, version already applied
            Migration::new(2, "add_name", "SELECT 1;"),
        ]);
        runner.run(&mut conn).unwrap();

        let count: u32 = conn
            .query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn appending_new_migration_applies_only_the_new_one() {
        let mut conn = mem();
        MigrationRunner::new(vec![Migration::new(
            1,
            "users",
            "CREATE TABLE users (id INTEGER PRIMARY KEY);",
        )])
        .run(&mut conn)
        .unwrap();

        // Later boot: append a v2.
        MigrationRunner::new(vec![
            Migration::new(1, "users", "SELECT 1;"),
            Migration::new(2, "add_name", "ALTER TABLE users ADD COLUMN name TEXT;"),
        ])
        .run(&mut conn)
        .unwrap();

        let count: u32 = conn
            .query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
}
