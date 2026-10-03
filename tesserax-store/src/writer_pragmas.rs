//! Explicit pragma budget for the SINGLE writer connection — [`crate::Db`]
//! and, through it, [`crate::BatchWriter`] (same physical connection, same
//! mutex). Mirrors [`crate::read_pool::apply_read_pragmas`] on the write
//! side: one function, applied once at open, so no writer-shaped connection
//! anywhere in a consumer silently runs on SQLite's own defaults
//! (`cache_size` 2 MiB, `busy_timeout` 0 — i.e. `SQLITE_BUSY` immediately
//! on any contention at all, `wal_autocheckpoint` 1000 pages run inline on
//! whichever commit happens to cross it).
//!
//! [`Db::open`](crate::Db::open) applies [`WriterPragmaConfig::default`]
//! automatically; [`Db::open_with_writer_pragmas`](crate::Db::open_with_writer_pragmas)
//! is the escape hatch for a consumer whose write pattern genuinely
//! differs from the defaults' own assumptions (see each field's doc).

use rusqlite::Connection;

use crate::db::DbError;
use crate::read_pool::READ_BUSY_TIMEOUT_MS;

/// Writer-side page-cache budget, in the negative-KiB form `cache_size`
/// wants (matches [`crate::read_pool`]'s own sign convention, so a
/// consumer never has to remember two conventions for the same pragma).
///
/// 32 MiB: the writer is ONE connection doing mostly sequential
/// inserts/updates — under [`crate::BatchWriter`] it is a single
/// transaction per batch — not the N-way point-lookup traffic
/// [`crate::ReadPool`] budgets 1 GiB total for
/// ([`crate::read_pool::DEFAULT_READ_CACHE_BUDGET_KIB`]). A large private
/// cache buys little here, and every KiB of it sits on top of, not shared
/// with, the read pool's own budget on the same host that constant's doc
/// sizes against (an 8 GiB box).
pub const DEFAULT_WRITER_CACHE_KIB: i64 = -32 * 1024;

/// Bytes the WAL file may grow to before `PRAGMA journal_size_limit`
/// forces it back down after the next checkpoint.
///
/// 1 GiB: a backstop against the exact failure [`crate::checkpoint`]'s own
/// doc measures — a WAL that reached 57.8 GB under a stalled reader before
/// this crate had any bound on it at all, and took minutes to recover on
/// the next start. A store routinely anywhere near this limit has a
/// checkpointing problem to fix, not a limit to raise.
pub const DEFAULT_JOURNAL_SIZE_LIMIT_BYTES: i64 = 1024 * 1024 * 1024;

/// WAL pages the writer's OWN built-in auto-checkpoint waits for before it
/// runs a PASSIVE checkpoint inline on whichever commit crosses the
/// threshold. SQLite's own default page size is 4 KiB, so SQLite's own
/// default of 1000 pages is roughly 4 MiB — aggressive enough that on a
/// busy writer it fires on a meaningful fraction of commits.
///
/// Set 4x higher here (roughly 16 MiB) so it acts as a BACKSTOP, not the
/// routine mechanism: the intended routine mechanism is
/// [`crate::Checkpointer::checkpoint_passive`] on the host's own timer,
/// off the writer's hot path entirely. If a consumer never wires a
/// `Checkpointer`, this backstop still bounds WAL growth on its own; if
/// they do (recommended — see [`crate::checkpoint`]'s own doc), the
/// backstop essentially never fires because the timer's PASSIVE
/// checkpoint already ran first. That is the "don't double-checkpoint"
/// coordination this module's own top doc promises. Set to `0` to hand
/// checkpointing over to a wired `Checkpointer` entirely.
pub const DEFAULT_WAL_AUTOCHECKPOINT_PAGES: i64 = 4_000;

/// Explicit pragma set for the single writer connection. Every field is an
/// independent knob a consumer can retune without touching the others —
/// see [`Db::open_with_writer_pragmas`](crate::Db::open_with_writer_pragmas).
#[derive(Clone, Copy, Debug)]
pub struct WriterPragmaConfig {
    /// Milliseconds the writer waits on `SQLITE_BUSY` before giving up.
    ///
    /// Defaulted to the SAME bound [`crate::read_pool::apply_read_pragmas`]
    /// gives every reader and [`crate::Checkpointer`]'s own connection —
    /// symmetric waits mean neither side can out-wait the other and starve
    /// it. The asymmetry this crate shipped with before this fix (writer
    /// `busy_timeout` unset, i.e. `0` — instant failure — against the
    /// checkpointer's 15s wait) is what [`crate::checkpoint`]'s own doc,
    /// incident (b), blames for poisoning the writer with `SQLITE_BUSY`
    /// 22 minutes into a run.
    pub busy_timeout_ms: i64,
    /// This connection's own page-cache budget, negative-KiB form. See
    /// [`DEFAULT_WRITER_CACHE_KIB`].
    pub cache_size_kib: i64,
    /// `PRAGMA journal_size_limit`, in bytes. See
    /// [`DEFAULT_JOURNAL_SIZE_LIMIT_BYTES`].
    pub journal_size_limit_bytes: i64,
    /// `PRAGMA wal_autocheckpoint`, in WAL pages. See
    /// [`DEFAULT_WAL_AUTOCHECKPOINT_PAGES`].
    pub wal_autocheckpoint_pages: i64,
}

impl Default for WriterPragmaConfig {
    fn default() -> Self {
        Self {
            busy_timeout_ms: READ_BUSY_TIMEOUT_MS,
            cache_size_kib: DEFAULT_WRITER_CACHE_KIB,
            journal_size_limit_bytes: DEFAULT_JOURNAL_SIZE_LIMIT_BYTES,
            wal_autocheckpoint_pages: DEFAULT_WAL_AUTOCHECKPOINT_PAGES,
        }
    }
}

/// Applies [`WriterPragmaConfig`] to a WAL-mode writer connection, plus one
/// pragma that is NOT a config field: `synchronous = NORMAL`.
///
/// `synchronous` is hardcoded rather than a toggle because under WAL mode
/// it is the documented, durable-enough production setting — sqlite.org's
/// own guarantee: "WAL mode is always consistent with
/// `synchronous=NORMAL`". A crash or power loss right after a NORMAL-mode
/// commit can, in the worst case, roll that last commit back on recovery
/// (the WAL's own per-frame checksum detects a torn/unsynced tail frame
/// and discards it rather than trusting it), but it can never leave the
/// database file itself corrupt — the guarantee `FULL` adds on top is
/// "no committed transaction is ever lost", at an fsync-per-commit latency
/// cost most services do not need to pay. A consumer that genuinely
/// needs `FULL` sets it explicitly with its own `conn.pragma_update` after
/// open — deliberately not exposed as a field here, so that stronger
/// guarantee is always something asked for on purpose, never opted out of
/// by omission.
pub fn apply_writer_pragmas(conn: &Connection, cfg: &WriterPragmaConfig) -> Result<(), DbError> {
    conn.pragma_update(None, "busy_timeout", cfg.busy_timeout_ms)
        .map_err(DbError::Pragma)?;
    conn.pragma_update(None, "cache_size", cfg.cache_size_kib)
        .map_err(DbError::Pragma)?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(DbError::Pragma)?;
    conn.pragma_update(None, "journal_size_limit", cfg.journal_size_limit_bytes)
        .map_err(DbError::Pragma)?;
    conn.pragma_update(None, "wal_autocheckpoint", cfg.wal_autocheckpoint_pages)
        .map_err(DbError::Pragma)?;
    Ok(())
}
