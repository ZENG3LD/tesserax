//! `tesserax-store` — SQLite persistence for `tesserax` services.
//!
//! Every write to a store goes through ONE writer; reads go through the
//! writer's own [`Db::read`] or, once they outgrow one connection, through
//! a [`ReadPool`] of independent WAL readers.
//!
//! - [`Db`] / [`DbConfig`]: the writer connection (`Arc<Mutex<Connection>>`),
//!   WAL + `foreign_keys` + the [`WriterPragmaConfig`] budget applied at
//!   open, async helpers that hop to `spawn_blocking`.
//! - [`MigrationRunner`] / [`Migration`]: versioned schema migrations under
//!   `BEGIN EXCLUSIVE`, recorded in `schema_migrations`.
//! - [`BatchWriter`]: fire-and-forget write closures on a bounded queue
//!   (never blocks; [`EnqueueError::Full`] past the bound), one transaction
//!   per batch, one `SAVEPOINT` per operation, [`BatchWriter::barrier`] for
//!   durability points.
//! - [`ReadPool`] / [`ReadPoolConfig`]: N independent read connections under
//!   a semaphore, one total page-cache budget split across them, per-call
//!   deadlines through the connection's interrupt handle, slow-query log and
//!   per-label metrics.
//! - [`Checkpointer`]: a dedicated `wal_checkpoint` connection (PASSIVE as
//!   the routine call, TRUNCATE only on a measured WAL).
//! - [`plan_guard`]: `EXPLAIN QUERY PLAN` assertions for tests.
//! - [`AuditLog`] and [`ChainedAuditSink`]: an append-only, SHA-256
//!   hash-chained audit table with [`AuditLog::verify`]; the sink implements
//!   the root [`tesserax::AuditSink`] and writes on its own thread.
//! - [`files`]: atomic TOML / JSON writes, [`files::DirtyTracker`], and
//!   [`files::JsonlAudit`] (an append-only JSON-lines audit sink on a writer
//!   thread behind a bounded channel).
//!
//! Not in this crate (yet): a `metrics` recorder that persists samples to
//! SQLite. Writing from metrics call sites would run SQLite synchronously
//! inside a business tick, which the contract forbids; it will come later
//! behind its own writer thread (owner ruling 2026-09-30). Until then, use
//! the `tsdb` feature from a task of your own, or an external scraper.
//!
//! SHA-256 comes from `tesserax::ct` (the family's single entry point);
//! BLAKE3 appears only inside two frozen on-disk formats (field-cipher
//! subkeys, time-series ids).
//!
//! # Features
//!
//! - `pool` — `DbPool`, N interchangeable connections with an async
//!   acquire and an RAII guard; read-only (`query_only`) unless opened
//!   with `DbPool::open_with_writes`. Writers use [`Db`].
//! - `cipher-applite` — `FieldCipher`: XChaCha20-Poly1305 per-column
//!   encryption done in application code, keyed by a
//!   `tesserax_secrets::keysource::KeySource`. Plain SQLite build, every
//!   platform.
//! - `cipher-native` — `DbConfig::EncryptedNative`: whole-file SQLCipher
//!   keyed by a `KeySource`; enables `rusqlite/bundled-sqlcipher`, which
//!   links the system libcrypto (OpenSSL headers at build time). Not for
//!   Windows-native builds.
//! - `tsdb` — module `tsdb`: an embedded time-series store (Gorilla-compressed
//!   chunks indexed in its own SQLite file).
//!
//! `cipher-applite` and `cipher-native` are mutually exclusive (a
//! `compile_error!` fires when both are on); never build this crate with
//! `--all-features`.
//!
//! On-disk layout: the table and column names of `audit_log` and
//! `schema_migrations`, the audit chain's genesis hash (64 `0`s) and its
//! `0x1f` field separator, the field-cipher subkey domain
//! `tesserax-field-cipher-v1|` and version byte `0x01`, and the time-series
//! tables `series` / `chunks` with their BLAKE3 series id.
//!
//! # Contract
//!
//! ```text
//! Role:      engine (persistence): every write through one writer; reads through `read` / `ReadPool`
//! Owns:      SQLite connections (one writer, N readers, one checkpointer), the audit chain, the TSDB chunk index,
//!            files it is told to write atomically, the JSONL audit file it appends to.
//! Exports:   Db, DbConfig, DbError, StoreError, Migration, MigrationRunner, BatchWriter, BatchConfig, BatchStats,
//!            EnqueueError, DEFAULT_QUEUE_CAPACITY, WriteOp, ReadPool, ReadPoolConfig, ReadPoolMetrics,
//!            ReadKindMetric, Checkpointer, WriterPragmaConfig,
//!            plan_guard::{assert_uses_index, query_plan}, AuditLog, AuditEntry, AuditRow, AuditVerifyReport,
//!            verify_chain, ChainedAuditSink, AuditSinkStats,
//!            files::{write_toml_atomic, write_json_atomic, DirtyTracker, JsonlAudit, FilesError}, rusqlite (re-export);
//!            feature pool: DbPool, DbConnection, PoolStats; feature cipher-applite: FieldCipher, CipherError;
//!            feature cipher-native: DbConfig::EncryptedNative; cipher features: keysource (re-export);
//!            feature tsdb: tsdb::{Tsdb, SeriesKey, SeriesId, LabelSet, Sample, Retention, Agg, TsdbError}.
//! Imports:   tesserax (no default features; serde), rusqlite (bundled), tokio (rt, sync, time, macros), tracing,
//!            thiserror, serde, serde_json, toml;
//!            cipher features: tesserax-secrets, zeroize; cipher-applite: chacha20poly1305, blake3, getrandom;
//!            tsdb: blake3.
//! Forbidden: axum, tower, reqwest, tesserax-http/-auth/-framework; sqlite called synchronously from a
//!            business tick (Db::*_blocking are for plain threads only); a SHA-256 or compare of its own
//!            (tesserax::ct; BLAKE3 only inside the frozen field-cipher and series-id formats);
//!            `--all-features` (cipher-native ⊥ cipher-applite); any product, host or consumer name.
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(all(feature = "cipher-native", feature = "cipher-applite"))]
compile_error!(
    "`cipher-native` and `cipher-applite` are mutually exclusive: they select different SQLite C builds. \
     Enable at most one."
);

mod audit;
mod batch;
mod config;
mod db;
mod error;
mod migrations;
#[cfg(feature = "pool")]
mod pool;
mod sink_worker;

pub mod checkpoint;
pub mod files;
pub mod plan_guard;
pub mod read_pool;
pub mod writer_pragmas;

#[cfg(feature = "cipher-applite")]
mod field_cipher;

#[cfg(feature = "tsdb")]
pub mod tsdb;

pub use audit::{
    AUDIT_LOG_MIGRATION_SQL, AuditEntry, AuditLog, AuditRow, AuditSinkStats, AuditVerifyReport,
    ChainedAuditSink, verify_chain,
};
pub use batch::{
    BatchConfig, BatchStats, BatchWriter, DEFAULT_QUEUE_CAPACITY, DEFAULT_SLOW_BATCH_THRESHOLD,
    EnqueueError, WriteOp,
};
pub use checkpoint::Checkpointer;
pub use config::DbConfig;
pub use db::{Db, DbError};
pub use error::StoreError;
pub use migrations::{Migration, MigrationRunner};
pub use read_pool::{ReadKindMetric, ReadPool, ReadPoolConfig, ReadPoolMetrics};
pub use writer_pragmas::WriterPragmaConfig;

#[cfg(feature = "pool")]
pub use pool::{DbConnection, DbPool, PoolStats};

#[cfg(feature = "cipher-applite")]
pub use field_cipher::{CipherError, FieldCipher};

/// Key sources for the cipher features, re-exported from
/// `tesserax-secrets` (the family's single definition).
#[cfg(any(feature = "cipher-applite", feature = "cipher-native"))]
pub use tesserax_secrets::keysource;

/// The `rusqlite` this crate is built against, so consumers need no second
/// dependency (and cannot pick a conflicting SQLite build).
pub use rusqlite;
