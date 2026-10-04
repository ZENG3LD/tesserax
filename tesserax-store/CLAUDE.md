# tesserax-store

Contract header. The crate docs mirror this block.

```text
Role:      engine (persistence): every write through one writer; reads through `read` / `ReadPool`
Owns:      SQLite connections (one writer, N readers, one checkpointer), the audit chain, the TSDB chunk index,
           files it is told to write atomically, the JSONL audit file it appends to.
Exports:   Db, DbConfig, DbError, StoreError, Migration, MigrationRunner, BatchWriter, BatchConfig, BatchStats,
           EnqueueError, DEFAULT_QUEUE_CAPACITY, WriteOp, ReadPool, ReadPoolConfig, ReadPoolMetrics,
           ReadKindMetric, Checkpointer, WriterPragmaConfig,
           plan_guard::{assert_uses_index, query_plan}, AuditLog, AuditEntry, AuditRow, AuditVerifyReport,
           verify_chain, ChainedAuditSink, AuditSinkStats,
           files::{write_toml_atomic, write_json_atomic, DirtyTracker, JsonlAudit, FilesError}, rusqlite (re-export);
           feature pool: DbPool, DbConnection, PoolStats; feature cipher-applite: FieldCipher, CipherError;
           feature cipher-native: DbConfig::EncryptedNative; cipher features: keysource (re-export);
           feature tsdb: tsdb::{Tsdb, SeriesKey, SeriesId, LabelSet, Sample, Retention, Agg, TsdbError}.
Imports:   tesserax (no default features; serde), rusqlite (bundled), tokio (rt, sync, time, macros), tracing,
           thiserror, serde, serde_json, toml;
           cipher features: tesserax-secrets, zeroize; cipher-applite: chacha20poly1305, blake3, getrandom;
           tsdb: blake3.
Forbidden: axum, tower, reqwest, tesserax-http/-auth/-framework; sqlite called synchronously from a
           business tick (Db::*_blocking are for plain threads only); a SHA-256 or compare of its own
           (tesserax::ct; BLAKE3 only inside the frozen field-cipher and series-id formats);
           `--all-features` (cipher-native ⊥ cipher-applite); any product, host or consumer name.
```
