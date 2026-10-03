# tesserax-store

SQLite persistence for services built with `tesserax`. Every write goes through one writer connection (`Db`), with a `BatchWriter` for hot writes (one transaction per batch, one savepoint per operation, durability barrier) and a `ReadPool` of independent WAL readers for reads that outgrow it (shared page-cache budget, per-call deadlines, slow-query metrics). A dedicated `Checkpointer`, versioned migrations, explicit writer pragmas and `EXPLAIN QUERY PLAN` test guards are included.

`AuditLog` is an append-only, SHA-256 hash-chained audit table with `verify()`; `ChainedAuditSink` and `files::JsonlAudit` implement the `tesserax::AuditSink` trait on their own writer threads behind bounded queues, so recording an event never blocks (full queue: the event is dropped and counted). `files` also has atomic TOML/JSON writes and a dirty flag.

Features: `pool` (interchangeable connection pool), `cipher-applite` (per-column XChaCha20-Poly1305 field cipher), `cipher-native` (whole-file SQLCipher; needs OpenSSL headers, not for Windows-native builds), `tsdb` (embedded time-series store with Gorilla-compressed chunks). The two cipher features are mutually exclusive, so do not build with `--all-features`.

Licensed under either of MIT or Apache-2.0, at your option.
