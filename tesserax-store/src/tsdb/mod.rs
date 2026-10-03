//! Embedded, push-native, single-node time-series store (feature `tsdb`).
//!
//! Persists metric history so a service keeps its own series without an
//! external time-series server. Collection and rendering live elsewhere;
//! this module is the storage and query engine in between.
//!
//! - [`model`] — series identity (`name + labels → SeriesId`), [`Sample`].
//! - [`codec`] — Gorilla chunk compression (delta-of-delta + XOR floats).
//! - [`Tsdb`] — SQLite series registry + chunk index, chunks stored inline
//!   as BLOBs, in its own file (its own single writer).
//! - Queries — range, window aggregate ([`Agg`]), counter `rate()`.
//! - [`Retention`] — one-shot eviction sweep; scheduling is the caller's.
//!
//! Sized for thousands of series (tens of MB over a 30-day retention); no
//! block management, no compaction.
//!
//! Frozen on-disk format: tables `series` / `chunks`, the Gorilla chunk
//! encoding, and the BLAKE3-derived 128-bit [`SeriesId`] — files written by
//! earlier releases open and query unchanged (`tests/golden.rs`).

pub mod codec;
pub mod model;
mod query;
mod retention;
mod store;

pub use codec::{ChunkCodec, CodecError, Gorilla};
pub use model::{LabelSet, Sample, SeriesId, SeriesKey};
pub use query::Agg;
pub use retention::Retention;
pub use store::{DEFAULT_CHUNK_CAP, DEFAULT_SERIES_SOFT_CAP, Tsdb, TsdbError};
