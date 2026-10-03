//! Storage — SQLite series registry + chunk index, with Gorilla-encoded
//! chunk data stored inline as BLOBs.
//!
//! At the target scale (~thousands of series, tens of MB over 30 days)
//! inline BLOBs in SQLite are simpler than a
//! file-offset index and lose nothing. No 2h-block management, no
//! compaction, no postings file — Prometheus's machinery is for millions
//! of series.
//!
//! ## Write path
//!
//! `record(key, sample)` resolves the [`SeriesId`] (registering it on
//! first sight), appends to an in-RAM open chunk for that series, and
//! flushes the chunk to a `chunks` row when it reaches `chunk_cap`
//! samples (or on [`Tsdb::flush`] / drop). WAL is intentionally skipped:
//! at a 30s cadence an unclean shutdown loses at most one open chunk
//! (≤ ~1h of one series). Acceptable for ops metrics — documented.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, params};

use super::codec::{ChunkCodec, Gorilla};
use super::model::{LabelSet, Sample, SeriesId, SeriesKey};

/// Time-series store failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TsdbError {
    /// The file could not be opened.
    #[error("open {path}: {source}")]
    Open {
        /// Path (or `:memory:`).
        path: String,
        /// SQLite's error.
        source: rusqlite::Error,
    },
    /// SQLite error.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A stored chunk does not decode.
    #[error("codec: {0}")]
    Codec(#[from] super::codec::CodecError),
    /// A thread panicked while holding the store lock.
    #[error("lock poisoned")]
    Lock,
}

/// Default samples per chunk. ~120 matches Gorilla's 2h-at-1min default;
/// at 30s that's ~1h per chunk. The only loss-on-crash window.
pub const DEFAULT_CHUNK_CAP: usize = 120;

/// Soft cap on live series before we warn about cardinality. Far above
/// the target scale; tripping it means a high-cardinality label
/// (request_id, raw ts, unbounded id) leaked into a series name.
pub const DEFAULT_SERIES_SOFT_CAP: usize = 10_000;

/// An open, not-yet-flushed chunk for one series.
struct LiveChunk {
    samples: Vec<Sample>,
}

struct Inner {
    conn: Connection,
    /// SeriesId → label/name registry cache (so we INSERT a series row
    /// only once). Value is whether it's been persisted to `series`.
    known: HashMap<SeriesId, ()>,
    /// SeriesId → open chunk.
    live: HashMap<SeriesId, LiveChunk>,
    chunk_cap: usize,
    series_soft_cap: usize,
    warned_cardinality: bool,
}

/// Embedded time-series store. Cheap to clone is NOT provided — hold one
/// `Tsdb` and share via `Arc<Tsdb>` (its internals are `Mutex`-guarded).
pub struct Tsdb {
    inner: Mutex<Inner>,
}

impl Tsdb {
    /// Open (or create) the store at `path`. Plain SQLite — the file is
    /// the metric index + chunks, not secret material.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TsdbError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path).map_err(|e| TsdbError::Open {
            path: path.display().to_string(),
            source: e,
        })?;
        Self::init(conn)
    }

    /// In-memory store for tests.
    pub fn open_in_memory() -> Result<Self, TsdbError> {
        let conn = Connection::open_in_memory().map_err(|e| TsdbError::Open {
            path: ":memory:".into(),
            source: e,
        })?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, TsdbError> {
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS series (
                series_id   BLOB PRIMARY KEY,
                name        TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                created_ms  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_series_name ON series(name);
            CREATE TABLE IF NOT EXISTS chunks (
                series_id   BLOB NOT NULL,
                t_start_ms  INTEGER NOT NULL,
                t_end_ms    INTEGER NOT NULL,
                sample_cnt  INTEGER NOT NULL,
                data        BLOB NOT NULL,
                PRIMARY KEY (series_id, t_start_ms)
            );
            CREATE INDEX IF NOT EXISTS idx_chunks_time
                ON chunks(series_id, t_start_ms, t_end_ms);
            "#,
        )?;
        // Pre-load the known-series set so we don't re-INSERT on restart.
        let mut known = HashMap::new();
        {
            let mut stmt = conn.prepare("SELECT series_id FROM series")?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            for r in rows {
                let bytes = r?;
                if bytes.len() == 16 {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&bytes);
                    known.insert(SeriesId::from_bytes(b), ());
                }
            }
        }
        Ok(Self {
            inner: Mutex::new(Inner {
                conn,
                known,
                live: HashMap::new(),
                chunk_cap: DEFAULT_CHUNK_CAP,
                series_soft_cap: DEFAULT_SERIES_SOFT_CAP,
                warned_cardinality: false,
            }),
        })
    }

    /// Override the chunk cap (samples per flushed chunk).
    pub fn with_chunk_cap(self, cap: usize) -> Self {
        if let Ok(mut g) = self.inner.lock() {
            g.chunk_cap = cap.max(1);
        }
        self
    }

    /// Record one sample for a series. Registers the series on first
    /// sight; appends to the open chunk; flushes when full.
    pub fn record(&self, key: &SeriesKey, sample: Sample) -> Result<(), TsdbError> {
        let id = key.id();
        let mut g = self.inner.lock().map_err(|_| TsdbError::Lock)?;

        if !g.known.contains_key(&id) {
            let labels_json = serde_json::to_string(&key.labels).unwrap_or_else(|_| "[]".into());
            g.conn.execute(
                "INSERT OR IGNORE INTO series (series_id, name, labels_json, created_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id.to_bytes().to_vec(), key.name, labels_json, sample.ts_ms,],
            )?;
            g.known.insert(id, ());

            // Cardinality guard — warn once when live series cross the cap.
            let soft_cap = g.series_soft_cap;
            if !g.warned_cardinality && g.known.len() > soft_cap {
                g.warned_cardinality = true;
                tracing::warn!(
                    series = g.known.len(),
                    soft_cap,
                    "tsdb live series count crossed the cardinality soft cap — \
                     check for a high-cardinality label (request_id / raw ts / unbounded id)"
                );
            }
        }

        let cap = g.chunk_cap;
        let chunk = g.live.entry(id).or_insert_with(|| LiveChunk {
            samples: Vec::with_capacity(cap),
        });
        chunk.samples.push(sample);

        if chunk.samples.len() >= cap {
            // Take the full chunk out and flush it.
            let full = g.live.remove(&id).expect("just inserted");
            Self::flush_chunk(&g.conn, id, &full.samples)?;
        }
        Ok(())
    }

    /// Flush all open chunks to disk. Call on graceful shutdown and
    /// periodically. Leaves the series' encoder fresh (open chunks are
    /// drained).
    pub fn flush(&self) -> Result<(), TsdbError> {
        let mut g = self.inner.lock().map_err(|_| TsdbError::Lock)?;
        let drained: Vec<(SeriesId, Vec<Sample>)> =
            g.live.drain().map(|(id, c)| (id, c.samples)).collect();
        for (id, samples) in drained {
            if !samples.is_empty() {
                Self::flush_chunk(&g.conn, id, &samples)?;
            }
        }
        Ok(())
    }

    fn flush_chunk(conn: &Connection, id: SeriesId, samples: &[Sample]) -> Result<(), TsdbError> {
        if samples.is_empty() {
            return Ok(());
        }
        let t_start = samples.first().unwrap().ts_ms;
        let t_end = samples.last().unwrap().ts_ms;
        let data = Gorilla::encode(samples);
        conn.execute(
            "INSERT OR REPLACE INTO chunks (series_id, t_start_ms, t_end_ms, sample_cnt, data)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id.to_bytes().to_vec(),
                t_start,
                t_end,
                samples.len() as i64,
                data,
            ],
        )?;
        Ok(())
    }

    // ── read helpers used by query.rs (same crate) ──

    /// Decode all samples for a series overlapping [t0, t1], INCLUDING
    /// the live (un-flushed) chunk, sorted by ts and filtered to window.
    pub(crate) fn read_range(
        &self,
        id: SeriesId,
        t0_ms: i64,
        t1_ms: i64,
    ) -> Result<Vec<Sample>, TsdbError> {
        let g = self.inner.lock().map_err(|_| TsdbError::Lock)?;
        let mut out: Vec<Sample> = Vec::new();

        // Flushed chunks that overlap the window.
        {
            let mut stmt = g.conn.prepare(
                "SELECT data FROM chunks
                 WHERE series_id = ?1 AND t_end_ms >= ?2 AND t_start_ms <= ?3
                 ORDER BY t_start_ms",
            )?;
            let rows = stmt.query_map(params![id.to_bytes().to_vec(), t0_ms, t1_ms], |r| {
                r.get::<_, Vec<u8>>(0)
            })?;
            for r in rows {
                let blob = r?;
                let samples = Gorilla::decode(&blob)?;
                out.extend(samples);
            }
        }

        // The live chunk, if any.
        if let Some(chunk) = g.live.get(&id) {
            out.extend(chunk.samples.iter().copied());
        }

        out.retain(|s| s.ts_ms >= t0_ms && s.ts_ms <= t1_ms);
        out.sort_by_key(|s| s.ts_ms);
        Ok(out)
    }

    /// All series matching a name + partial label matcher.
    pub(crate) fn select_series(
        &self,
        name: &str,
        matchers: &[(String, String)],
    ) -> Result<Vec<SeriesKey>, TsdbError> {
        let g = self.inner.lock().map_err(|_| TsdbError::Lock)?;
        let mut stmt = g
            .conn
            .prepare("SELECT name, labels_json FROM series WHERE name = ?1")?;
        let rows = stmt.query_map(params![name], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (n, labels_json) = r?;
            let labels: LabelSet = serde_json::from_str(&labels_json).unwrap_or_default();
            if labels.matches(matchers) {
                out.push(SeriesKey::new(n, labels));
            }
        }
        Ok(out)
    }

    /// Delete chunks whose newest sample is older than `cutoff_ms`, then
    /// drop now-orphaned series rows. Returns (chunks_deleted,
    /// series_deleted). Used by the retention reaper.
    pub fn evict_before(&self, cutoff_ms: i64) -> Result<(usize, usize), TsdbError> {
        let g = self.inner.lock().map_err(|_| TsdbError::Lock)?;
        let chunks = g
            .conn
            .execute("DELETE FROM chunks WHERE t_end_ms < ?1", params![cutoff_ms])?;
        let series = g.conn.execute(
            "DELETE FROM series WHERE series_id NOT IN (SELECT DISTINCT series_id FROM chunks)",
            [],
        )?;
        Ok((chunks, series))
    }

    /// Count of registered series (for diagnostics / tests).
    pub fn series_count(&self) -> Result<usize, TsdbError> {
        let g = self.inner.lock().map_err(|_| TsdbError::Lock)?;
        let n: i64 = g
            .conn
            .query_row("SELECT COUNT(*) FROM series", [], |r| r.get(0))?;
        Ok(n as usize)
    }
}

impl Drop for Tsdb {
    fn drop(&mut self) {
        // Best-effort flush of open chunks so a clean shutdown loses
        // nothing. Errors are swallowed — nothing to do in drop.
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tsdb::model::SeriesKey;

    fn key() -> SeriesKey {
        SeriesKey::new("cpu_pct", LabelSet::new(vec![("host".into(), "a".into())]))
    }

    #[test]
    fn record_and_read_back_within_open_chunk() {
        let db = Tsdb::open_in_memory().unwrap();
        let k = key();
        for i in 0..10 {
            db.record(
                &k,
                Sample {
                    ts_ms: 1000 + i * 30_000,
                    value: i as f64,
                },
            )
            .unwrap();
        }
        // Still in the open chunk (cap 120) — read_range sees it.
        let got = db.read_range(k.id(), 0, i64::MAX).unwrap();
        assert_eq!(got.len(), 10);
        assert_eq!(got[0].value, 0.0);
        assert_eq!(got[9].value, 9.0);
    }

    #[test]
    fn chunk_flushes_at_cap_and_reads_across_boundary() {
        let db = Tsdb::open_in_memory().unwrap().with_chunk_cap(50);
        let k = key();
        for i in 0..130 {
            db.record(
                &k,
                Sample {
                    ts_ms: 1000 + i * 30_000,
                    value: i as f64,
                },
            )
            .unwrap();
        }
        // 130 samples, cap 50 → 2 flushed chunks (50+50) + 30 live.
        let got = db.read_range(k.id(), 0, i64::MAX).unwrap();
        assert_eq!(got.len(), 130);
        for (i, s) in got.iter().enumerate() {
            assert_eq!(s.value, i as f64);
        }
    }

    #[test]
    fn flush_persists_open_chunk() {
        let db = Tsdb::open_in_memory().unwrap();
        let k = key();
        for i in 0..5 {
            db.record(
                &k,
                Sample {
                    ts_ms: 1000 + i * 30_000,
                    value: i as f64,
                },
            )
            .unwrap();
        }
        db.flush().unwrap();
        let got = db.read_range(k.id(), 0, i64::MAX).unwrap();
        assert_eq!(got.len(), 5);
    }

    #[test]
    fn range_filters_to_window() {
        let db = Tsdb::open_in_memory().unwrap().with_chunk_cap(10);
        let k = key();
        for i in 0..100 {
            db.record(
                &k,
                Sample {
                    ts_ms: i * 1000,
                    value: i as f64,
                },
            )
            .unwrap();
        }
        let got = db.read_range(k.id(), 10_000, 20_000).unwrap();
        assert!(got.iter().all(|s| s.ts_ms >= 10_000 && s.ts_ms <= 20_000));
        assert_eq!(got.first().unwrap().ts_ms, 10_000);
        assert_eq!(got.last().unwrap().ts_ms, 20_000);
    }

    #[test]
    fn series_registered_once() {
        let db = Tsdb::open_in_memory().unwrap();
        let k = key();
        for i in 0..20 {
            db.record(
                &k,
                Sample {
                    ts_ms: i * 1000,
                    value: 1.0,
                },
            )
            .unwrap();
        }
        assert_eq!(db.series_count().unwrap(), 1);
    }

    #[test]
    fn select_by_label_matcher() {
        let db = Tsdb::open_in_memory().unwrap();
        let a = SeriesKey::new("cpu", LabelSet::new(vec![("host".into(), "a".into())]));
        let b = SeriesKey::new("cpu", LabelSet::new(vec![("host".into(), "b".into())]));
        db.record(
            &a,
            Sample {
                ts_ms: 1,
                value: 1.0,
            },
        )
        .unwrap();
        db.record(
            &b,
            Sample {
                ts_ms: 1,
                value: 2.0,
            },
        )
        .unwrap();
        let all = db.select_series("cpu", &[]).unwrap();
        assert_eq!(all.len(), 2);
        let only_a = db
            .select_series("cpu", &[("host".into(), "a".into())])
            .unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].labels.as_slice()[0].1, "a");
    }

    #[test]
    fn evict_before_drops_old_chunks_and_series() {
        let db = Tsdb::open_in_memory().unwrap().with_chunk_cap(5);
        let k = key();
        // 5 old samples (flush to a chunk ending at ts 5000) + 5 recent.
        for i in 0..5 {
            db.record(
                &k,
                Sample {
                    ts_ms: 1000 + i * 1000,
                    value: i as f64,
                },
            )
            .unwrap();
        }
        // chunk flushed (cap 5). Now evict everything before 1_000_000.
        let (chunks, _series) = db.evict_before(1_000_000).unwrap();
        assert_eq!(chunks, 1, "the old chunk should be deleted");
    }

    #[test]
    fn reopen_preserves_known_series() {
        // File-backed: register a series, drop, reopen, confirm it's known
        // (no duplicate INSERT path needed).
        let dir =
            std::env::temp_dir().join(format!("tesserax-store-tsdb-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("reopen.db");
        let k = key();
        {
            let db = Tsdb::open(&path).unwrap();
            db.record(
                &k,
                Sample {
                    ts_ms: 1000,
                    value: 1.0,
                },
            )
            .unwrap();
            db.flush().unwrap();
        }
        {
            let db = Tsdb::open(&path).unwrap();
            assert_eq!(db.series_count().unwrap(), 1);
            // Recording again must not create a duplicate series row.
            db.record(
                &k,
                Sample {
                    ts_ms: 2000,
                    value: 2.0,
                },
            )
            .unwrap();
            assert_eq!(db.series_count().unwrap(), 1);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
