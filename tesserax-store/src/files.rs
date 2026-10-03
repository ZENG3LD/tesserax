//! Plain files: atomic TOML / JSON writes, a dirty flag for debounced
//! flushes, and [`JsonlAudit`], an append-only JSON-lines audit sink.
//!
//! Atomic writes go tmp + rename: `<name>.<ext>.tmp` is written and synced,
//! then renamed onto `<name>.<ext>`. A reader never observes a partial file
//! (rename is atomic on POSIX filesystems and on NTFS).

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tesserax::{AuditEvent, AuditSink};

use crate::audit::AuditSinkStats;
use crate::sink_worker::SinkWorker;

/// Errors of the file helpers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FilesError {
    /// Filesystem error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// TOML serialization failed.
    #[error("toml serialize: {0}")]
    TomlSer(#[from] toml::ser::Error),
    /// JSON serialization failed.
    #[error("json serialize: {0}")]
    JsonSer(#[from] serde_json::Error),
}

/// Atomic TOML write: serialize, write `<path>.tmp`, sync, rename.
pub fn write_toml_atomic<T: serde::Serialize + ?Sized>(
    path: &Path,
    value: &T,
) -> Result<(), FilesError> {
    let body = toml::to_string_pretty(value)?;
    atomic_write_bytes(path, body.as_bytes())
}

/// Atomic JSON write (pretty-printed).
pub fn write_json_atomic<T: serde::Serialize + ?Sized>(
    path: &Path,
    value: &T,
) -> Result<(), FilesError> {
    let body = serde_json::to_string_pretty(value)?;
    atomic_write_bytes(path, body.as_bytes())
}

fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), FilesError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => format!("{ext}.tmp"),
        None => "tmp".to_owned(),
    });
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Debounced "mark dirty, flush on tick" flag.
///
/// ```
/// use tesserax_store::files::DirtyTracker;
///
/// let dirty = DirtyTracker::new();
/// dirty.mark();                  // state changed
/// if dirty.take_and_clear() {    // on the flush timer
///     // write_json_atomic(&path, &state)?;
/// }
/// assert!(!dirty.is_dirty());
/// ```
#[derive(Debug, Default)]
pub struct DirtyTracker {
    flag: AtomicBool,
}

impl DirtyTracker {
    /// A clean tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the state dirty.
    pub fn mark(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// True if marked since the last [`Self::take_and_clear`].
    pub fn is_dirty(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// Atomic test-and-clear: true if it was dirty.
    pub fn take_and_clear(&self) -> bool {
        self.flag.swap(false, Ordering::AcqRel)
    }
}

/// [`AuditSink`] appending one JSON object per line to a file, on its own
/// writer thread.
///
/// `record` never blocks: events go into a bounded queue with `try_send`;
/// when the disk is slow and the queue is full, the newest event is dropped
/// and counted ([`AuditSinkStats::dropped`]); the first drop logs one
/// `tracing::warn!`, later ones only at power-of-two drop counts. The writer drains the queue in
/// batches and flushes the file after each batch. Each line is the
/// serde form of [`AuditEvent`].
pub struct JsonlAudit {
    worker: SinkWorker<AuditEvent>,
}

impl std::fmt::Debug for JsonlAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonlAudit")
            .field("stats", &self.worker.stats())
            .finish()
    }
}

impl JsonlAudit {
    /// Default queue capacity.
    pub const DEFAULT_CAPACITY: usize = 4096;

    /// Appends to `path` (created with its parent directory if missing).
    pub fn open(path: &Path, capacity: usize) -> Result<Self, FilesError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Self::with_writer(file, capacity)
    }

    /// Appends to any writer (a file, a pipe, a test double).
    pub fn with_writer<W: Write + Send + 'static>(
        writer: W,
        capacity: usize,
    ) -> Result<Self, FilesError> {
        let mut out = BufWriter::new(writer);
        let worker = SinkWorker::spawn(
            "tesserax-audit-jsonl".into(),
            capacity,
            move |batch: &mut Vec<AuditEvent>| {
                let mut write_batch = || -> Result<(), FilesError> {
                    for event in batch.iter() {
                        serde_json::to_writer(&mut out, event)?;
                        out.write_all(b"\n")?;
                    }
                    out.flush()?;
                    Ok(())
                };
                write_batch().map_err(|e| e.to_string())
            },
        )?;
        Ok(Self { worker })
    }

    /// Writer-thread counters.
    pub fn stats(&self) -> AuditSinkStats {
        self.worker.stats()
    }

    /// Waits (up to `timeout`) until every event accepted before this call
    /// is written and flushed. For shutdown and tests.
    pub fn flush(&self, timeout: Duration) -> bool {
        self.worker.flush(timeout)
    }
}

impl AuditSink for JsonlAudit {
    fn record(&self, event: AuditEvent) {
        self.worker.submit(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Sample {
        name: String,
        n: u32,
    }

    fn fixture(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tesserax-store-files-{}-{name}",
            std::process::id()
        ));
        p
    }

    #[test]
    fn toml_roundtrip() {
        let path = fixture("rt.toml");
        let sample = Sample {
            name: "x".into(),
            n: 7,
        };
        write_toml_atomic(&path, &sample).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("name = \"x\""));
        assert!(body.contains("n = 7"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn json_roundtrip() {
        let path = fixture("rt.json");
        let sample = Sample {
            name: "y".into(),
            n: 12,
        };
        write_json_atomic(&path, &sample).unwrap();
        let back: Sample = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back, sample);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tmp_file_is_removed_after_rename() {
        let path = fixture("clean.json");
        let tmp = path.with_extension("json.tmp");
        write_json_atomic(
            &path,
            &Sample {
                name: "a".into(),
                n: 1,
            },
        )
        .unwrap();
        assert!(path.exists());
        assert!(!tmp.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn creates_parent_directory() {
        let root = fixture("nested");
        let path = root.join("sub").join("config.toml");
        let _ = std::fs::remove_dir_all(&root);
        write_toml_atomic(
            &path,
            &Sample {
                name: "z".into(),
                n: 99,
            },
        )
        .unwrap();
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dirty_tracker_mark_then_clear() {
        let d = DirtyTracker::new();
        assert!(!d.is_dirty());
        d.mark();
        assert!(d.is_dirty());
        assert!(d.take_and_clear());
        assert!(!d.is_dirty());
        assert!(!d.take_and_clear());
    }

    #[test]
    fn jsonl_audit_appends_one_line_per_event() {
        let path = fixture("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let sink = JsonlAudit::open(&path, 16).unwrap();
        for i in 0..5u16 {
            sink.record(AuditEvent {
                ts_ms: 1_000 + u64::from(i),
                door: "admin".into(),
                principal: Some("k1".into()),
                client: None,
                verb: "POST".into(),
                target: format!("/items/{i}"),
                status: 200 + i,
            });
        }
        assert!(sink.flush(Duration::from_secs(10)));
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<AuditEvent> = body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[4].target, "/items/4");
        assert_eq!(lines[4].status, 204);
        assert_eq!(sink.stats().written, 5);
        let _ = std::fs::remove_file(&path);
    }
}
