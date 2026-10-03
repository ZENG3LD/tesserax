//! Append-only audit log with a SHA-256 hash chain, and
//! [`ChainedAuditSink`], the root [`AuditSink`] that writes into it.
//!
//! Each row carries `row_hash = SHA-256(prev_hash || 0x1f || ts || 0x1f ||
//! actor || 0x1f || action || 0x1f || payload)` (hex, lowercase), where
//! `prev_hash` is the previous row's `row_hash` and the first row's
//! `prev_hash` is 64 `0`s. Changing, deleting or reordering any row breaks
//! every later link, and [`AuditLog::verify`] names the first broken row.
//! The ASCII unit separator (`0x1f`) keeps field boundaries unambiguous.
//!
//! Schema (frozen on-disk format — table, columns, genesis and separator are
//! kept byte-identical with earlier releases; `tests/golden.rs` verifies a
//! chain written by the old code):
//!
//! ```sql
//! CREATE TABLE audit_log (
//!   id        INTEGER PRIMARY KEY AUTOINCREMENT,
//!   ts        TEXT NOT NULL,   -- ISO 8601 UTC
//!   actor     TEXT NOT NULL,   -- who acted
//!   action    TEXT NOT NULL,   -- what was done
//!   payload   TEXT NOT NULL,   -- JSON text, hashed exactly as stored
//!   prev_hash TEXT NOT NULL,
//!   row_hash  TEXT NOT NULL
//! );
//! ```
//!
//! Append-only is a contract of the API (there is no update or delete);
//! SQLite cannot enforce row immutability portably, which is exactly what
//! the chain detects. Hashing goes through `tesserax::ct::sha256`, the
//! family's single SHA-256.

use std::time::Duration;

use rusqlite::Connection;
use tesserax::{AuditEvent, AuditSink};

use crate::db::{Db, DbError};
use crate::migrations::Migration;
use crate::sink_worker::SinkWorker;

/// `prev_hash` of the first row.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Field separator inside the hashed body.
const SEP: u8 = 0x1f;

/// SQL creating the `audit_log` table (idempotent). See also
/// [`AuditLog::migration`].
pub const AUDIT_LOG_MIGRATION_SQL: &str = "CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    payload     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    row_hash    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);";

/// One entry to append.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Who acted (key id, user id, `system`).
    pub actor: String,
    /// What was done.
    pub action: String,
    /// Free-form JSON; stored as text (no JSON1 extension needed).
    pub payload: serde_json::Value,
}

impl AuditEntry {
    /// An entry.
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            actor: actor.into(),
            action: action.into(),
            payload,
        }
    }
}

/// A row read back from `audit_log`.
#[derive(Debug, Clone)]
pub struct AuditRow {
    /// Row id (append order).
    pub id: i64,
    /// Timestamp text as stored.
    pub ts: String,
    /// Actor.
    pub actor: String,
    /// Action.
    pub action: String,
    /// Payload parsed as JSON (`Null` if the stored text is not JSON).
    pub payload: serde_json::Value,
    /// Previous row's hash (genesis for the first row).
    pub prev_hash: String,
    /// This row's hash.
    pub row_hash: String,
}

/// Result of [`AuditLog::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyReport {
    /// True when every link recomputes.
    pub is_valid: bool,
    /// Rows examined (up to and including the first broken one).
    pub rows_checked: u64,
    /// Id of the first row whose `prev_hash` or `row_hash` does not
    /// recompute; `None` for an intact (or empty) chain.
    pub first_break: Option<i64>,
}

/// Append-only, hash-chained audit table. Cheap to clone.
#[derive(Clone, Debug)]
pub struct AuditLog {
    db: Db,
}

impl AuditLog {
    /// Audit log in `db`'s `audit_log` table (create it first with
    /// [`AuditLog::migration`] or [`AUDIT_LOG_MIGRATION_SQL`]).
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// The migration creating the table, at the caller's version number.
    pub fn migration(version: u32) -> Migration {
        Migration::new(version, "audit_log", AUDIT_LOG_MIGRATION_SQL)
    }

    /// The underlying store.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Appends one entry (async; the chain advances by one row). Returns the
    /// row id.
    pub async fn append(&self, entry: AuditEntry) -> Result<i64, DbError> {
        let row = PendingRow::from_entry(iso8601_ms(now_ms()), entry);
        self.db
            .write(move |c| append_rows(c, std::slice::from_ref(&row)))
            .await
    }

    /// [`Self::append`] for plain OS threads (panics on a tokio thread).
    pub fn append_blocking(&self, entry: AuditEntry) -> Result<i64, DbError> {
        let row = PendingRow::from_entry(iso8601_ms(now_ms()), entry);
        self.db
            .write_blocking(|c| append_rows(c, std::slice::from_ref(&row)))
            .map_err(DbError::Query)
    }

    /// Rows in append order, at most `limit` of them.
    pub async fn list(&self, limit: Option<u32>) -> Result<Vec<AuditRow>, DbError> {
        self.db.read(move |c| list_rows(c, limit)).await
    }

    /// Walks the chain from genesis and recomputes every link.
    pub async fn verify(&self) -> Result<AuditVerifyReport, DbError> {
        self.db.read(verify_chain).await
    }

    /// [`Self::verify`] for plain OS threads (panics on a tokio thread).
    pub fn verify_blocking(&self) -> Result<AuditVerifyReport, DbError> {
        self.db.read_blocking(verify_chain).map_err(DbError::Query)
    }
}

/// Verifies the chain on any connection to a store holding `audit_log`
/// (e.g. a read-pool connection or an offline copy).
pub fn verify_chain(conn: &Connection) -> rusqlite::Result<AuditVerifyReport> {
    let mut stmt = conn.prepare(
        "SELECT id, ts, actor, action, payload, prev_hash, row_hash FROM audit_log ORDER BY id ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut prev = GENESIS.to_string();
    let mut checked = 0u64;
    let mut first_break = None;
    while let Some(r) = rows.next()? {
        checked += 1;
        let id: i64 = r.get(0)?;
        let ts: String = r.get(1)?;
        let actor: String = r.get(2)?;
        let action: String = r.get(3)?;
        let payload: String = r.get(4)?;
        let prev_hash: String = r.get(5)?;
        let row_hash: String = r.get(6)?;
        let expected = chain_hash(&prev, &ts, &actor, &action, &payload);
        if prev_hash != prev || row_hash != expected {
            first_break = Some(id);
            break;
        }
        prev = row_hash;
    }
    Ok(AuditVerifyReport {
        is_valid: first_break.is_none(),
        rows_checked: checked,
        first_break,
    })
}

struct PendingRow {
    ts: String,
    actor: String,
    action: String,
    payload: String,
}

impl PendingRow {
    fn from_entry(ts: String, entry: AuditEntry) -> Self {
        Self {
            ts,
            actor: entry.actor,
            action: entry.action,
            payload: serde_json::to_string(&entry.payload).unwrap_or_else(|_| "null".into()),
        }
    }

    fn from_event(event: &AuditEvent) -> Self {
        let payload = serde_json::json!({
            "door": event.door,
            "target": event.target,
            "status": event.status,
            "client": event.client,
            "ts_ms": event.ts_ms,
        });
        Self {
            ts: iso8601_ms(event.ts_ms),
            actor: event.principal.clone().unwrap_or_else(|| "-".into()),
            action: event.verb.clone(),
            payload: serde_json::to_string(&payload).unwrap_or_else(|_| "null".into()),
        }
    }
}

/// Appends `rows` in one transaction; the tail hash is read inside the same
/// transaction, so the chain cannot fork. Returns the last row id.
fn append_rows(conn: &mut Connection, rows: &[PendingRow]) -> rusqlite::Result<i64> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut prev: String = match tx.query_row(
        "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get(0),
    ) {
        Ok(h) => h,
        Err(rusqlite::Error::QueryReturnedNoRows) => GENESIS.to_string(),
        Err(e) => return Err(e),
    };
    let mut last_id = 0;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO audit_log (ts, actor, action, payload, prev_hash, row_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for row in rows {
            let hash = chain_hash(&prev, &row.ts, &row.actor, &row.action, &row.payload);
            stmt.execute(rusqlite::params![
                row.ts,
                row.actor,
                row.action,
                row.payload,
                prev,
                hash
            ])?;
            last_id = tx.last_insert_rowid();
            prev = hash;
        }
    }
    tx.commit()?;
    Ok(last_id)
}

fn list_rows(conn: &Connection, limit: Option<u32>) -> rusqlite::Result<Vec<AuditRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, ts, actor, action, payload, prev_hash, row_hash \
         FROM audit_log ORDER BY id ASC LIMIT ?1",
    )?;
    let limit = limit.map(i64::from).unwrap_or(-1);
    stmt.query_map([limit], |r| {
        let payload: String = r.get(4)?;
        Ok(AuditRow {
            id: r.get(0)?,
            ts: r.get(1)?,
            actor: r.get(2)?,
            action: r.get(3)?,
            payload: serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null),
            prev_hash: r.get(5)?,
            row_hash: r.get(6)?,
        })
    })?
    .collect()
}

fn chain_hash(prev: &str, ts: &str, actor: &str, action: &str, payload: &str) -> String {
    let mut body =
        Vec::with_capacity(prev.len() + ts.len() + actor.len() + action.len() + payload.len() + 4);
    for (i, part) in [prev, ts, actor, action, payload].iter().enumerate() {
        if i > 0 {
            body.push(SEP);
        }
        body.extend_from_slice(part.as_bytes());
    }
    hex_lower(&tesserax::ct::sha256(&body))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` from Unix milliseconds (civil-from-days).
pub(crate) fn iso8601_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let sod = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60,
        ms % 1000
    )
}

/// Counters of an audit sink's writer thread.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditSinkStats {
    /// Events taken into the queue.
    pub accepted: u64,
    /// Events durably handed to the store / file.
    pub written: u64,
    /// Events refused because the queue was full or the writer was gone.
    /// The producer never waits; this counter is the price.
    pub dropped: u64,
    /// Accepted events lost because their batch failed to write.
    pub failed: u64,
}

/// [`AuditSink`] that appends every [`AuditEvent`] to the hash-chained
/// [`AuditLog`] on its own writer thread.
///
/// `record` never blocks and never fails: the event goes into a bounded
/// queue with `try_send`; when the queue is full (the store is slow or
/// locked) the newest event is dropped and counted in
/// [`AuditSinkStats::dropped`]. The first drop logs one `tracing::warn!`,
/// later ones only when the drop count reaches a power of two (2, 4, 8,
/// …) — best-effort; the counter is the record.
/// The writer thread appends each drained batch in one transaction.
///
/// Row mapping: `ts` = the event's `ts_ms` as ISO 8601 with milliseconds,
/// `actor` = the principal's key id (or `-`), `action` = the verb, `payload`
/// = `{"client", "door", "status", "target", "ts_ms"}`.
pub struct ChainedAuditSink {
    worker: SinkWorker<AuditEvent>,
    log: AuditLog,
}

impl std::fmt::Debug for ChainedAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainedAuditSink")
            .field("db", &self.log.db.label())
            .field("stats", &self.worker.stats())
            .finish()
    }
}

impl ChainedAuditSink {
    /// Default queue capacity.
    pub const DEFAULT_CAPACITY: usize = 4096;

    /// Starts the writer thread over `db` (whose `audit_log` table must
    /// exist) with a queue of `capacity` events.
    pub fn spawn(db: Db, capacity: usize) -> std::io::Result<Self> {
        let log = AuditLog::new(db);
        let writer_db = log.db.clone();
        let worker = SinkWorker::spawn(
            "tesserax-audit-chain".into(),
            capacity,
            move |batch: &mut Vec<AuditEvent>| {
                let rows: Vec<PendingRow> = batch.iter().map(PendingRow::from_event).collect();
                writer_db
                    .write_blocking(|c| append_rows(c, &rows))
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            },
        )?;
        Ok(Self { worker, log })
    }

    /// Writer-thread counters.
    pub fn stats(&self) -> AuditSinkStats {
        self.worker.stats()
    }

    /// Waits (up to `timeout`) until every event accepted before this call
    /// is written. For shutdown and tests; producers never call it.
    pub fn flush(&self, timeout: Duration) -> bool {
        self.worker.flush(timeout)
    }

    /// The chained log this sink appends to.
    pub fn log(&self) -> &AuditLog {
        &self.log
    }

    /// [`AuditLog::verify`] over this sink's table.
    pub async fn verify(&self) -> Result<AuditVerifyReport, DbError> {
        self.log.verify().await
    }
}

impl AuditSink for ChainedAuditSink {
    fn record(&self, event: AuditEvent) {
        self.worker.submit(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DbConfig;
    use crate::migrations::MigrationRunner;

    async fn fresh_log() -> AuditLog {
        let db = Db::open(&DbConfig::in_memory()).unwrap();
        db.run_migrations(MigrationRunner::new(vec![AuditLog::migration(1)]))
            .await
            .unwrap();
        AuditLog::new(db)
    }

    #[tokio::test]
    async fn append_and_list_in_order() {
        let log = fresh_log().await;
        log.append(AuditEntry::new(
            "alice",
            "login",
            serde_json::json!({"ip": "127.0.0.1"}),
        ))
        .await
        .unwrap();
        log.append(AuditEntry::new(
            "bob",
            "delete",
            serde_json::json!({"path": "/tmp/x"}),
        ))
        .await
        .unwrap();
        let rows = log.list(None).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].actor, "alice");
        assert_eq!(rows[1].actor, "bob");
        assert_eq!(rows[0].prev_hash, GENESIS);
        assert_eq!(rows[1].prev_hash, rows[0].row_hash);
        assert_eq!(log.list(Some(1)).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn verify_intact_chain() {
        let log = fresh_log().await;
        for i in 0..5 {
            log.append(AuditEntry::new(
                "actor",
                format!("act-{i}"),
                serde_json::json!({"i": i}),
            ))
            .await
            .unwrap();
        }
        let report = log.verify().await.unwrap();
        assert!(report.is_valid, "{report:?}");
        assert_eq!(report.rows_checked, 5);
        assert!(report.first_break.is_none());
    }

    #[tokio::test]
    async fn verify_detects_tampered_payload() {
        let log = fresh_log().await;
        for _ in 0..3 {
            log.append(AuditEntry::new("a", "act", serde_json::Value::Null))
                .await
                .unwrap();
        }
        log.db
            .write(|c| {
                c.execute(
                    "UPDATE audit_log SET payload = '\"TAMPERED\"' WHERE id = 2",
                    [],
                )
                .map(|_| ())
            })
            .await
            .unwrap();
        let report = log.verify().await.unwrap();
        assert!(!report.is_valid);
        assert_eq!(report.first_break, Some(2));
    }

    #[tokio::test]
    async fn verify_detects_deleted_row() {
        let log = fresh_log().await;
        for _ in 0..4 {
            log.append(AuditEntry::new("a", "act", serde_json::Value::Null))
                .await
                .unwrap();
        }
        log.db
            .write(|c| {
                c.execute("DELETE FROM audit_log WHERE id = 2", [])
                    .map(|_| ())
            })
            .await
            .unwrap();
        let report = log.verify().await.unwrap();
        assert_eq!(
            report.first_break,
            Some(3),
            "row 3's prev_hash points at the deleted row"
        );
    }

    #[tokio::test]
    async fn empty_log_is_valid() {
        let log = fresh_log().await;
        let report = log.verify().await.unwrap();
        assert!(report.is_valid);
        assert_eq!(report.rows_checked, 0);
    }

    #[test]
    fn chain_hash_matches_the_frozen_layout() {
        // SHA-256 over "prev\x1fts\x1factor\x1faction\x1f{}" computed
        // independently of this crate.
        assert_eq!(
            chain_hash("prev", "ts", "actor", "action", "{}"),
            "da8f1d713685d218fa6b1a2a2492325e3d42e7a651b67001b4eff510a874d7e5"
        );
        assert_ne!(
            chain_hash("prev", "ts", "actor", "action", "{}"),
            chain_hash("prev", "ts", "actor", "action", "{\"x\":1}")
        );
    }

    #[test]
    fn iso8601_ms_shape() {
        assert_eq!(iso8601_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601_ms(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert_eq!(iso8601_ms(1_790_000_000_999), "2026-09-21T14:13:20.999Z");
    }
}
