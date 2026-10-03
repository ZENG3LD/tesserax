//! `ChainedAuditSink`: events recorded through the root `AuditSink` land in
//! the hash chain, `verify()` passes, a tampered row is found, and a slow
//! (locked) store never blocks the producer.

mod common;

use std::time::{Duration, Instant};

use tesserax::{AuditEvent, AuditSink};
use tesserax_store::{AuditLog, ChainedAuditSink, Db, DbConfig, MigrationRunner};

fn event(i: u64) -> AuditEvent {
    AuditEvent {
        ts_ms: 1_790_000_000_000 + i,
        door: "admin".into(),
        principal: if i.is_multiple_of(2) {
            Some(format!("key-{i}"))
        } else {
            None
        },
        client: Some("127.0.0.1".into()),
        verb: "POST".into(),
        target: format!("/items/{i}"),
        status: 200,
    }
}

fn open_store(tag: &str) -> (Db, std::path::PathBuf) {
    let path = common::temp_path(tag);
    let db = Db::open(&DbConfig::new(&path)).unwrap();
    // `blocking` takes the free lock without waiting, so it is fine on a
    // runtime thread too.
    db.blocking(|c| MigrationRunner::new(vec![AuditLog::migration(1)]).run(c))
        .unwrap();
    (db, path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recorded_events_form_a_valid_chain_and_tampering_is_found() {
    let (db, path) = open_store("chain");
    let sink = ChainedAuditSink::spawn(db.clone(), 1024).unwrap();
    let as_sink: &dyn AuditSink = &sink;
    for i in 0..300 {
        as_sink.record(event(i));
    }
    assert!(sink.flush(Duration::from_secs(10)));
    let stats = sink.stats();
    assert_eq!(stats.accepted, 300);
    assert_eq!(stats.written, 300);
    assert_eq!(stats.dropped, 0);

    let report = sink.verify().await.unwrap();
    assert!(report.is_valid, "{report:?}");
    assert_eq!(report.rows_checked, 300);

    let rows = sink.log().list(Some(2)).await.unwrap();
    assert_eq!(rows[0].actor, "key-0");
    assert_eq!(rows[1].actor, "-");
    assert_eq!(rows[0].action, "POST");
    assert_eq!(rows[0].payload["target"], "/items/0");
    assert_eq!(rows[0].ts, "2026-09-21T14:13:20.000Z");

    db.write(|c| {
        c.execute("UPDATE audit_log SET payload = '{}' WHERE id = 150", [])
            .map(|_| ())
    })
    .await
    .unwrap();
    let report = sink.verify().await.unwrap();
    assert!(!report.is_valid);
    assert_eq!(report.first_break, Some(150));

    drop(sink);
    drop(db);
    common::cleanup(&path);
}

#[test]
fn a_locked_store_never_blocks_the_producer() {
    let (db, path) = open_store("locked");
    let sink = ChainedAuditSink::spawn(db.clone(), 64).unwrap();

    // Hold the writer lock for a while: the sink's writer thread stalls.
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let holder = {
        let db = db.clone();
        std::thread::spawn(move || {
            db.write_blocking(|_c| {
                locked_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(600));
                Ok(())
            })
            .unwrap();
        })
    };
    locked_rx.recv().unwrap();

    const N: u64 = 20_000;
    let started = Instant::now();
    let mut slowest = Duration::ZERO;
    for i in 0..N {
        let t = Instant::now();
        sink.record(event(i));
        slowest = slowest.max(t.elapsed());
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(400),
        "producer took {elapsed:?} while the store was locked"
    );
    assert!(
        slowest < Duration::from_millis(50),
        "one record() call took {slowest:?}"
    );

    let during = sink.stats();
    assert_eq!(during.accepted + during.dropped, N);
    assert!(
        during.dropped > 0,
        "a 64-slot queue against a locked store must drop"
    );

    holder.join().unwrap();
    assert!(sink.flush(Duration::from_secs(10)));
    let after = sink.stats();
    assert_eq!(after.written, after.accepted);
    assert_eq!(after.failed, 0);
    let report = sink.log().verify_blocking().unwrap();
    assert!(report.is_valid);
    assert_eq!(report.rows_checked, after.written);

    drop(sink);
    drop(db);
    common::cleanup(&path);
}
