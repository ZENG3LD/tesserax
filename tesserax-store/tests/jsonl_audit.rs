//! `JsonlAudit`: a slow disk never blocks the producer — the bounded queue
//! fills, further events are dropped and counted, and everything accepted
//! is written once the disk catches up.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tesserax::{AuditEvent, AuditSink};
use tesserax_store::files::JsonlAudit;

/// A writer that takes `delay` for every write and flush, recording bytes.
#[derive(Clone)]
struct SlowDisk {
    delay: Duration,
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for SlowDisk {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::thread::sleep(self.delay);
        self.bytes.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::thread::sleep(self.delay);
        Ok(())
    }
}

fn event(i: u64) -> AuditEvent {
    AuditEvent {
        ts_ms: i,
        door: "public".into(),
        principal: None,
        client: None,
        verb: "GET".into(),
        target: format!("/r/{i}"),
        status: 200,
    }
}

#[test]
fn slow_disk_never_blocks_the_producer_and_drops_are_counted() {
    let disk = SlowDisk {
        delay: Duration::from_millis(100),
        bytes: Arc::new(Mutex::new(Vec::new())),
    };
    let sink = JsonlAudit::with_writer(disk.clone(), 32).unwrap();

    const N: u64 = 10_000;
    let started = Instant::now();
    let mut slowest = Duration::ZERO;
    for i in 0..N {
        let t = Instant::now();
        sink.record(event(i));
        slowest = slowest.max(t.elapsed());
    }
    let elapsed = started.elapsed();
    // One disk write alone takes 100 ms; the whole producer loop must not
    // wait for even one of them.
    assert!(
        elapsed < Duration::from_millis(100),
        "producer took {elapsed:?} against a slow disk"
    );
    assert!(
        slowest < Duration::from_millis(20),
        "one record() call took {slowest:?}"
    );

    let stats = sink.stats();
    assert_eq!(stats.accepted + stats.dropped, N);
    assert!(
        stats.dropped > 0,
        "a 32-slot queue against a 100 ms disk must drop"
    );
    assert!(
        stats.accepted < N / 10,
        "only the queue and the batch in flight were accepted"
    );

    assert!(sink.flush(Duration::from_secs(30)));
    let stats = sink.stats();
    assert_eq!(stats.written, stats.accepted);
    let body = String::from_utf8(disk.bytes.lock().unwrap().clone()).unwrap();
    let lines: Vec<AuditEvent> = body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len() as u64, stats.written);
    // Order kept, no duplicates.
    assert!(lines.windows(2).all(|w| w[0].ts_ms < w[1].ts_ms));
}
