//! The writer thread behind both audit sinks: a bounded queue the producer
//! only ever `try_send`s into (full → the newest event is dropped and
//! counted), and one OS thread that drains it in batches.
//!
//! Drop warnings: the first drop logs one `tracing::warn!`, and after that
//! only drops whose running count is a power of two (1, 2, 4, 8, …) do.
//! That needs no clock or extra state on the producer path (one atomic
//! add, already there for the counter), is deterministic, and keeps a
//! sustained overload to about 64 lines over the life of the process
//! while still showing that drops continue. The log is best-effort; the
//! authoritative figure is [`AuditSinkStats::dropped`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use crate::audit::AuditSinkStats;

/// Most items one batch hands to the handler.
const MAX_BATCH: usize = 256;

enum Msg<T> {
    Item(T),
    Flush(mpsc::Sender<()>),
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    written: AtomicU64,
    dropped: AtomicU64,
    failed: AtomicU64,
}

pub(crate) struct SinkWorker<T> {
    tx: SyncSender<Msg<T>>,
    counters: Arc<Counters>,
    name: Arc<str>,
}

/// True for the drop counts that log (see the module docs).
fn warn_on_drop(count: u64) -> bool {
    count.is_power_of_two()
}

impl<T: Send + 'static> SinkWorker<T> {
    /// Spawns the thread. `handle` receives each batch in queue order and
    /// reports success or a failure description (the whole batch then
    /// counts as failed).
    pub(crate) fn spawn<F>(name: String, capacity: usize, mut handle: F) -> std::io::Result<Self>
    where
        F: FnMut(&mut Vec<T>) -> Result<(), String> + Send + 'static,
    {
        let (tx, rx) = mpsc::sync_channel::<Msg<T>>(capacity.max(1));
        let counters = Arc::new(Counters::default());
        let worker_counters = counters.clone();
        let sink_name: Arc<str> = Arc::from(name.as_str());
        std::thread::Builder::new()
            .name(name.clone())
            .spawn(move || run(&name, rx, &worker_counters, &mut handle))?;
        Ok(Self {
            tx,
            counters,
            name: sink_name,
        })
    }

    /// Hands `item` to the writer thread without ever blocking: a full queue
    /// (or a dead writer) drops the item and counts it; the first drop and
    /// every power-of-two drop count log a warning.
    pub(crate) fn submit(&self, item: T) {
        let reason = match self.tx.try_send(Msg::Item(item)) {
            Ok(()) => {
                self.counters.accepted.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(TrySendError::Full(_)) => "queue full",
            Err(TrySendError::Disconnected(_)) => "writer gone",
        };
        let dropped = self.counters.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if warn_on_drop(dropped) {
            tracing::warn!(
                sink = %self.name,
                reason,
                dropped_total = dropped,
                "audit event dropped (newest is dropped; next warning at {} drops)",
                dropped.saturating_mul(2)
            );
        }
    }

    /// Waits until every item accepted before this call has been handled,
    /// or `timeout` passes. This call may wait; producers use `submit`.
    pub(crate) fn flush(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (ack_tx, ack_rx) = mpsc::channel();
        let mut msg = Msg::Flush(ack_tx);
        loop {
            match self.tx.try_send(msg) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(back)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    msg = back;
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        ack_rx.recv_timeout(left).is_ok()
    }

    pub(crate) fn stats(&self) -> AuditSinkStats {
        AuditSinkStats {
            accepted: self.counters.accepted.load(Ordering::Relaxed),
            written: self.counters.written.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            failed: self.counters.failed.load(Ordering::Relaxed),
        }
    }
}

fn run<T, F>(name: &str, rx: Receiver<Msg<T>>, counters: &Counters, handle: &mut F)
where
    F: FnMut(&mut Vec<T>) -> Result<(), String>,
{
    let mut batch: Vec<T> = Vec::with_capacity(MAX_BATCH);
    let mut acks: Vec<mpsc::Sender<()>> = Vec::new();
    while let Ok(first) = rx.recv() {
        push(first, &mut batch, &mut acks);
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(msg) => push(msg, &mut batch, &mut acks),
                Err(_) => break,
            }
        }
        if !batch.is_empty() {
            let n = batch.len() as u64;
            match handle(&mut batch) {
                Ok(()) => {
                    counters.written.fetch_add(n, Ordering::Relaxed);
                }
                Err(e) => {
                    counters.failed.fetch_add(n, Ordering::Relaxed);
                    tracing::warn!(sink = name, error = %e, items = n, "audit batch lost");
                }
            }
            batch.clear();
        }
        for ack in acks.drain(..) {
            let _ = ack.send(());
        }
    }
}

fn push<T>(msg: Msg<T>, batch: &mut Vec<T>, acks: &mut Vec<mpsc::Sender<()>>) {
    match msg {
        Msg::Item(item) => batch.push(item),
        Msg::Flush(ack) => acks.push(ack),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warns_on_first_drop_then_powers_of_two() {
        let warned: Vec<u64> = (1..=100).filter(|&n| warn_on_drop(n)).collect();
        assert_eq!(warned, vec![1, 2, 4, 8, 16, 32, 64]);
        assert!(!warn_on_drop(0));
        // 64 powers of two fit a u64: at most 64 lines, ever.
        assert!(warn_on_drop(1 << 63));
        assert!(!warn_on_drop(u64::MAX));
    }

    #[test]
    fn full_queue_drops_newest_and_counts() {
        // A handler that holds the first batch until released, so the
        // queue (capacity 2) fills behind it.
        let (release, gate) = mpsc::channel::<()>();
        let (started_tx, started) = mpsc::channel::<()>();
        let gate = std::sync::Mutex::new(Some((gate, started_tx)));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_w = seen.clone();
        let w = SinkWorker::spawn("test-sink".into(), 2, move |batch: &mut Vec<u32>| {
            if let Some((g, s)) = gate.lock().unwrap().take() {
                let _ = s.send(());
                let _ = g.recv_timeout(Duration::from_secs(10));
            }
            seen_w.lock().unwrap().extend(batch.iter().copied());
            Ok(())
        })
        .unwrap();
        w.submit(0);
        started.recv_timeout(Duration::from_secs(10)).unwrap();
        w.submit(1);
        w.submit(2);
        for i in 3..10 {
            w.submit(i); // queue full: dropped, never blocks
        }
        let s = w.stats();
        assert_eq!(s.accepted, 3);
        assert_eq!(s.dropped, 7);
        release.send(()).unwrap();
        assert!(w.flush(Duration::from_secs(10)));
        // The oldest were kept, the newest dropped.
        assert_eq!(*seen.lock().unwrap(), vec![0, 1, 2]);
        assert_eq!(w.stats().written, 3);
    }
}
