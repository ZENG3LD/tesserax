//! Bounded FIFO between threads of the shell layer (observation inbox,
//! executor lanes, the persist flusher). Locks are held for one push or pop;
//! the only waits are on the queue's own condition variables.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub(crate) enum Refused<T> {
    Full(T),
    Closed(T),
}

struct State<T> {
    items: VecDeque<T>,
    closed: bool,
}

pub(crate) struct BoundedQueue<T> {
    state: Mutex<State<T>>,
    not_empty: Condvar,
    not_full: Condvar,
    capacity: usize,
}

impl<T> BoundedQueue<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            state: Mutex::new(State {
                items: VecDeque::with_capacity(capacity.min(256)),
                closed: false,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            capacity,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn len(&self) -> usize {
        self.lock().items.len()
    }

    /// Never blocks.
    pub(crate) fn try_push(&self, item: T) -> Result<(), Refused<T>> {
        let mut state = self.lock();
        if state.closed {
            return Err(Refused::Closed(item));
        }
        if state.items.len() >= self.capacity {
            return Err(Refused::Full(item));
        }
        state.items.push_back(item);
        drop(state);
        self.not_empty.notify_one();
        Ok(())
    }

    /// Waits up to `timeout` for room.
    pub(crate) fn push_timeout(&self, item: T, timeout: Duration) -> Result<(), Refused<T>> {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();
        loop {
            if state.closed {
                return Err(Refused::Closed(item));
            }
            if state.items.len() < self.capacity {
                state.items.push_back(item);
                drop(state);
                self.not_empty.notify_one();
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Refused::Full(item));
            }
            state = self
                .not_full
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }

    /// Takes up to `limit` items without waiting.
    pub(crate) fn drain(&self, limit: usize) -> Vec<T> {
        let mut state = self.lock();
        let n = limit.min(state.items.len());
        let out: Vec<T> = state.items.drain(..n).collect();
        drop(state);
        if !out.is_empty() {
            self.not_full.notify_all();
        }
        out
    }

    /// Waits for at least one item and takes up to `limit`; `None` once the
    /// queue is closed and empty.
    pub(crate) fn drain_wait(&self, limit: usize) -> Option<Vec<T>> {
        let mut state = self.lock();
        loop {
            if !state.items.is_empty() {
                let n = limit.max(1).min(state.items.len());
                let out: Vec<T> = state.items.drain(..n).collect();
                drop(state);
                self.not_full.notify_all();
                return Some(out);
            }
            if state.closed {
                return None;
            }
            state = self
                .not_empty
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    /// No push succeeds afterwards; waiting consumers drain what is left.
    pub(crate) fn close(&self) {
        self.lock().closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.lock().closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn full_is_refused_without_blocking_and_room_frees_waiters() {
        let q = Arc::new(BoundedQueue::new(1));
        assert!(q.try_push(1).is_ok());
        assert!(matches!(q.try_push(2), Err(Refused::Full(2))));
        assert!(matches!(
            q.push_timeout(3, Duration::from_millis(5)),
            Err(Refused::Full(3))
        ));
        let q2 = Arc::clone(&q);
        let t = std::thread::spawn(move || q2.push_timeout(4, Duration::from_secs(10)).is_ok());
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(q.drain(8), vec![1]);
        assert!(t.join().unwrap());
        assert_eq!(q.drain_wait(8), Some(vec![4]));
        q.close();
        assert!(matches!(q.try_push(5), Err(Refused::Closed(5))));
        assert_eq!(q.drain_wait(8), None);
    }
}
