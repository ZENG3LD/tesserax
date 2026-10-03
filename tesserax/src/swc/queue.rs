//! Internal bounded FIFO shared by one producer side and one consumer side.
//!
//! Used for the command ingress and for every subscriber queue. Unlike
//! `std::sync::mpsc::sync_channel` it can (a) wait for an item without taking
//! it, which `KernelPort::wait` needs, and (b) append one terminal item past
//! capacity, which the edge uses to tell a slow subscriber to resync before
//! cutting it off. Locks are held for a push or a pop only, never across a
//! wait on anything but its own condition variable.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

pub(crate) enum PushError<T> {
    Full(T),
    Closed(T),
}

pub(crate) enum PopError {
    Empty,
    Disconnected,
}

struct State<T> {
    items: VecDeque<T>,
    capacity: usize,
    /// No producer will push again.
    tx_closed: bool,
    /// No consumer will pop again.
    rx_closed: bool,
}

pub(crate) struct Queue<T> {
    state: Mutex<State<T>>,
    ready: Condvar,
}

impl<T> Queue<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            state: Mutex::new(State {
                items: VecDeque::with_capacity(capacity.min(64)),
                capacity,
                tx_closed: false,
                rx_closed: false,
            }),
            ready: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn try_push(&self, item: T) -> Result<(), PushError<T>> {
        let mut state = self.lock();
        if state.rx_closed || state.tx_closed {
            return Err(PushError::Closed(item));
        }
        if state.items.len() >= state.capacity {
            return Err(PushError::Full(item));
        }
        state.items.push_back(item);
        drop(state);
        self.ready.notify_one();
        Ok(())
    }

    /// Appends `item` ignoring capacity, then closes the producer side.
    /// Returns false if the consumer is already gone.
    pub(crate) fn push_final(&self, item: T) -> bool {
        let mut state = self.lock();
        if state.rx_closed || state.tx_closed {
            state.tx_closed = true;
            return false;
        }
        state.items.push_back(item);
        state.tx_closed = true;
        drop(state);
        self.ready.notify_all();
        true
    }

    pub(crate) fn close_tx(&self) {
        self.lock().tx_closed = true;
        self.ready.notify_all();
    }

    pub(crate) fn close_rx(&self) {
        let mut state = self.lock();
        state.rx_closed = true;
        state.items.clear();
    }

    pub(crate) fn is_rx_closed(&self) -> bool {
        self.lock().rx_closed
    }

    pub(crate) fn try_pop(&self) -> Result<T, PopError> {
        let mut state = self.lock();
        match state.items.pop_front() {
            Some(item) => Ok(item),
            None if state.tx_closed => Err(PopError::Disconnected),
            None => Err(PopError::Empty),
        }
    }

    pub(crate) fn pop_timeout(&self, timeout: Duration) -> Result<T, PopError> {
        let state = self.lock();
        let (mut state, _) = self
            .ready
            .wait_timeout_while(state, timeout, |s| s.items.is_empty() && !s.tx_closed)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match state.items.pop_front() {
            Some(item) => Ok(item),
            None if state.tx_closed => Err(PopError::Disconnected),
            None => Err(PopError::Empty),
        }
    }

    /// Waits until at least one item is queued, the producer side closes, or
    /// `timeout` elapses. Takes nothing. Returns true iff an item is queued.
    pub(crate) fn wait_nonempty(&self, timeout: Duration) -> bool {
        let state = self.lock();
        let (state, _) = self
            .ready
            .wait_timeout_while(state, timeout, |s| s.items.is_empty() && !s.tx_closed)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !state.items.is_empty()
    }

    pub(crate) fn drain(&self, limit: usize) -> Vec<T> {
        let mut state = self.lock();
        let n = limit.min(state.items.len());
        state.items.drain(..n).collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.lock().items.len()
    }
}
