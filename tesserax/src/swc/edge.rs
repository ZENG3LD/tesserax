//! The edge: the only place of the contract that holds locks.
//!
//! It owns the published snapshot (an `ArcSwap`, so readers never lock), the
//! bounded event-log ring used for resync, and the subscriber list. Events
//! are appended and the snapshot is swapped under one mutex, so a resync
//! reader always sees a snapshot and a log that end at the same sequence.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;

use super::resync::ResyncReply;
use super::subscription::{Subscription, SubscriptionSender, subscription_channel};
use super::types::{CoreEvent, EventEnvelope, Generation, Snapshot};
use crate::error::{PublishError, SendError, SubscribeError};

/// Outcome of one [`KernelPort::publish`](super::KernelPort::publish).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct PublishReport {
    /// Event deliveries made (one per event per subscriber that took it).
    pub delivered: usize,
    /// Subscribers cut off because their queue was full. Each was sent a
    /// final [`CoreEvent::ResyncRequired`].
    pub disconnected_slow: usize,
    /// Subscribers removed because they had dropped their subscription.
    pub disconnected_closed: usize,
}

impl core::ops::AddAssign for PublishReport {
    fn add_assign(&mut self, rhs: Self) {
        self.delivered += rhs.delivered;
        self.disconnected_slow += rhs.disconnected_slow;
        self.disconnected_closed += rhs.disconnected_closed;
    }
}

struct EdgeInner<V> {
    log: VecDeque<EventEnvelope<V>>,
    last_sequence: u64,
    revision: u64,
    subscribers: Vec<SubscriptionSender<V>>,
    closed: bool,
}

impl<V> EdgeInner<V> {
    fn oldest_available(&self) -> u64 {
        match self.log.front() {
            Some(event) => event.sequence,
            None => self.last_sequence.saturating_add(1),
        }
    }
}

pub(crate) struct Edge<V, S> {
    snapshot: ArcSwap<Snapshot<S>>,
    inner: Mutex<EdgeInner<V>>,
    log_capacity: usize,
    max_subscribers: usize,
}

impl<V, S> Edge<V, S> {
    pub(crate) fn new(initial: Snapshot<S>, log_capacity: usize, max_subscribers: usize) -> Self {
        let last_sequence = initial.through_sequence;
        let revision = initial.revision;
        Self {
            snapshot: ArcSwap::from_pointee(initial),
            inner: Mutex::new(EdgeInner {
                log: VecDeque::with_capacity(log_capacity.min(1_024)),
                last_sequence,
                revision,
                subscribers: Vec::new(),
                closed: false,
            }),
            log_capacity,
            max_subscribers,
        }
    }

    fn lock(&self) -> MutexGuard<'_, EdgeInner<V>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Lock-free read of the current snapshot.
    pub(crate) fn snapshot(&self) -> Arc<Snapshot<S>> {
        self.snapshot.load_full()
    }

    pub(crate) fn subscribe(&self, capacity: usize) -> Result<Subscription<V>, SubscribeError> {
        let (sender, subscription) = subscription_channel(capacity);
        let mut inner = self.lock();
        if inner.closed {
            // Dropping `sender` disconnects the subscription at once.
            return Ok(subscription);
        }
        inner.subscribers.retain(|s| !s.is_closed());
        if inner.subscribers.len() >= self.max_subscribers {
            return Err(SubscribeError::TooManySubscribers);
        }
        inner.subscribers.push(sender);
        Ok(subscription)
    }

    pub(crate) fn subscriber_count(&self) -> usize {
        let mut inner = self.lock();
        inner.subscribers.retain(|s| !s.is_closed());
        inner.subscribers.len()
    }

    /// Kernel side is gone: disconnect every subscriber, refuse new ones.
    pub(crate) fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        inner.subscribers.clear();
    }
}

impl<V: Clone, S> Edge<V, S> {
    pub(crate) fn publish(
        &self,
        events: Vec<EventEnvelope<V>>,
        snapshot: Snapshot<S>,
    ) -> Result<PublishReport, PublishError> {
        let mut inner = self.lock();

        // Validate the whole batch before touching anything.
        let mut previous = inner.last_sequence;
        for event in &events {
            if previous.checked_add(1) != Some(event.sequence) {
                return Err(PublishError::SequenceGap {
                    expected_previous: previous,
                    found: event.sequence,
                });
            }
            if matches!(event.event, CoreEvent::ResyncRequired { .. }) {
                return Err(PublishError::EdgeOnlyEvent {
                    sequence: event.sequence,
                });
            }
            previous = event.sequence;
        }
        if snapshot.through_sequence != previous {
            return Err(PublishError::ThroughSequenceMismatch {
                expected: previous,
                found: snapshot.through_sequence,
            });
        }
        if snapshot.revision < inner.revision {
            return Err(PublishError::RevisionRegressed {
                current: inner.revision,
                found: snapshot.revision,
            });
        }

        // Append to the ring and swap the snapshot under the same lock.
        for event in &events {
            if inner.log.len() >= self.log_capacity {
                inner.log.pop_front();
            }
            inner.log.push_back(event.clone());
        }
        inner.last_sequence = previous;
        inner.revision = snapshot.revision;
        self.snapshot.store(Arc::new(snapshot));

        // Deliver in order; a full queue ends that subscriber.
        let mut report = PublishReport::default();
        if events.is_empty() {
            return Ok(report);
        }
        let oldest_available = inner.oldest_available();
        inner.subscribers.retain(|subscriber| {
            for event in &events {
                match subscriber.try_send(event.clone()) {
                    Ok(()) => report.delivered += 1,
                    Err(SendError::Full) => {
                        subscriber.send_final(EventEnvelope {
                            sequence: event.sequence,
                            command_id: None,
                            subject: None,
                            generation: Generation::default(),
                            event: CoreEvent::ResyncRequired { oldest_available },
                        });
                        report.disconnected_slow += 1;
                        return false;
                    }
                    Err(SendError::Closed) => {
                        report.disconnected_closed += 1;
                        return false;
                    }
                }
            }
            true
        });
        Ok(report)
    }

    pub(crate) fn resync(&self, after_sequence: u64) -> ResyncReply<V, S> {
        let inner = self.lock();
        let snapshot = self.snapshot.load_full();
        let oldest_available = inner.oldest_available();
        let start = inner.log.partition_point(|e| e.sequence <= after_sequence);
        ResyncReply {
            event_sequence: inner.last_sequence,
            oldest_available,
            gap: after_sequence < oldest_available.saturating_sub(1)
                || after_sequence > inner.last_sequence,
            snapshot,
            events: inner.log.range(start..).cloned().collect(),
        }
    }
}
