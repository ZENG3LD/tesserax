//! Bounded least-recently-used map.
//!
//! A plain single-owner data structure (`&mut self`): no lock, no async. A
//! shell that shares one cache between threads wraps it in its own mutex;
//! a single writer simply owns it.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

/// Map of at most `capacity` entries; inserting past capacity evicts the
/// least recently used entry. `get`, `put` and `remove` are `O(log n)`.
#[derive(Clone, Debug)]
pub struct LruCache<K, V> {
    map: HashMap<K, (V, u64)>,
    by_rank: BTreeMap<u64, K>,
    counter: u64,
    capacity: usize,
}

impl<K: Eq + Hash + Clone, V> LruCache<K, V> {
    /// Empty cache holding at most `capacity` entries (at least 1).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            map: HashMap::with_capacity(capacity.min(1_024)),
            by_rank: BTreeMap::new(),
            counter: 0,
            capacity,
        }
    }

    /// Maximum number of entries.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True iff empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn next_rank(&mut self) -> u64 {
        if self.counter == u64::MAX {
            self.renumber();
        }
        self.counter += 1;
        self.counter
    }

    /// Compacts ranks to `1..=len` keeping their order (reached only after
    /// 2^64 touches; kept so the cache never misorders).
    fn renumber(&mut self) {
        let old = std::mem::take(&mut self.by_rank);
        self.counter = 0;
        for (_, key) in old {
            self.counter += 1;
            if let Some(entry) = self.map.get_mut(&key) {
                entry.1 = self.counter;
            }
            self.by_rank.insert(self.counter, key);
        }
    }

    /// Looks `key` up and marks it most recently used.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if !self.map.contains_key(key) {
            return None;
        }
        let rank = self.next_rank();
        let entry = self.map.get_mut(key)?;
        let old = std::mem::replace(&mut entry.1, rank);
        if let Some(k) = self.by_rank.remove(&old) {
            self.by_rank.insert(rank, k);
        }
        self.map.get(key).map(|(v, _)| v)
    }

    /// Looks `key` up without changing recency.
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|(v, _)| v)
    }

    /// Inserts or replaces `key`, marking it most recently used. Returns the
    /// entry evicted to make room, if any.
    pub fn put(&mut self, key: K, value: V) -> Option<(K, V)> {
        let rank = self.next_rank();
        if let Some((_, old_rank)) = self.map.insert(key.clone(), (value, rank)) {
            self.by_rank.remove(&old_rank);
        }
        self.by_rank.insert(rank, key);
        if self.map.len() > self.capacity {
            let (_, victim) = self.by_rank.pop_first()?;
            let (value, _) = self.map.remove(&victim)?;
            return Some((victim, value));
        }
        None
    }

    /// Removes `key`.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let (value, rank) = self.map.remove(key)?;
        self.by_rank.remove(&rank);
        Some(value)
    }

    /// Removes every entry.
    pub fn clear(&mut self) {
        self.map.clear();
        self.by_rank.clear();
        self.counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip() {
        let mut c = LruCache::new(4);
        c.put("a", 1);
        c.put("b", 2);
        assert_eq!(c.get(&"a"), Some(&1));
        assert_eq!(c.get(&"missing"), None);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn evicts_least_recently_used() {
        let mut c = LruCache::new(2);
        c.put("a", 1);
        c.put("b", 2);
        let _ = c.get(&"a");
        assert_eq!(c.put("c", 3), Some(("b", 2)));
        assert_eq!(c.peek(&"a"), Some(&1));
        assert_eq!(c.peek(&"b"), None);
        assert_eq!(c.peek(&"c"), Some(&3));
    }

    #[test]
    fn replace_and_remove() {
        let mut c = LruCache::new(2);
        c.put("a", 1);
        assert_eq!(c.put("a", 10), None);
        assert_eq!(c.len(), 1);
        assert_eq!(c.remove(&"a"), Some(10));
        assert!(c.is_empty());
        assert_eq!(LruCache::<u8, u8>::new(0).capacity(), 1);
    }

    #[test]
    fn renumber_keeps_order() {
        let mut c = LruCache::new(3);
        c.put(1, 'a');
        c.put(2, 'b');
        c.put(3, 'c');
        c.counter = u64::MAX;
        let _ = c.get(&1); // forces renumbering; order now 2, 3, 1
        assert_eq!(c.put(4, 'd'), Some((2, 'b')));
        assert_eq!(c.put(5, 'e'), Some((3, 'c')));
    }
}
