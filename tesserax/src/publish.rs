//! Lock-free published values: [`Published<T>`] and the [`Flags`] registry.
//!
//! A published value has one writer that replaces it wholesale and any number
//! of readers that load an `Arc` without locking (read-copy-update). This is
//! the snapshot cell of the single-writer contract, usable for any value that
//! is read far more often than it changes (configuration, key rings, flags).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;

/// A value readers load lock-free and a writer replaces atomically.
pub struct Published<T>(ArcSwap<T>);

impl<T> Published<T> {
    /// Publishes `initial`.
    pub fn new(initial: T) -> Self {
        Self(ArcSwap::from_pointee(initial))
    }

    /// Publishes an already shared value.
    pub fn from_arc(initial: Arc<T>) -> Self {
        Self(ArcSwap::new(initial))
    }

    /// The current value. Never blocks.
    pub fn load(&self) -> Arc<T> {
        self.0.load_full()
    }

    /// Replaces the value; readers holding the old `Arc` keep it until they
    /// drop it.
    pub fn store(&self, value: T) {
        self.0.store(Arc::new(value));
    }

    /// Replaces the value with an already shared one.
    pub fn store_arc(&self, value: Arc<T>) {
        self.0.store(value);
    }

    /// Replaces the value and returns the previous one.
    pub fn swap(&self, value: T) -> Arc<T> {
        self.0.swap(Arc::new(value))
    }

    /// Read-copy-update: computes the next value from the current one and
    /// retries if another writer replaced it in between, so no update is lost.
    /// `f` may run more than once.
    pub fn rcu<F>(&self, mut f: F) -> Arc<T>
    where
        F: FnMut(&T) -> T,
    {
        let mut current = self.load();
        loop {
            let next = Arc::new(f(&current));
            let previous = self.0.compare_and_swap(&current, Arc::clone(&next));
            if Arc::ptr_eq(&previous, &current) {
                return next;
            }
            current = arc_swap::Guard::into_inner(previous);
        }
    }
}

impl<T: Default> Default for Published<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for Published<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Published").field(&*self.load()).finish()
    }
}

#[derive(Clone, Debug, Default)]
struct FlagState {
    map: HashMap<String, bool>,
    generation: u64,
}

/// Named on/off switches (kill switches, rollout flags) readable lock-free.
///
/// A flag that was never set reads as the registry default. Every change
/// bumps [`generation`](Self::generation), so a reader can notice changes by
/// polling one number.
#[derive(Debug)]
pub struct Flags {
    state: Published<FlagState>,
    default_on: bool,
}

impl Default for Flags {
    /// Unset flags read as on (kill-switch semantics: paths are live until
    /// switched off).
    fn default() -> Self {
        Self::new(true)
    }
}

impl Flags {
    /// Empty registry; unset flags read as `default_on`.
    pub fn new(default_on: bool) -> Self {
        Self {
            state: Published::default(),
            default_on,
        }
    }

    /// Value of `name`, or the default if never set.
    pub fn is_on(&self, name: &str) -> bool {
        self.state
            .load()
            .map
            .get(name)
            .copied()
            .unwrap_or(self.default_on)
    }

    /// Negation of [`is_on`](Self::is_on).
    pub fn is_off(&self, name: &str) -> bool {
        !self.is_on(name)
    }

    /// Sets one flag. Concurrent `set`s never lose each other.
    pub fn set(&self, name: impl Into<String>, on: bool) {
        let name = name.into();
        self.state.rcu(|current| {
            let mut map = current.map.clone();
            map.insert(name.clone(), on);
            FlagState {
                map,
                generation: current.generation.wrapping_add(1),
            }
        });
    }

    /// Replaces every flag at once (for example from a file at start-up).
    pub fn replace_all(&self, flags: BTreeMap<String, bool>) {
        let map: HashMap<String, bool> = flags.into_iter().collect();
        self.state.rcu(|current| FlagState {
            map: map.clone(),
            generation: current.generation.wrapping_add(1),
        });
    }

    /// Every explicitly set flag, sorted by name.
    pub fn snapshot(&self) -> BTreeMap<String, bool> {
        self.state
            .load()
            .map
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Change counter (wrapping).
    pub fn generation(&self) -> u64 {
        self.state.load().generation
    }

    /// Value read for flags that were never set.
    pub fn default_value(&self) -> bool {
        self.default_on
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn published_load_store_swap() {
        let p = Published::new(1_u32);
        assert_eq!(*p.load(), 1);
        p.store(2);
        assert_eq!(*p.swap(3), 2);
        assert_eq!(*p.load(), 3);
    }

    #[test]
    fn stress_published_rcu_loses_no_update() {
        const THREADS: u64 = 8;
        const PER_THREAD: u64 = 1_000;
        let p = Arc::new(Published::new(0_u64));
        let start = Instant::now();
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let p = Arc::clone(&p);
                std::thread::spawn(move || {
                    for _ in 0..PER_THREAD {
                        p.rcu(|v| v + 1);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*p.load(), THREADS * PER_THREAD);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn flags_default_set_replace() {
        let f = Flags::new(true);
        assert!(f.is_on("ingest"));
        f.set("ingest", false);
        assert!(f.is_off("ingest"));
        let g = f.generation();
        f.replace_all(BTreeMap::from([("other".to_owned(), false)]));
        assert!(f.generation() != g);
        assert!(
            f.is_on("ingest"),
            "replaced registry falls back to the default"
        );
        assert_eq!(f.snapshot().len(), 1);
        assert!(Flags::new(false).is_off("anything"));
    }

    #[test]
    fn stress_flags_concurrent_set_loses_nothing() {
        const WRITERS: usize = 8;
        let f = Arc::new(Flags::new(true));
        let start = Instant::now();
        let handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let f = Arc::clone(&f);
                std::thread::spawn(move || {
                    for i in 0..200 {
                        f.set(format!("flag-{w}-{i}"), false);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(f.snapshot().len(), WRITERS * 200);
        assert_eq!(f.generation(), (WRITERS * 200) as u64);
        assert!(start.elapsed() < Duration::from_secs(10));
    }
}
