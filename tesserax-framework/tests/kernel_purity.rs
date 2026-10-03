//! SWC law 3, mechanically: the kernel module uses no lock, no channel, no
//! atomics, no thread, no async runtime, no filesystem and no network.
//! Equivalent to `rg -n '<pattern>' src/kernel` printing nothing.

use std::path::Path;

const FORBIDDEN: &[&str] = &[
    "Mutex",
    "RwLock",
    "Condvar",
    "mpsc",
    "channel",
    "Atomic",
    "std::sync",
    "std::thread",
    "std::fs",
    "std::net",
    "tokio",
    "async",
    ".await",
    "spawn",
];

#[test]
fn kernel_has_no_lock_channel_thread_or_io() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/kernel");
    let mut hits = Vec::new();
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            for word in FORBIDDEN {
                if line.contains(word) {
                    hits.push(format!("{}:{}: {word}: {line}", path.display(), n + 1));
                }
            }
        }
    }
    assert!(files >= 3, "kernel sources not found in {}", dir.display());
    assert!(hits.is_empty(), "forbidden in kernel:\n{}", hits.join("\n"));
}
