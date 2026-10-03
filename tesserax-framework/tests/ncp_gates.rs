//! The mechanical gates of NCP §5.3, as file-content tests (the same
//! shape as `kernel_purity.rs`): they read the sources, so they run
//! regardless of which tier features are enabled.
//!
//! The third gate of §5.3 — "a binary of one tier has no symbol of the
//! tier above" — is a cargo-level property and is checked by the brief's
//! feature builds (`cargo check --no-default-features --features c2`,
//! `hq`, `node`, `node-os`), not by this file.

use std::path::Path;

fn ncp_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ncp")
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// §5.3.3 first grep: `rg -n "Hq" src/ncp/{c2,node,link,roster,oracle}.rs`
/// must print nothing — the middle tier, the node tier and the shared
/// modules never name the top tier.
#[test]
fn no_top_tier_name_below_the_top() {
    let files = ["c2.rs", "node.rs", "link.rs", "roster.rs", "oracle.rs"];
    let mut hits = Vec::new();
    for file in files {
        let path = ncp_dir().join(file);
        let text = read(&path);
        for (n, line) in text.lines().enumerate() {
            if line.contains("Hq") {
                hits.push(format!("{}:{}: {line}", path.display(), n + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "top-tier name below the top:\n{}",
        hits.join("\n")
    );
}

/// §5.3.3 second grep: `rg -n "std::process|Command::new" src/ncp`
/// outside `node/os.rs` must print nothing — only the node's `node-os`
/// half may touch an OS process.
#[test]
fn no_os_process_outside_node_os() {
    let mut hits = Vec::new();
    let mut files = 0;
    fn walk(dir: &Path, files: &mut usize, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, files, hits);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            if path.ends_with("node/os.rs") {
                continue; // the one allowed file
            }
            *files += 1;
            let text = read(&path);
            for (n, line) in text.lines().enumerate() {
                if line.contains("std::process") || line.contains("Command::new") {
                    hits.push(format!("{}:{}: {line}", path.display(), n + 1));
                }
            }
        }
    }
    walk(&ncp_dir(), &mut files, &mut hits);
    assert!(
        files >= 4,
        "ncp sources not found under {}",
        ncp_dir().display()
    );
    assert!(
        hits.is_empty(),
        "OS process outside node/os.rs:\n{}",
        hits.join("\n")
    );
}

/// The allowed file must exist and must be the one carrying the process
/// code — otherwise the gate above is vacuous.
#[test]
fn node_os_is_the_process_module() {
    let path = ncp_dir().join("node/os.rs");
    let text = read(&path);
    assert!(
        text.contains("std::process") || text.contains("Command::new"),
        "node/os.rs no longer carries the process code — is the second grep gate vacuous?"
    );
}
