//! Publish-readiness scrub (design §7.3). Walks the repository and fails
//! on a product or host token from `scrub_tokens.txt`, or on an IPv4
//! literal outside loopback, RFC 1918, RFC 5737 documentation ranges, and
//! `0.0.0.0`.
//!
//! The token list is data, not source: this file does not spell the
//! tokens, and the walker skips the list itself.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate lives in the repo root")
        .to_path_buf()
}

fn tokens() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/scrub_tokens.txt");
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

fn skip_dir(name: &str) -> bool {
    matches!(name, ".git" | "target")
}

fn skip_file(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == "scrub_tokens.txt")
}

fn ipv4_allowed(octets: [u8; 4]) -> bool {
    let [a, b, c, _] = octets;
    (a, b, c) == (0, 0, 0) && octets[3] == 0
        || a == 127
        || a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
}

/// Pull dotted-quads out of a line. A match is four runs of 1–3 digits
/// separated by dots, not touching another digit.
fn ipv4_literals(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_digit()) {
            if let Some((end, text, octets)) = parse_ipv4(&bytes[i..]) {
                let after = i + end;
                if after == bytes.len() || !bytes[after].is_ascii_digit() {
                    if !ipv4_allowed(octets) {
                        out.push(text);
                    }
                }
                i = after;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn parse_ipv4(bytes: &[u8]) -> Option<(usize, String, [u8; 4])> {
    let mut octets = [0u8; 4];
    let mut pos = 0;
    for part in 0..4 {
        if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
            return None;
        }
        let start = pos;
        let mut value: u16 = 0;
        let mut digits = 0;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            digits += 1;
            if digits > 3 {
                return None;
            }
            value = value * 10 + u16::from(bytes[pos] - b'0');
            if value > 255 {
                return None;
            }
            pos += 1;
        }
        if digits == 0 {
            return None;
        }
        // Reject a leading zero on a multi-digit octet (not an address).
        if digits > 1 && bytes[start] == b'0' {
            return None;
        }
        octets[part] = value as u8;
        if part < 3 {
            if pos >= bytes.len() || bytes[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    let text = std::str::from_utf8(&bytes[..pos]).ok()?.to_string();
    Some((pos, text, octets))
}

fn walk(dir: &Path, hits: &mut Vec<String>, tokens: &[String]) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if skip_dir(&name) {
                continue;
            }
            walk(&path, hits, tokens);
            continue;
        }
        if skip_file(&path) {
            continue;
        }
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if data.contains(&0) {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&data) else {
            continue;
        };
        let lower = text.to_ascii_lowercase();
        for (n, (raw, folded)) in text.lines().zip(lower.lines()).enumerate() {
            for token in tokens {
                if folded.contains(token.as_str()) {
                    hits.push(format!("{}:{}: token {token}", path.display(), n + 1));
                }
            }
            for addr in ipv4_literals(raw) {
                hits.push(format!("{}:{}: ipv4 {addr}", path.display(), n + 1));
            }
        }
    }
}

#[test]
fn scrub_repo() {
    let tokens = tokens();
    assert!(tokens.len() >= 8, "token list missing");
    let mut hits = Vec::new();
    walk(&repo_root(), &mut hits, &tokens);
    assert!(
        hits.is_empty(),
        "scrub failed ({} hit(s)):\n{}",
        hits.len(),
        hits.join("\n")
    );
}
