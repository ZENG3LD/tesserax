//! Host tripwire: notice that the process now runs on a different host.
//!
//! On first boot a pin file records the host fingerprint; on every later
//! boot the live fingerprint is compared with it. A mismatch means the disk
//! image was moved or cloned (or the provider migrated the machine).
//! [`SealedSecret`](crate::SealedSecret) stops data from decrypting on the
//! new host; the tripwire stops the service from starting there without an
//! explicit decision.
//!
//! - [`TripwirePolicy::Strict`]: mismatch is an error; the caller aborts.
//! - [`TripwirePolicy::WarnAndPin`]: mismatch is logged and the pin is
//!   rewritten (an accepted migration).
//! - [`TripwirePolicy::Off`]: no check.
//!
//! The pin file is plain JSON (the check must run before anything can be
//! unsealed). It holds the BLAKE3 hex of the fingerprint and 8-byte BLAKE3
//! hashes of each factor, never the raw values:
//!
//! ```json
//! {"version": 1, "fingerprint_blake3_hex": "…", "first_seen_unix": 1716800000,
//!  "host_notes": {"machine_id_h": "…", "primary_mac_h": "…", "uid_h": "…"}}
//! ```
//!
//! The fingerprint label is `tesserax-tripwire-v1|`.

use serde::{Deserialize, Serialize};

use crate::host::HostFactors;

/// What to do on a fingerprint mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripwirePolicy {
    /// Mismatch → `Err`. Caller aborts.
    Strict,
    /// Mismatch → warn + rewrite the pin to the current host.
    WarnAndPin,
    /// No tripwire — debug only.
    Off,
}

/// Tripwire failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum TripwireError {
    #[error("fingerprint mismatch: pin file says host {pinned}, live host is {live}")]
    Mismatch { pinned: String, live: String },
    #[error("pin file io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pin file parse: {0}")]
    Parse(String),
    #[error("fingerprint compute: {0}")]
    Fingerprint(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PinFile {
    version: u32,
    fingerprint_blake3_hex: String,
    first_seen_unix: u64,
    host_notes: HostNotes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostNotes {
    machine_id_h: String,
    primary_mac_h: String,
    uid_h: String,
}

/// Result of a check.
#[derive(Debug, Clone)]
pub struct TripwireOutcome {
    /// `true` if the pin file existed before this call.
    pub pin_existed: bool,
    /// `true` if the live fingerprint matched the pinned one.
    pub matched: bool,
    /// Set when `policy = WarnAndPin` AND mismatch occurred.
    pub rewritten: bool,
}

/// Run the tripwire check. Reads (or creates) the pin file at `path`;
/// compares to live fingerprint per `policy`; returns
/// [`TripwireOutcome`] or [`TripwireError::Mismatch`] when strict.
pub fn check_or_pin(
    path: &std::path::Path,
    policy: TripwirePolicy,
) -> Result<TripwireOutcome, TripwireError> {
    if matches!(policy, TripwirePolicy::Off) {
        return Ok(TripwireOutcome {
            pin_existed: false,
            matched: true,
            rewritten: false,
        });
    }
    let host = HostFactors::read().map_err(|e| TripwireError::Fingerprint(e.to_string()))?;
    check_or_pin_with(path, policy, &host)
}

/// [`check_or_pin`] against explicit host factors.
pub fn check_or_pin_with(
    path: &std::path::Path,
    policy: TripwirePolicy,
    host: &HostFactors,
) -> Result<TripwireOutcome, TripwireError> {
    if matches!(policy, TripwirePolicy::Off) {
        return Ok(TripwireOutcome {
            pin_existed: false,
            matched: true,
            rewritten: false,
        });
    }
    let live_fp = compute_fingerprint(host);
    let live_hex = blake3_hex(&live_fp.bytes);

    let existing = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };

    match existing {
        None => {
            // First boot — pin and accept.
            write_pin(path, &live_hex, &live_fp)?;
            Ok(TripwireOutcome {
                pin_existed: false,
                matched: true,
                rewritten: false,
            })
        }
        Some(body) => {
            let pin: PinFile =
                serde_json::from_str(&body).map_err(|e| TripwireError::Parse(e.to_string()))?;
            if tesserax::ct::ct_eq_str(&pin.fingerprint_blake3_hex, &live_hex) {
                Ok(TripwireOutcome {
                    pin_existed: true,
                    matched: true,
                    rewritten: false,
                })
            } else {
                match policy {
                    TripwirePolicy::Strict => {
                        tracing::error!(
                            pinned = %pin.fingerprint_blake3_hex,
                            live = %live_hex,
                            "host tripwire — fingerprint mismatch; refusing to boot"
                        );
                        Err(TripwireError::Mismatch {
                            pinned: pin.fingerprint_blake3_hex,
                            live: live_hex,
                        })
                    }
                    TripwirePolicy::WarnAndPin => {
                        tracing::warn!(
                            pinned = %pin.fingerprint_blake3_hex,
                            live = %live_hex,
                            "host tripwire — fingerprint changed; rewriting pin (WarnAndPin)"
                        );
                        write_pin(path, &live_hex, &live_fp)?;
                        Ok(TripwireOutcome {
                            pin_existed: true,
                            matched: false,
                            rewritten: true,
                        })
                    }
                    TripwirePolicy::Off => Ok(TripwireOutcome {
                        pin_existed: true,
                        matched: false,
                        rewritten: false,
                    }),
                }
            }
        }
    }
}

struct LiveFingerprint {
    bytes: [u8; 32],
    machine_id: String,
    primary_mac: String,
    uid: String,
}

fn compute_fingerprint(host: &HostFactors) -> LiveFingerprint {
    let mut h = blake3::Hasher::new();
    h.update(b"tesserax-tripwire-v1|");
    h.update(b"machine_id=");
    h.update(host.machine_id.as_bytes());
    h.update(b"|mac=");
    h.update(host.primary_mac.as_bytes());
    h.update(b"|uid=");
    h.update(host.uid.as_bytes());
    LiveFingerprint {
        bytes: *h.finalize().as_bytes(),
        machine_id: host.machine_id.clone(),
        primary_mac: host.primary_mac.clone(),
        uid: host.uid.clone(),
    }
}

fn write_pin(
    path: &std::path::Path,
    fingerprint_hex: &str,
    fp: &LiveFingerprint,
) -> Result<(), TripwireError> {
    let pin = PinFile {
        version: 1,
        fingerprint_blake3_hex: fingerprint_hex.to_string(),
        first_seen_unix: unix_seconds_now(),
        host_notes: HostNotes {
            machine_id_h: blake3_hex_8(fp.machine_id.as_bytes()),
            primary_mac_h: blake3_hex_8(fp.primary_mac.as_bytes()),
            uid_h: blake3_hex_8(fp.uid.as_bytes()),
        },
    };
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let body =
        serde_json::to_string_pretty(&pin).map_err(|e| TripwireError::Parse(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn blake3_hex(bytes: &[u8]) -> String {
    let h = blake3::hash(bytes);
    h.to_hex().to_string()
}

/// 8-byte BLAKE3 hex (16 chars) for the `host_notes` — short, prefix-
/// stable, doesn't leak the actual value.
fn blake3_hex_8(bytes: &[u8]) -> String {
    let h = blake3::hash(bytes);
    let bs = h.as_bytes();
    let mut s = String::with_capacity(16);
    const HEX: &[u8] = b"0123456789abcdef";
    for &b in bs.iter().take(8) {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_pin_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tesserax-tripwire-{}-{}-{}.json",
            tag,
            std::process::id(),
            unix_seconds_now()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn off_policy_short_circuits() {
        let path = temp_pin_path("off");
        let outcome = check_or_pin(&path, TripwirePolicy::Off).unwrap();
        assert!(outcome.matched);
        assert!(!outcome.pin_existed); // never read
        // File must not have been created.
        assert!(!path.exists());
    }

    #[test]
    fn first_boot_creates_pin() {
        let path = temp_pin_path("first");
        let outcome = check_or_pin(&path, TripwirePolicy::Strict).unwrap();
        assert!(!outcome.pin_existed);
        assert!(outcome.matched);
        assert!(path.exists());
        // File is JSON parseable.
        let body = std::fs::read_to_string(&path).unwrap();
        let pin: PinFile = serde_json::from_str(&body).unwrap();
        assert_eq!(pin.version, 1);
        assert_eq!(pin.fingerprint_blake3_hex.len(), 64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn second_boot_matches_first() {
        let path = temp_pin_path("second");
        let _ = check_or_pin(&path, TripwirePolicy::Strict).unwrap();
        let outcome = check_or_pin(&path, TripwirePolicy::Strict).unwrap();
        assert!(outcome.pin_existed);
        assert!(outcome.matched);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn strict_mismatch_returns_err() {
        let path = temp_pin_path("strict-mismatch");
        // Write a pin with a bogus fingerprint.
        let bogus = PinFile {
            version: 1,
            fingerprint_blake3_hex: "0".repeat(64),
            first_seen_unix: 0,
            host_notes: HostNotes {
                machine_id_h: "00".into(),
                primary_mac_h: "00".into(),
                uid_h: "00".into(),
            },
        };
        std::fs::write(&path, serde_json::to_string(&bogus).unwrap()).unwrap();

        let err = check_or_pin(&path, TripwirePolicy::Strict).unwrap_err();
        assert!(matches!(err, TripwireError::Mismatch { .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn warn_and_pin_rewrites_on_mismatch() {
        let path = temp_pin_path("warn-pin");
        let bogus = PinFile {
            version: 1,
            fingerprint_blake3_hex: "ff".repeat(32),
            first_seen_unix: 0,
            host_notes: HostNotes {
                machine_id_h: "00".into(),
                primary_mac_h: "00".into(),
                uid_h: "00".into(),
            },
        };
        std::fs::write(&path, serde_json::to_string(&bogus).unwrap()).unwrap();

        let outcome = check_or_pin(&path, TripwirePolicy::WarnAndPin).unwrap();
        assert!(outcome.pin_existed);
        assert!(!outcome.matched);
        assert!(outcome.rewritten);

        // Pin file now matches the live fingerprint.
        let next = check_or_pin(&path, TripwirePolicy::Strict).unwrap();
        assert!(next.matched);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn host_notes_are_hashes_not_raw_values() {
        let path = temp_pin_path("hashes");
        let _ = check_or_pin(&path, TripwirePolicy::Strict).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let pin: PinFile = serde_json::from_str(&body).unwrap();
        // Each note is 16 hex chars (8 bytes BLAKE3) — never the
        // raw value.
        assert_eq!(pin.host_notes.machine_id_h.len(), 16);
        assert_eq!(pin.host_notes.primary_mac_h.len(), 16);
        assert_eq!(pin.host_notes.uid_h.len(), 16);
        assert!(
            pin.host_notes
                .machine_id_h
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        );
        let _ = std::fs::remove_file(&path);
    }
}
