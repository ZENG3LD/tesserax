//! Host-identity readers: the single source of the factors every seal,
//! fingerprint, tripwire and key-derivation in this crate uses.
//!
//! These strings feed cryptographic fingerprints, so they are read in one
//! place only; two readers that drift even slightly would make a value
//! sealed by one module fail to open under another. Every reader is
//! best-effort and OS-specific; none writes to disk or caches, so a moved
//! disk image is noticed on the next read.
//!
//! | Identifier | Linux | Windows | macOS |
//! |---|---|---|---|
//! | [`machine_id`] | `/etc/machine-id` (then `/var/lib/dbus/machine-id`) | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | `IOPlatformUUID` |
//! | [`primary_mac`] | first non-loopback `/sys/class/net/*/address` | `getmac /fo csv /nh` | `ifconfig -a` ether |
//! | [`uid`] | `/proc/self/loginuid` then `$USER` | `$USERDOMAIN\$USERNAME` | `$USER` |
//! | [`product_uuid`] | `/sys/class/dmi/id/product_uuid` | `wmic csproduct get uuid` | `IOPlatformUUID` |
//!
//! `/etc/machine-id` can be regenerated on first boot of a cloned image and
//! a virtual NIC's MAC can change across reboots; the DMI `product_uuid`
//! is assigned by the hypervisor and survives reboots and restores, so it
//! is the preferred factor for anything that must outlive a reboot.
//!
//! On Linux without readable DMI, [`product_uuid`] falls back to
//! [`machine_id`] (see its docs and
//! [`BindingStrength`](crate::BindingStrength)).

/// Failure reading a host identifier. The variant names the identifier;
/// the string carries the OS-specific cause.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum PlatformIdError {
    #[error("machine_id: {0}")]
    MachineId(String),
    #[error("primary_mac: {0}")]
    PrimaryMac(String),
    #[error("product_uuid: {0}")]
    ProductUuid(String),
    #[error("unsupported platform for {0}")]
    Unsupported(&'static str),
}

// ── machine_id ──────────────────────────────────────────────────────────────

/// Stable per-installation machine identifier.
///
/// Not reboot-stable on cloud VPS that regenerate `/etc/machine-id` on a
/// cloned image — prefer [`product_uuid`] for reboot-critical
/// fingerprints. Kept because it is the historical fingerprint factor
/// and is universally present.
#[cfg(target_os = "linux")]
pub fn machine_id() -> Result<String, PlatformIdError> {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let t = s.trim();
            if !t.is_empty() {
                return Ok(t.to_string());
            }
        }
    }
    Err(PlatformIdError::MachineId(
        "neither /etc/machine-id nor /var/lib/dbus/machine-id readable".into(),
    ))
}

/// Stable per-installation machine identifier (see the module table).
#[cfg(target_os = "windows")]
pub fn machine_id() -> Result<String, PlatformIdError> {
    let out = std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .map_err(|e| PlatformIdError::MachineId(format!("reg query MachineGuid: {e}")))?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if let Some(idx) = line.find("REG_SZ") {
            let v = line[idx + 6..].trim();
            if !v.is_empty() {
                return Ok(v.to_string());
            }
        }
    }
    Err(PlatformIdError::MachineId(
        "MachineGuid not found in registry output".into(),
    ))
}

/// Stable per-installation machine identifier (see the module table).
#[cfg(target_os = "macos")]
pub fn machine_id() -> Result<String, PlatformIdError> {
    // IOPlatformUUID is the stable per-Mac identifier.
    product_uuid().map_err(|e| PlatformIdError::MachineId(e.to_string()))
}

/// Stable per-installation machine identifier (see the module table).
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn machine_id() -> Result<String, PlatformIdError> {
    Err(PlatformIdError::Unsupported("machine_id"))
}

// ── product_uuid (DMI) ──────────────────────────────────────────────────────

/// DMI product UUID — the reboot-stable host identifier on cloud VPS.
///
/// Prefer this over [`machine_id`] for any fingerprint that must survive
/// a reboot or restore-from-snapshot.
///
/// **Linux no-DMI fallback**: reading the DMI node usually needs root; when
/// it is unreadable or empty this returns [`machine_id`] instead (kept for
/// compatibility with data sealed by earlier releases). The caller cannot
/// tell the two apart from the value;
/// [`HostFactors::binding_strength`](crate::HostFactors::binding_strength)
/// reports it.
#[cfg(target_os = "linux")]
pub fn product_uuid() -> Result<String, PlatformIdError> {
    if let Some(t) = read_dmi() {
        return Ok(t);
    }
    machine_id().map_err(|e| {
        PlatformIdError::ProductUuid(format!(
            "product_uuid unreadable and machine-id fallback failed: {e}"
        ))
    })
}

#[cfg(target_os = "linux")]
fn read_dmi() -> Option<String> {
    let s = std::fs::read_to_string("/sys/class/dmi/id/product_uuid").ok()?;
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// True if the Linux DMI node is readable and non-empty (so
/// [`product_uuid`] did not fall back to [`machine_id`]).
#[cfg(target_os = "linux")]
pub(crate) fn dmi_readable() -> bool {
    read_dmi().is_some()
}

/// DMI product UUID, the reboot-stable host identifier (see the module table).
#[cfg(target_os = "windows")]
pub fn product_uuid() -> Result<String, PlatformIdError> {
    // wmic csproduct get uuid  →  "UUID\r\n<value>\r\n"
    let out = std::process::Command::new("wmic")
        .args(["csproduct", "get", "uuid"])
        .output()
        .map_err(|e| PlatformIdError::ProductUuid(format!("wmic csproduct: {e}")))?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let t = line.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("UUID") {
            continue;
        }
        // A real UUID line looks like "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX".
        if t.contains('-') && t.len() >= 32 {
            return Ok(t.to_string());
        }
    }
    Err(PlatformIdError::ProductUuid(
        "product UUID not found in wmic output".into(),
    ))
}

/// DMI product UUID, the reboot-stable host identifier (see the module table).
#[cfg(target_os = "macos")]
pub fn product_uuid() -> Result<String, PlatformIdError> {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg("ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/{print $3}'")
        .output()
        .map_err(|e| PlatformIdError::ProductUuid(format!("ioreg: {e}")))?;
    let s = String::from_utf8_lossy(&out.stdout)
        .trim()
        .trim_matches('"')
        .to_string();
    if s.is_empty() {
        Err(PlatformIdError::ProductUuid("IOPlatformUUID empty".into()))
    } else {
        Ok(s)
    }
}

/// DMI product UUID, the reboot-stable host identifier (see the module table).
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn product_uuid() -> Result<String, PlatformIdError> {
    Err(PlatformIdError::Unsupported("product_uuid"))
}

// ── primary_mac ─────────────────────────────────────────────────────────────

/// First non-loopback, non-zero MAC address, lowercased.
///
/// On Linux interfaces are sorted by name so the result is deterministic
/// across calls. Not reboot-stable on every cloud VPS (VirtIO NIC MAC may
/// change) — it is a fingerprint *factor*, not a sole identifier.
#[cfg(target_os = "linux")]
pub fn primary_mac() -> Result<String, PlatformIdError> {
    let entries = std::fs::read_dir("/sys/class/net")
        .map_err(|e| PlatformIdError::PrimaryMac(format!("read /sys/class/net: {e}")))?;
    let mut candidates: Vec<(String, String)> = Vec::new();
    for ent in entries.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if name == "lo" || name.is_empty() {
            continue;
        }
        if let Ok(mac) = std::fs::read_to_string(ent.path().join("address")) {
            let mac = mac.trim().to_ascii_lowercase();
            if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                candidates.push((name, mac));
            }
        }
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    candidates
        .into_iter()
        .next()
        .map(|(_, mac)| mac)
        .ok_or_else(|| PlatformIdError::PrimaryMac("no non-loopback MAC found".into()))
}

/// First non-loopback, non-zero MAC address, lower-cased (see the module table).
#[cfg(target_os = "windows")]
pub fn primary_mac() -> Result<String, PlatformIdError> {
    // getmac /fo csv /nh outputs `"MAC","Transport"` lines per adapter.
    let out = std::process::Command::new("getmac")
        .args(["/fo", "csv", "/nh"])
        .output()
        .map_err(|e| PlatformIdError::PrimaryMac(format!("getmac: {e}")))?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(mac) = t.split(',').next() {
            let mac = mac.trim().trim_matches('"');
            if mac.contains('-') || mac.contains(':') {
                return Ok(mac.to_ascii_lowercase());
            }
        }
    }
    Err(PlatformIdError::PrimaryMac(
        "no MAC in getmac output".into(),
    ))
}

/// First non-loopback, non-zero MAC address, lower-cased (see the module table).
#[cfg(target_os = "macos")]
pub fn primary_mac() -> Result<String, PlatformIdError> {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg("ifconfig -a | awk '/ether /{print $2; exit}'")
        .output()
        .map_err(|e| PlatformIdError::PrimaryMac(format!("ifconfig: {e}")))?;
    let mac = String::from_utf8_lossy(&out.stdout)
        .trim()
        .to_ascii_lowercase();
    if mac.is_empty() {
        Err(PlatformIdError::PrimaryMac(
            "no ether line in ifconfig".into(),
        ))
    } else {
        Ok(mac)
    }
}

/// First non-loopback, non-zero MAC address, lower-cased (see the module table).
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn primary_mac() -> Result<String, PlatformIdError> {
    Err(PlatformIdError::Unsupported("primary_mac"))
}

// ── uid ─────────────────────────────────────────────────────────────────────

/// Best-effort process owner identifier. Never fails — falls back to
/// `"unknown-uid"`. Used only as a fingerprint factor; a missing uid
/// weakens the seal but does not break it.
pub fn uid() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/loginuid") {
            let s = s.trim();
            // 4294967295 == (u32::MAX) == "no loginuid set".
            if !s.is_empty() && s != "4294967295" {
                return s.to_string();
            }
        }
        std::env::var("USER").unwrap_or_else(|_| "unknown-uid".into())
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var("USER").unwrap_or_else(|_| "unknown-uid".into())
    }
    #[cfg(target_os = "windows")]
    {
        let user = std::env::var("USERNAME").unwrap_or_default();
        let domain = std::env::var("USERDOMAIN").unwrap_or_default();
        if user.is_empty() && domain.is_empty() {
            "unknown-uid".into()
        } else {
            format!("{domain}\\{user}")
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "unknown-uid".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These run on the dev/CI host. On a platform where a reader is
    // unavailable (e.g. DMI node unreadable without root) we accept a
    // clean Err — what we assert is determinism and non-emptiness when Ok.

    #[test]
    fn machine_id_is_stable_when_available() {
        match (machine_id(), machine_id()) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b, "two reads must match");
                assert!(!a.is_empty());
            }
            (Err(_), _) | (_, Err(_)) => { /* unavailable on this host — fine */ }
        }
    }

    #[test]
    fn product_uuid_is_stable_when_available() {
        match (product_uuid(), product_uuid()) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b);
                assert!(!a.is_empty());
            }
            (Err(_), _) | (_, Err(_)) => {}
        }
    }

    #[test]
    fn primary_mac_is_lowercase_when_available() {
        if let Ok(mac) = primary_mac() {
            assert_eq!(mac, mac.to_ascii_lowercase());
            assert!(!mac.is_empty());
            assert_ne!(mac, "00:00:00:00:00:00");
        }
    }

    #[test]
    fn uid_never_panics_and_never_empty() {
        let u = uid();
        assert!(!u.is_empty());
    }
}
