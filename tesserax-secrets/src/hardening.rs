//! Process hardening for hostile hosts (feature `hardening`): the only
//! module of this crate allowed to contain `unsafe`, and only for the four
//! libc calls std does not expose (`prctl` twice, `mlockall`, `setrlimit`).
//!
//! [`harden_process`] applies, best effort, and reports what took:
//!
//! - Linux: `prctl(PR_SET_DUMPABLE, 0)` (no core dump, no ptrace attach by
//!   non-root), `prctl(PR_SET_NO_NEW_PRIVS, 1)`, `mlockall(MCL_CURRENT |
//!   MCL_FUTURE)` (needs `CAP_IPC_LOCK` or a large `RLIMIT_MEMLOCK`), and
//!   writing `0` to `/proc/self/coredump_filter`.
//! - macOS: `setrlimit(RLIMIT_CORE, 0)` and `mlockall`.
//! - Other platforms: nothing; every knob is reported as not applied.
//!
//! Call once at start-up, before unsealing anything. The report is for
//! logging; do not gate behaviour on it.
#![allow(unsafe_code)]

use serde::Serialize;

/// What [`harden_process`] managed to apply.
#[derive(Debug, Clone, Serialize, Default)]
pub struct HardeningReport {
    /// Core dumps disabled.
    pub no_core_dump: bool,
    /// `no_new_privs` set.
    pub no_new_privs: bool,
    /// Pages locked in memory.
    pub mlock_pages: bool,
    /// Core-dump filter zeroed.
    pub coredump_filter_zeroed: bool,
    /// Free-form messages for each attempt that didn't succeed —
    /// shown in logs so operators understand why.
    pub notes: Vec<String>,
}

impl HardeningReport {
    /// `true` iff every applicable knob was set. Use only for
    /// reporting, not for gating.
    pub fn all_applied(&self) -> bool {
        self.no_core_dump && self.no_new_privs && self.mlock_pages && self.coredump_filter_zeroed
    }
}

/// Apply every safe hardening knob. Best-effort; logs notes for any
/// that don't take. Never panics.
pub fn harden_process() -> HardeningReport {
    let mut r = HardeningReport::default();
    disable_core_dumps(&mut r);
    set_no_new_privs(&mut r);
    lock_pages(&mut r);
    zero_coredump_filter(&mut r);
    r
}

#[cfg(target_os = "linux")]
fn disable_core_dumps(r: &mut HardeningReport) {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) is well-defined and async-signal-safe.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64) };
    if rc == 0 {
        r.no_core_dump = true;
    } else {
        r.notes
            .push(format!("PR_SET_DUMPABLE failed (errno={})", errno_now()));
    }
}

#[cfg(target_os = "macos")]
fn disable_core_dumps(r: &mut HardeningReport) {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid, initialised rlimit struct.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
    if rc == 0 {
        r.no_core_dump = true;
    } else {
        r.notes.push(format!(
            "setrlimit(RLIMIT_CORE,0) failed (errno={})",
            errno_now()
        ));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn disable_core_dumps(r: &mut HardeningReport) {
    r.notes
        .push("disable_core_dumps: unsupported on this platform".into());
}

#[cfg(target_os = "linux")]
fn set_no_new_privs(r: &mut HardeningReport) {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1) takes integer arguments only.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1_u64, 0_u64, 0_u64, 0_u64) };
    if rc == 0 {
        r.no_new_privs = true;
    } else {
        r.notes.push(format!(
            "PR_SET_NO_NEW_PRIVS failed (errno={})",
            errno_now()
        ));
    }
}

#[cfg(not(target_os = "linux"))]
fn set_no_new_privs(r: &mut HardeningReport) {
    r.notes.push("set_no_new_privs: linux-only knob".into());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lock_pages(r: &mut HardeningReport) {
    // MCL_CURRENT | MCL_FUTURE — pin current pages and all future
    // allocations. Requires CAP_IPC_LOCK on Linux unless RLIMIT_MEMLOCK
    // is generous; on EPERM we log and move on (deployment choice).
    // SAFETY: mlockall takes a flag word only.
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 {
        r.mlock_pages = true;
    } else {
        r.notes.push(format!(
            "mlockall failed (errno={} — needs CAP_IPC_LOCK or generous RLIMIT_MEMLOCK)",
            errno_now()
        ));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn lock_pages(r: &mut HardeningReport) {
    r.notes
        .push("lock_pages: unsupported on this platform".into());
}

#[cfg(target_os = "linux")]
fn zero_coredump_filter(r: &mut HardeningReport) {
    match std::fs::write("/proc/self/coredump_filter", b"00000000") {
        Ok(_) => r.coredump_filter_zeroed = true,
        Err(e) => r.notes.push(format!("write coredump_filter failed: {e}")),
    }
}

#[cfg(not(target_os = "linux"))]
fn zero_coredump_filter(r: &mut HardeningReport) {
    r.notes.push("zero_coredump_filter: linux-only".into());
}

#[cfg(unix)]
fn errno_now() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn errno_now() -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_returns_a_report_without_panic() {
        let r = harden_process();
        // On Linux as a normal user we typically get: no_core_dump +
        // no_new_privs OK, mlock fails (no caps), coredump_filter OK.
        // On Windows everything is a no-op. We just assert the call
        // doesn't panic and a notes vec exists.
        let _ = r.all_applied();
        let _ = r.notes.len();
    }

    #[test]
    fn report_serializes_to_json() {
        let r = HardeningReport::default();
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["no_core_dump"], false);
        assert!(v["notes"].is_array());
    }
}
