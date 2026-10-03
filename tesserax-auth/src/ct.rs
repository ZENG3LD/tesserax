//! Constant-time compare and HMAC-SHA256 for this crate.
//!
//! The implementations live in the root (`tesserax::ct`, one copy for the
//! whole family); this module re-exports them and adds hex helpers. Every
//! comparison of a presented credential against stored material in this
//! crate goes through here (or through [`KeyHash`](crate::KeyHash)'s
//! [`ct_matches`](crate::KeyHash::ct_matches), which calls into this
//! module).

pub use tesserax::ct::{ct_eq, ct_eq_str, hmac_sha256};

pub(crate) use tesserax::ct::sha256;

/// Constant-time equality of two 32-byte digests.
pub(crate) fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    tesserax::ct::ct_eq_array(a, b)
}

/// Lower-case hex.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Parses exactly 64 hex digits.
pub(crate) fn from_hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, &[hi_c, lo_c]) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_val(hi_c)?;
        let lo = hex_val(lo_c)?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let d = sha256(b"x");
        assert_eq!(from_hex_32(&to_hex(&d)), Some(d));
        assert_eq!(from_hex_32(&to_hex(&d).to_uppercase()), Some(d));
        assert_eq!(from_hex_32("zz"), None);
        assert_eq!(from_hex_32(&"g".repeat(64)), None);
    }

    #[test]
    fn reexported_compare_works() {
        assert!(ct_eq_str("a", "a"));
        assert!(!ct_eq_str("a", "b"));
        assert_eq!(hmac_sha256(b"k", b"m").len(), 32);
    }
}
