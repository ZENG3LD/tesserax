//! The single constant-time compare of the family, and HMAC-SHA256.
//!
//! Every comparison of a presented secret against stored material in any
//! tesserax crate goes through this module. Both sides of [`ct_eq`] are
//! hashed with SHA-256 first and the two 32-byte digests are folded with
//! `subtle`, so neither the length nor the position of the first differing
//! byte shows up in timing. It lives in the root (pure, wasm-clean: sha2 +
//! subtle only) so crates that must not depend on each other share one
//! implementation.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Constant-time equality of two byte strings of any length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let da = Sha256::digest(a);
    let db = Sha256::digest(b);
    bool::from(da.as_slice().ct_eq(db.as_slice()))
}

/// [`ct_eq`] over UTF-8 strings.
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    ct_eq(a.as_bytes(), b.as_bytes())
}

/// Constant-time equality of two fixed-size arrays (digests, prefixes).
pub fn ct_eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256 (RFC 2104). Infallible for every key length.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(msg)
        .finalize();
    let out: [u8; 32] = Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into();
    wipe(&mut k);
    wipe(&mut ipad);
    wipe(&mut opad);
    out
}

/// Best-effort wipe of a stack buffer (the full zeroize crate is not a
/// root dependency).
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 4231 test cases 1, 2, 3, 4, 6, 7.
    #[test]
    fn hmac_sha256_rfc4231_vectors() {
        let cases: [(Vec<u8>, Vec<u8>, &str); 6] = [
            (vec![0x0b; 20], b"Hi There".to_vec(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (vec![0xaa; 20], vec![0xdd; 50], "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            (
                (1u8..=25).collect(),
                vec![0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                vec![0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, msg, want) in cases {
            assert_eq!(hmac_sha256(&key, &msg).to_vec(), unhex(want));
        }
    }

    /// Property: `ct_eq(a, b) == (a == b)` for many pseudo-random vectors,
    /// including equal pairs, equal-length pairs and prefix pairs.
    #[test]
    fn ct_eq_agrees_with_plain_equality() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..5_000 {
            let len_a = (next() % 48) as usize;
            let a: Vec<u8> = (0..len_a).map(|_| next() as u8).collect();
            let b: Vec<u8> = match next() % 4 {
                0 => a.clone(),
                1 => {
                    let mut b = a.clone();
                    if let Some(x) = b.get_mut((next() as usize) % len_a.max(1)) {
                        *x ^= 1 << (next() % 8);
                    }
                    b
                }
                2 => a[..(next() as usize) % (len_a + 1)].to_vec(),
                _ => (0..(next() % 48)).map(|_| next() as u8).collect(),
            };
            assert_eq!(ct_eq(&a, &b), a == b, "a={a:?} b={b:?}");
        }
        assert!(ct_eq_str("", ""));
        assert!(!ct_eq_str("a", ""));
    }
}
