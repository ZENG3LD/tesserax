//! Shamir secret sharing (k-of-n) over GF(256).
//!
//! Classical Adi Shamir 1979 construction. Split a secret into N
//! shares such that any K of them reconstruct the secret and any
//! K-1 give zero information.
//!
//! ## Threat model fit
//!
//! Use when the secret (e.g. the SealedSecret unseal key on a
//! hostile-host deployment) shouldn't live on any single machine.
//! Split it K-of-N across peer hosts; reassemble at boot by
//! contacting K of them. Compromise of fewer than K hosts reveals
//! nothing.
//!
//! ## Math
//!
//! Each output BYTE of the secret is treated as a value in GF(256)
//! (Rijndael's field, polynomial 0x11b). We pick a random degree-(K-1)
//! polynomial `f(x)` with `f(0) = secret_byte`. Share i is `(i, f(i))`
//! for `i = 1..=N`. Reconstruction is Lagrange interpolation at `x=0`
//! over any K shares.
//!
//! Multi-byte secret = per-byte SSS sharing; each share holds the
//! same x-coordinate across all byte positions, so a share is just
//! `(i, payload[..])` where `payload[j]` is the y-coordinate of byte j.
//!
//! ## Implementation notes
//!
//! - GF(256) arithmetic uses log/exp tables built once at start
//!   (`std::sync::OnceLock`). Multiplication is `exp[log[a]+log[b]]`,
//!   classic.
//! - Random coefficients come from `getrandom` (system entropy).
//! - K and N must satisfy `1 <= K <= N <= 255` (GF(256) has 256
//!   elements; x-coordinate 0 is reserved for the secret, so usable
//!   share indices are 1..=255).
//! - Constant-time? NO. The reconstruction does table lookups indexed
//!   by share bytes. This matters if shares are themselves secret to
//!   the verifier; in our use case (operator collects shares from
//!   peer hosts they control) it doesn't.

use std::sync::OnceLock;

/// Split / reconstruct failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ShamirError {
    #[error("threshold k={k} must be >=1")]
    BadThresholdZero { k: u8 },
    #[error("share count n={n} must be >= threshold k={k}")]
    BadShareCount { k: u8, n: u8 },
    #[error("k+n out of range: k={k}, n={n} (need k<=n<=255)")]
    OutOfRange { k: u8, n: u8 },
    #[error("rng: {0}")]
    Rng(String),
    #[error("need at least {needed} shares to reconstruct, got {provided}")]
    NotEnoughShares { needed: usize, provided: usize },
    #[error("share x-coordinate must be nonzero (0 is reserved for the secret)")]
    ZeroShareIndex,
    #[error("duplicate share index {0}")]
    DuplicateShareIndex(u8),
    #[error("shares have inconsistent lengths")]
    InconsistentLengths,
}

/// One Shamir share. `x` is the share index (1..=255). `y_bytes` is
/// the payload — same length as the original secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// Share index, `1..=255`.
    pub x: u8,
    /// One y-coordinate per secret byte.
    pub y_bytes: Vec<u8>,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Share(x={}, <{} bytes redacted>)",
            self.x,
            self.y_bytes.len()
        )
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.y_bytes);
    }
}

/// Split `secret` into N shares, any K of which suffice to reconstruct.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>, ShamirError> {
    if k == 0 {
        return Err(ShamirError::BadThresholdZero { k });
    }
    if n < k {
        return Err(ShamirError::BadShareCount { k, n });
    }
    if n == 0 {
        return Err(ShamirError::OutOfRange { k, n });
    }
    // k, n are u8 so they're inherently <= 255; the OutOfRange error
    // variant keeps the legacy shape in case the types are widened
    // later.

    // For each byte of the secret we pick K-1 random coefficients
    // (a_1..a_{k-1}); a_0 is the secret byte. f(x) = a_0 + a_1 x +
    // a_2 x^2 + ... + a_{k-1} x^{k-1}.
    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            x,
            y_bytes: Vec::with_capacity(secret.len()),
        })
        .collect();

    let mut coeffs = vec![0u8; (k as usize).saturating_sub(1)];
    for &sec_byte in secret {
        if !coeffs.is_empty() {
            getrandom::fill(&mut coeffs).map_err(|e| ShamirError::Rng(e.to_string()))?;
        }
        for share in shares.iter_mut() {
            share.y_bytes.push(eval_poly(sec_byte, &coeffs, share.x));
        }
    }
    Ok(shares)
}

/// Reconstruct from K (or more) shares. Returns the original secret.
pub fn reconstruct(shares: &[Share], k: u8) -> Result<Vec<u8>, ShamirError> {
    if k == 0 {
        return Err(ShamirError::BadThresholdZero { k });
    }
    if shares.len() < k as usize {
        return Err(ShamirError::NotEnoughShares {
            needed: k as usize,
            provided: shares.len(),
        });
    }
    // Verify share well-formedness.
    if shares.iter().any(|s| s.x == 0) {
        return Err(ShamirError::ZeroShareIndex);
    }
    let expected_len = shares[0].y_bytes.len();
    if shares.iter().any(|s| s.y_bytes.len() != expected_len) {
        return Err(ShamirError::InconsistentLengths);
    }
    let mut seen = std::collections::HashSet::new();
    for s in shares.iter() {
        if !seen.insert(s.x) {
            return Err(ShamirError::DuplicateShareIndex(s.x));
        }
    }
    // Use only the first K shares (caller can pass more; extras are
    // ignored).
    let used = &shares[..k as usize];

    let mut secret = Vec::with_capacity(expected_len);
    for byte_idx in 0..expected_len {
        let mut acc: u8 = 0;
        for (i, s_i) in used.iter().enumerate() {
            let y_i = s_i.y_bytes[byte_idx];
            // Lagrange basis: l_i(0) = prod_{j != i} (-x_j) / (x_i - x_j)
            // In GF(256), negation is identity (char 2), so -x_j == x_j.
            // l_i(0) = prod_{j != i} x_j / (x_i + x_j).
            let mut num: u8 = 1;
            let mut den: u8 = 1;
            for (j, s_j) in used.iter().enumerate() {
                if i == j {
                    continue;
                }
                num = gf_mul(num, s_j.x);
                den = gf_mul(den, s_i.x ^ s_j.x); // a - b == a XOR b in GF(2^n)
            }
            let inv_den = gf_inv(den);
            let basis = gf_mul(num, inv_den);
            acc ^= gf_mul(y_i, basis);
        }
        secret.push(acc);
    }
    Ok(secret)
}

// ── GF(256) arithmetic with log/exp tables ──────────────────────────

const PRIM_POLY: u16 = 0x11b; // AES Rijndael's primitive polynomial.
const GENERATOR: u8 = 0x03; // Standard generator for that polynomial.

struct GfTables {
    log: [u8; 256],
    exp: [u8; 512], // doubled so we don't have to mod 255 on add
}

static GF: OnceLock<GfTables> = OnceLock::new();

fn gf() -> &'static GfTables {
    GF.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        // Build tables by successive multiplication by GENERATOR=0x03
        // (a primitive element of GF(256) with the AES polynomial).
        // x starts at 1 = GENERATOR^0.
        let mut x: u8 = 1;
        for (i, slot) in exp.iter_mut().take(255).enumerate() {
            *slot = x;
            log[x as usize] = i as u8;
            // Multiply by generator (0x03) using the bit-wise shift-
            // and-reduce; do it inline so we don't depend on gf_mul
            // (which itself depends on this table).
            x = gf_mul_raw(x, GENERATOR);
        }
        // Duplicate the table to avoid `(a + b) % 255` on multiply.
        exp.copy_within(0..255, 255);
        // log[0] is undefined (no logarithm of 0); leave as 0.
        GfTables { log, exp }
    })
}

/// Direct GF(256) multiplication via shift-and-reduce. Used only to
/// bootstrap the log/exp tables — runtime path uses gf_mul which
/// goes through the tables.
fn gf_mul_raw(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut aa: u8 = a;
    let mut bb: u8 = b;
    while bb != 0 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let high = aa & 0x80;
        aa <<= 1;
        if high != 0 {
            aa ^= (PRIM_POLY & 0xff) as u8;
        }
        bb >>= 1;
    }
    result
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = gf();
    let li = t.log[a as usize] as usize + t.log[b as usize] as usize;
    t.exp[li]
}

fn gf_inv(a: u8) -> u8 {
    // a * a^(254) = a^255 = 1 in GF(256)*.
    // So a^-1 = a^(254) = exp[255 - log[a]] = exp[255 - log[a]].
    // exp table is doubled so the index is fine even when log[a] is 0.
    if a == 0 {
        // Division by zero in field — should never happen with
        // distinct, nonzero share x-coords. Return 0 defensively.
        return 0;
    }
    let t = gf();
    t.exp[255 - t.log[a as usize] as usize]
}

/// Evaluate the polynomial `f(x) = secret + a_1 x + a_2 x^2 + ... + a_{k-1} x^{k-1}`
/// at point `x` over GF(256). Coefficients in `coeffs[i]` are a_{i+1}.
fn eval_poly(secret: u8, coeffs: &[u8], x: u8) -> u8 {
    let mut acc = secret;
    let mut x_pow = 1u8;
    for &c in coeffs {
        x_pow = gf_mul(x_pow, x);
        acc ^= gf_mul(c, x_pow);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_mul_identity_zero() {
        assert_eq!(gf_mul(0, 5), 0);
        assert_eq!(gf_mul(5, 0), 0);
        assert_eq!(gf_mul(1, 5), 5);
        assert_eq!(gf_mul(5, 1), 5);
    }

    #[test]
    fn gf_inv_round_trip() {
        for a in 1u8..=255 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "a={a} inv={inv}");
        }
    }

    #[test]
    fn split_then_reconstruct_with_exact_k() {
        let secret = b"hello world";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        // Use shares 1, 3, 4 (any 3 of 5).
        let chosen = vec![shares[0].clone(), shares[2].clone(), shares[3].clone()];
        let back = reconstruct(&chosen, 3).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn split_then_reconstruct_with_more_than_k() {
        let secret = b"k=2";
        let shares = split(secret, 2, 4).unwrap();
        // Pass all 4; reconstruct only uses first K=2.
        let back = reconstruct(&shares, 2).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn fewer_than_k_shares_rejected() {
        let secret = b"abc";
        let shares = split(secret, 3, 5).unwrap();
        let too_few = vec![shares[0].clone(), shares[1].clone()];
        let err = reconstruct(&too_few, 3).unwrap_err();
        assert!(matches!(err, ShamirError::NotEnoughShares { .. }));
    }

    #[test]
    fn wrong_k_minus_one_shares_give_garbage() {
        // Reconstruction with FEWER than K shares (passing them as if
        // they were enough by lying about k) should produce garbage,
        // not the original. We do this by reconstructing with k=2
        // shares but the polynomial was degree 2 (k=3 split).
        let secret = b"\x42\x42\x42";
        let shares = split(secret, 3, 5).unwrap();
        let two = vec![shares[0].clone(), shares[1].clone()];
        let garbage = reconstruct(&two, 2).unwrap();
        // It WILL succeed (2 of 2 shares for a k=2 reconstruction is
        // fine math), but the answer is NOT the secret because the
        // polynomial degree doesn't match.
        assert_ne!(garbage, secret);
    }

    #[test]
    fn duplicate_share_index_rejected() {
        let s = Share {
            x: 1,
            y_bytes: vec![1, 2, 3],
        };
        let s2 = s.clone();
        let err = reconstruct(&[s, s2], 2).unwrap_err();
        assert!(matches!(err, ShamirError::DuplicateShareIndex(1)));
    }

    #[test]
    fn zero_x_share_rejected() {
        let s = Share {
            x: 0,
            y_bytes: vec![1, 2, 3],
        };
        let s2 = Share {
            x: 2,
            y_bytes: vec![4, 5, 6],
        };
        let err = reconstruct(&[s, s2], 2).unwrap_err();
        assert!(matches!(err, ShamirError::ZeroShareIndex));
    }

    #[test]
    fn k_zero_rejected() {
        let err = split(b"x", 0, 1).unwrap_err();
        assert!(matches!(err, ShamirError::BadThresholdZero { .. }));
    }

    #[test]
    fn n_less_than_k_rejected() {
        let err = split(b"x", 5, 3).unwrap_err();
        assert!(matches!(err, ShamirError::BadShareCount { .. }));
    }

    #[test]
    fn long_secret_round_trips() {
        let secret: Vec<u8> = (0..1024).map(|i| (i & 0xff) as u8).collect();
        let shares = split(&secret, 4, 7).unwrap();
        // Pick a random-ish subset of 4.
        let chosen = vec![
            shares[1].clone(),
            shares[3].clone(),
            shares[5].clone(),
            shares[6].clone(),
        ];
        let back = reconstruct(&chosen, 4).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn empty_secret_works() {
        let shares = split(b"", 2, 3).unwrap();
        // Each share has empty y_bytes.
        assert!(shares.iter().all(|s| s.y_bytes.is_empty()));
        let back = reconstruct(&shares[..2], 2).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn k_equals_one_is_trivial_share() {
        // K=1 means every share is the secret itself (no entropy).
        // Useful as a degenerate test — should still round-trip.
        let secret = b"public";
        let shares = split(secret, 1, 3).unwrap();
        for s in &shares {
            assert_eq!(s.y_bytes, secret);
        }
        let back = reconstruct(&shares[..1], 1).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn k_equals_n_requires_all() {
        let secret = b"all-or-nothing";
        let shares = split(secret, 5, 5).unwrap();
        // Drop one — must fail.
        let err = reconstruct(&shares[..4], 5).unwrap_err();
        assert!(matches!(err, ShamirError::NotEnoughShares { .. }));
        // All 5 → success.
        let back = reconstruct(&shares, 5).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn random_subset_of_k_works_for_all_combinations() {
        // 3-of-5: every 3-subset must reconstruct.
        let secret = b"every-combo-works";
        let shares = split(secret, 3, 5).unwrap();
        for i in 0..5 {
            for j in (i + 1)..5 {
                for kk in (j + 1)..5 {
                    let chosen = vec![shares[i].clone(), shares[j].clone(), shares[kk].clone()];
                    let back = reconstruct(&chosen, 3).unwrap();
                    assert_eq!(back, secret, "subset {i},{j},{kk} failed");
                }
            }
        }
    }
}
