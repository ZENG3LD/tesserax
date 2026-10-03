//! Gorilla chunk codec — delta-of-delta timestamps + XOR floats.
//!
//! Implements the Facebook Gorilla compression scheme (VLDB 2015) in
//! ~one file. Built in-tree rather than pulled from a crate: the
//! algorithm is fully specified, it's a format primitive (not a
//! framework), and the available crates (`tsz` 0.1.4) are stale. Behind
//! the [`ChunkCodec`] trait so the impl can be swapped without touching
//! the store.
//!
//! ## Timestamp encoding (delta-of-delta)
//!
//! First sample: full 64-bit timestamp. Second: the delta from the
//! first (zigzag varint-ish — here a plain signed write). Thereafter,
//! `D = (t_n - t_{n-1}) - (t_{n-1} - t_{n-2})`:
//! - `D == 0`            → `0`                          (1 bit)
//! - `D ∈ [-63, 64]`     → `10`  + 7-bit signed         (9 bits)
//! - `D ∈ [-255, 256]`   → `110` + 9-bit signed         (12 bits)
//! - `D ∈ [-2047, 2048]` → `1110`+ 12-bit signed        (16 bits)
//! - else                → `1111`+ 32-bit signed        (36 bits)
//!
//! At a fixed scrape interval `D == 0` for almost every sample → 1 bit.
//!
//! ## Value encoding (XOR floats)
//!
//! First value: full 64-bit IEEE-754. Thereafter `xor = bits(v_n) ^
//! bits(v_{n-1})`:
//! - `xor == 0` → `0`                                    (1 bit)
//! - else       → `1`, then either
//!   - `0` + meaningful bits reusing the previous leading/trailing
//!     window (when it fits), or
//!   - `1` + 5-bit leading-zero count + 6-bit meaningful length +
//!     the meaningful bits.

use super::model::Sample;

/// Chunk decode failures.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The blob ended mid-sample.
    #[error("truncated chunk: ran out of bits while decoding")]
    Truncated,
    /// The blob is malformed.
    #[error("corrupt chunk: {0}")]
    Corrupt(String),
}

/// Pluggable chunk codec. The store encodes a run of samples into one
/// opaque blob and decodes it back. Gorilla is the only impl today.
pub trait ChunkCodec {
    /// Encodes a run of samples.
    fn encode(samples: &[Sample]) -> Vec<u8>;
    /// Decodes a blob produced by [`Self::encode`].
    fn decode(blob: &[u8]) -> Result<Vec<Sample>, CodecError>;
}

// ── bit IO ──────────────────────────────────────────────────────────────────

#[derive(Default)]
struct BitWriter {
    buf: Vec<u8>,
    cur: u8,
    nbits: u8, // bits filled in `cur` (0..=7)
}

impl BitWriter {
    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.cur |= 1 << (7 - self.nbits);
        }
        self.nbits += 1;
        if self.nbits == 8 {
            self.buf.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// Write the low `count` bits of `value`, MSB-first.
    fn write_bits(&mut self, value: u64, count: u8) {
        for i in (0..count).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.buf.push(self.cur);
        }
        self.buf
    }
}

struct BitReader<'a> {
    buf: &'a [u8],
    byte: usize,
    bit: u8,
}

impl<'a> BitReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            byte: 0,
            bit: 0,
        }
    }

    fn read_bit(&mut self) -> Result<bool, CodecError> {
        if self.byte >= self.buf.len() {
            return Err(CodecError::Truncated);
        }
        let b = (self.buf[self.byte] >> (7 - self.bit)) & 1 == 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.byte += 1;
        }
        Ok(b)
    }

    fn read_bits(&mut self, count: u8) -> Result<u64, CodecError> {
        let mut v = 0u64;
        for _ in 0..count {
            v = (v << 1) | self.read_bit()? as u64;
        }
        Ok(v)
    }
}

// ── signed helpers ──────────────────────────────────────────────────────────

/// Sign-extend the low `bits` of `v` to i64.
fn sign_extend(v: u64, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

/// Mask the low `bits` of a signed value for writing.
fn low_bits(v: i64, bits: u8) -> u64 {
    (v as u64) & ((1u64 << bits) - 1)
}

// ── Gorilla codec ─────────────────────────────────────────────────────────────

/// The Gorilla chunk codec (the on-disk chunk format).
pub struct Gorilla;

impl ChunkCodec for Gorilla {
    fn encode(samples: &[Sample]) -> Vec<u8> {
        let mut w = BitWriter::default();
        // Header: u32 sample count (LE) so decode knows when to stop —
        // simpler + safer than a stream-end sentinel.
        let n = samples.len() as u32;
        for b in n.to_le_bytes() {
            w.write_bits(b as u64, 8);
        }
        if samples.is_empty() {
            return w.finish();
        }

        // First sample: full timestamp (64) + full value bits (64).
        let mut prev_ts = samples[0].ts_ms;
        w.write_bits(prev_ts as u64, 64);
        let mut prev_val_bits = samples[0].value.to_bits();
        w.write_bits(prev_val_bits, 64);

        let mut prev_delta: i64 = 0;
        let mut prev_leading: u32 = u32::MAX; // sentinel: no window yet
        let mut prev_trailing: u32 = 0;

        for s in &samples[1..] {
            // ── timestamp: delta-of-delta ──
            let delta = s.ts_ms - prev_ts;
            let dod = delta - prev_delta;
            if dod == 0 {
                w.write_bit(false);
            } else if (-63..=64).contains(&dod) {
                w.write_bits(0b10, 2);
                w.write_bits(low_bits(dod, 7), 7);
            } else if (-255..=256).contains(&dod) {
                w.write_bits(0b110, 3);
                w.write_bits(low_bits(dod, 9), 9);
            } else if (-2047..=2048).contains(&dod) {
                w.write_bits(0b1110, 4);
                w.write_bits(low_bits(dod, 12), 12);
            } else {
                w.write_bits(0b1111, 4);
                w.write_bits(low_bits(dod, 32), 32);
            }
            prev_delta = delta;
            prev_ts = s.ts_ms;

            // ── value: XOR ──
            let bits = s.value.to_bits();
            let xor = bits ^ prev_val_bits;
            if xor == 0 {
                w.write_bit(false);
            } else {
                w.write_bit(true);
                let leading = xor.leading_zeros();
                let trailing = xor.trailing_zeros();
                // Reuse the previous window when the new meaningful bits
                // fall inside it.
                if prev_leading != u32::MAX && leading >= prev_leading && trailing >= prev_trailing
                {
                    w.write_bit(false);
                    let meaningful = 64 - prev_leading - prev_trailing;
                    w.write_bits(xor >> prev_trailing, meaningful as u8);
                } else {
                    w.write_bit(true);
                    // 5-bit leading count, 6-bit meaningful length.
                    let meaningful = 64 - leading - trailing;
                    w.write_bits(leading as u64, 5);
                    // length stored as meaningful (1..=64); 6 bits holds 0..63
                    // so store meaningful-1? Gorilla stores the raw length in
                    // 6 bits and relies on never being 64 here (xor!=0 ⇒
                    // meaningful>=1; a single-bit flip ⇒ meaningful==1).
                    // meaningful can be up to 64 → 6 bits can't hold 64.
                    // Clamp: 64 wraps to 0 in 6 bits; on decode 0 ⇒ 64.
                    w.write_bits((meaningful & 0x3F) as u64, 6);
                    w.write_bits(xor >> trailing, meaningful as u8);
                    prev_leading = leading;
                    prev_trailing = trailing;
                }
            }
            prev_val_bits = bits;
        }

        w.finish()
    }

    fn decode(blob: &[u8]) -> Result<Vec<Sample>, CodecError> {
        let mut r = BitReader::new(blob);
        let mut count_bytes = [0u8; 4];
        for b in count_bytes.iter_mut() {
            *b = r.read_bits(8)? as u8;
        }
        let n = u32::from_le_bytes(count_bytes) as usize;
        let mut out = Vec::with_capacity(n);
        if n == 0 {
            return Ok(out);
        }

        let mut ts = r.read_bits(64)? as i64;
        let mut val_bits = r.read_bits(64)?;
        out.push(Sample {
            ts_ms: ts,
            value: f64::from_bits(val_bits),
        });

        let mut prev_delta: i64 = 0;
        let mut leading: u32 = 0;
        let mut trailing: u32 = 0;

        for _ in 1..n {
            // ── timestamp ──
            let dod: i64 = if !r.read_bit()? {
                0
            } else if !r.read_bit()? {
                // `10`
                sign_extend(r.read_bits(7)?, 7)
            } else if !r.read_bit()? {
                // `110`
                sign_extend(r.read_bits(9)?, 9)
            } else if !r.read_bit()? {
                // `1110`
                sign_extend(r.read_bits(12)?, 12)
            } else {
                // `1111`
                sign_extend(r.read_bits(32)?, 32)
            };
            let delta = prev_delta + dod;
            ts += delta;
            prev_delta = delta;

            // ── value ──
            if !r.read_bit()? {
                // unchanged
            } else if !r.read_bit()? {
                // reuse previous window
                let meaningful = 64 - leading - trailing;
                let m = r.read_bits(meaningful as u8)?;
                val_bits ^= m << trailing;
            } else {
                leading = r.read_bits(5)? as u32;
                let raw_len = r.read_bits(6)? as u32;
                let meaningful = if raw_len == 0 { 64 } else { raw_len };
                trailing = 64 - leading - meaningful;
                let m = r.read_bits(meaningful as u8)?;
                val_bits ^= m << trailing;
            }
            out.push(Sample {
                ts_ms: ts,
                value: f64::from_bits(val_bits),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(samples: &[Sample]) {
        let blob = Gorilla::encode(samples);
        let back = Gorilla::decode(&blob).expect("decode");
        assert_eq!(back.len(), samples.len());
        for (a, b) in samples.iter().zip(back.iter()) {
            assert_eq!(a.ts_ms, b.ts_ms, "ts mismatch");
            // Exact bit-equality: XOR codec is lossless including NaN bits.
            assert_eq!(a.value.to_bits(), b.value.to_bits(), "value mismatch");
        }
    }

    #[test]
    fn empty() {
        roundtrip(&[]);
    }

    #[test]
    fn single() {
        roundtrip(&[Sample {
            ts_ms: 1_700_000_000_000,
            value: 42.5,
        }]);
    }

    #[test]
    fn fixed_interval_constant_value() {
        // The compression best case: 30s steps, unchanged value.
        let mut s = Vec::new();
        let mut t = 1_700_000_000_000i64;
        for _ in 0..120 {
            s.push(Sample {
                ts_ms: t,
                value: 7.0,
            });
            t += 30_000;
        }
        roundtrip(&s);
        // After the first sample, each subsequent one should cost ~2 bits
        // (1 dod + 1 value). 120 samples => header(4B) + 16B first +
        // ~30B tail. Assert it's far under the 120*16=1920 raw bytes.
        let blob = Gorilla::encode(&s);
        assert!(
            blob.len() < 100,
            "expected tight compression, got {}",
            blob.len()
        );
    }

    #[test]
    fn varying_values_and_jitter() {
        let mut s = Vec::new();
        let mut t = 1_700_000_000_000i64;
        for i in 0..200 {
            // jittered interval + drifting value
            t += 30_000 + (i % 5) - 2;
            s.push(Sample {
                ts_ms: t,
                value: (i as f64) * 1.7 + 0.001,
            });
        }
        roundtrip(&s);
    }

    #[test]
    fn negative_and_special_floats() {
        roundtrip(&[
            Sample {
                ts_ms: 1000,
                value: -2.5,
            },
            Sample {
                ts_ms: 2000,
                value: 0.0,
            },
            Sample {
                ts_ms: 3000,
                value: f64::INFINITY,
            },
            Sample {
                ts_ms: 4000,
                value: -0.0,
            },
            Sample {
                ts_ms: 5000,
                value: 1e300,
            },
        ]);
    }

    #[test]
    fn counter_like_monotonic() {
        let mut s = Vec::new();
        let mut t = 1_700_000_000_000i64;
        let mut v = 0.0;
        for _ in 0..150 {
            s.push(Sample { ts_ms: t, value: v });
            t += 30_000;
            v += 1.0;
        }
        roundtrip(&s);
    }

    #[test]
    fn truncated_blob_errors() {
        let s = vec![
            Sample {
                ts_ms: 1000,
                value: 1.0,
            },
            Sample {
                ts_ms: 2000,
                value: 2.0,
            },
        ];
        let blob = Gorilla::encode(&s);
        // Lop off the tail — decode should fail cleanly, not panic.
        let truncated = &blob[..blob.len() - 1];
        let _ = Gorilla::decode(truncated); // may Ok with fewer or Err; must not panic
        // Header says 2 samples but bits are short → Truncated.
        let very_short = &blob[..5];
        assert!(matches!(
            Gorilla::decode(very_short),
            Err(CodecError::Truncated)
        ));
    }
}
