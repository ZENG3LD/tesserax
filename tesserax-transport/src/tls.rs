//! TLS: certificate pins (always) and, with feature `tls`, the HTTPS accept
//! loop of a tesserax server.
//!
//! A pin is the lowercase hex SHA-256 of a certificate's
//! SubjectPublicKeyInfo ([`compute_spki_pin`] over
//! [`spki_of_certificate`]): trust follows the key, so a peer can renew its
//! certificate with the same key without a new pin. For pins written for
//! the earlier scheme, which hashed the whole leaf certificate, the SHA-256
//! of the full DER also matches ([`SpkiPin::matches_certificate`]); both
//! are full-strength digests, accepting either admits nothing a pin did not
//! name.
//!
//! Feature `tls`:
//!
//! - `load_server_config` reads the PEM chain and key of a
//!   `tesserax::TlsConfig`, advertises ALPN `h2` then `http/1.1`, and, when
//!   the config lists client pins, requires a client certificate matching
//!   one (chain validity is deliberately not checked: the pin is the
//!   trust).
//! - `serve_tls` runs the accept loop: TLS handshake with a 10 s
//!   deadline off the accept path, HTTP/1.1 + HTTP/2, graceful drain on
//!   shutdown.
//! - `TlsDriver` plugs it into a `ServerBuilder` (or
//!   `TransportExt::with_tls`).
//! - `pinned_client_config` is the client side: a rustls client config
//!   that accepts exactly the servers whose certificate matches a pin.
//!
//! Crypto provider: `ring`, passed explicitly, so no process-wide default
//! provider has to be installed.

use tesserax::ct::{ct_eq_array, sha256};
use thiserror::Error;

/// Why a pin string was refused.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PinError {
    /// Not 64 hex characters.
    #[error("pin must be 64 hex characters (sha256), got {0:?}")]
    BadHex(String),
}

/// A set of certificate pins (SHA-256 digests). Cheap to clone.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct SpkiPin {
    pins: Vec<[u8; 32]>,
}

impl std::fmt::Debug for SpkiPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.pins.iter().map(|p| hex(p)))
            .finish()
    }
}

impl SpkiPin {
    /// No pins.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins from hex strings (any case).
    pub fn from_hex<I, S>(pins: I) -> Result<Self, PinError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Self::new();
        for p in pins {
            out.push(p.as_ref())?;
        }
        Ok(out)
    }

    /// Adds one hex pin.
    pub fn push(&mut self, hex_pin: &str) -> Result<(), PinError> {
        let digest = parse_hex32(hex_pin).ok_or_else(|| PinError::BadHex(hex_pin.to_owned()))?;
        self.pins.push(digest);
        Ok(())
    }

    /// Adds the SPKI pin of a DER certificate; false if the certificate
    /// cannot be parsed.
    pub fn push_certificate(&mut self, cert_der: &[u8]) -> bool {
        match spki_of_certificate(cert_der) {
            Some(spki) => {
                self.pins.push(sha256(spki));
                true
            }
            None => false,
        }
    }

    /// True when no pin is set.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Number of pins.
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Constant-time membership of a digest; every pin is compared.
    pub fn contains(&self, digest: &[u8; 32]) -> bool {
        self.pins
            .iter()
            .fold(false, |hit, p| hit | ct_eq_array(p, digest))
    }

    /// [`contains`](Self::contains) for a hex digest (any case); false for
    /// anything that is not 64 hex characters.
    pub fn contains_hex(&self, hex_pin: &str) -> bool {
        parse_hex32(hex_pin).is_some_and(|d| self.contains(&d))
    }

    /// True when the SHA-256 of the certificate's SubjectPublicKeyInfo, or
    /// of the whole DER certificate, is pinned.
    pub fn matches_certificate(&self, cert_der: &[u8]) -> bool {
        let by_key = spki_of_certificate(cert_der).is_some_and(|spki| self.contains(&sha256(spki)));
        let by_cert = self.contains(&sha256(cert_der));
        by_key | by_cert
    }
}

/// Lowercase hex SHA-256 of SubjectPublicKeyInfo DER bytes.
pub fn compute_spki_pin(spki_der: &[u8]) -> String {
    hex(&sha256(spki_der))
}

/// The SubjectPublicKeyInfo (tag and length included) of an X.509 DER
/// certificate, or `None` if the bytes are not shaped like one.
pub fn spki_of_certificate(cert_der: &[u8]) -> Option<&[u8]> {
    let cert = Der::read(cert_der)?.expect(0x30)?;
    let mut tbs = Der::read(cert.content)?.expect(0x30)?.content;
    // Optional explicit version [0].
    let first = Der::read(tbs)?;
    if first.tag == 0xA0 {
        tbs = first.rest;
    }
    // serialNumber, signature, issuer, validity, subject.
    for expected in [0x02, 0x30, 0x30, 0x30, 0x30] {
        tbs = Der::read(tbs)?.expect(expected)?.rest;
    }
    Some(Der::read(tbs)?.expect(0x30)?.whole)
}

/// One DER element.
struct Der<'a> {
    tag: u8,
    content: &'a [u8],
    whole: &'a [u8],
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    fn read(input: &'a [u8]) -> Option<Self> {
        let (&tag, rest) = input.split_first()?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            (len, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        let header = input.len() - rest.len();
        Some(Self {
            tag,
            content: &rest[..len],
            whole: &input[..header + len],
            rest: &rest[len..],
        })
    }

    fn expect(self, tag: u8) -> Option<Self> {
        (self.tag == tag).then_some(self)
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(feature = "tls")]
mod rustls_side;
#[cfg(feature = "tls")]
pub use rustls_side::{
    HANDSHAKE_TIMEOUT, TlsDriver, TlsError, load_server_config, pinned_client_config, serve_tls,
    server_config_from_pem,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_is_64_lowercase_hex() {
        let pin = compute_spki_pin(b"some-spki-bytes");
        assert_eq!(pin.len(), 64);
        assert!(
            pin.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert_eq!(
            compute_spki_pin(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn from_hex_rejects_bad_length_and_non_hex() {
        assert!(SpkiPin::from_hex(["abc"]).is_err());
        assert!(SpkiPin::from_hex(["deadbeefcafe".repeat(8)]).is_err());
        let mut s = "a".repeat(64);
        s.replace_range(0..1, "z");
        assert!(SpkiPin::from_hex([s]).is_err());
    }

    #[test]
    fn contains_matches_case_insensitive_and_rejects_short_input() {
        let pin = "a".repeat(64);
        let store = SpkiPin::from_hex([pin.as_str()]).unwrap();
        assert!(store.contains_hex(&pin));
        assert!(store.contains_hex(&"A".repeat(64)));
        assert!(!store.contains_hex(&"b".repeat(64)));
        assert!(!store.contains_hex("abc"));
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        assert!(SpkiPin::new().is_empty());
    }

    #[test]
    fn spki_is_found_in_a_generated_certificate() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let der = ck.cert.der().to_vec();
        let spki = spki_of_certificate(&der).expect("parse");
        assert_eq!(spki, ck.key_pair.public_key_der().as_slice());

        let mut by_key = SpkiPin::new();
        assert!(by_key.push_certificate(&der));
        assert!(by_key.matches_certificate(&der));
        assert!(by_key.contains_hex(&compute_spki_pin(spki)));

        let legacy = SpkiPin::from_hex([hex(&sha256(&der))]).unwrap();
        assert!(
            legacy.matches_certificate(&der),
            "full-certificate pin still matches"
        );

        let other = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        assert!(!by_key.matches_certificate(other.cert.der()));
    }

    #[test]
    fn malformed_der_yields_none() {
        for bad in [
            &b""[..],
            b"\x30",
            b"\x30\x05\x30\x03\x02\x01",
            b"\x04\x00",
            b"\x30\x84\xff\xff\xff\xff",
        ] {
            assert!(spki_of_certificate(bad).is_none(), "{bad:?}");
        }
    }
}
