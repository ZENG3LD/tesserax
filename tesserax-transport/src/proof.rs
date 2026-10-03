//! Mutual link proof: what both ends of a link compute to show they hold
//! the same secret, bound to the exchange they are in.
//!
//! A handshake runs: the client sends a fresh `client_nonce`; the server
//! answers with a fresh `server_nonce` and
//! `link_proof(secret, role, LinkRole::Server, ..)`; the client checks it
//! with [`proofs_match`] and only then answers
//! `link_proof(secret, role, LinkRole::Client, ..)`, which the server
//! checks. Neither side sends a byte of application data before its peer's
//! proof matched. Both nonces enter both proofs, so neither side can replay
//! an earlier exchange.
//!
//! The proof is `HMAC-SHA256(secret, message)` (via
//! [`tesserax::ct::hmac_sha256`]) over
//!
//! ```text
//! domain                         caller's protocol domain, raw bytes (fixed per protocol)
//! direction                      1 = LinkRole::Server, 2 = LinkRole::Client
//! role                           caller's role byte (what the client asks to be)
//! client_nonce                   32 bytes
//! server_nonce                   32 bytes
//! u32 little-endian len(binding)
//! binding                        caller's negotiated context, raw bytes
//! ```
//!
//! [`LinkContext::domain`] separates protocols and protocol versions; it
//! must be a constant of the protocol that no other domain is a prefix of
//! (end it with a NUL byte, or build it with [`domain_with_label`]).
//! [`LinkContext::binding`] carries whatever both ends negotiated before the
//! proof (offered and selected capabilities, a build or schema label, …);
//! its length prefix stops bytes from shifting across the boundary.
//!
//! The layout reproduces, byte for byte, the negotiated proof of the
//! local-node wire this module was taken from when `domain` is that
//! protocol's tag followed by its `u16`-length-prefixed build label
//! ([`domain_with_label`]) and `binding` is its serialized compatibility
//! negotiation; `tests/link_proof.rs` pins that with vectors produced by the
//! original code.

use tesserax::ct::{ct_eq_array, hmac_sha256};

use crate::error::TransportError;

/// Nonce length in bytes.
pub const NONCE_BYTES: usize = 32;
/// Proof length in bytes.
pub const PROOF_BYTES: usize = 32;

/// Which end of the link a proof speaks for.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LinkRole {
    /// The accepting end (encoded as `1`).
    Server,
    /// The dialling end (encoded as `2`).
    Client,
}

impl LinkRole {
    fn byte(self) -> u8 {
        match self {
            LinkRole::Server => 1,
            LinkRole::Client => 2,
        }
    }
}

/// What a proof is bound to besides the secret, the roles and the nonces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkContext<'a> {
    /// Protocol domain: a constant of the protocol, no other domain a
    /// prefix of it.
    pub domain: &'a [u8],
    /// Negotiated context both ends agreed on before the proof (may be
    /// empty).
    pub binding: &'a [u8],
}

impl<'a> LinkContext<'a> {
    /// `domain` and `binding` as described on the fields.
    pub fn new(domain: &'a [u8], binding: &'a [u8]) -> Self {
        Self { domain, binding }
    }
}

/// `tag || u16 little-endian len(label) || label`: a domain for a protocol
/// whose proofs are also bound to a label such as a build or schema
/// version. `tag` should end in a NUL byte.
pub fn domain_with_label(tag: &[u8], label: &[u8]) -> Result<Vec<u8>, TransportError> {
    let len = u16::try_from(label.len())
        .map_err(|_| TransportError::LabelTooLong { len: label.len() })?;
    let mut out = Vec::with_capacity(tag.len() + 2 + label.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(label);
    Ok(out)
}

/// The proof `direction` sends in an exchange with these nonces; see the
/// module docs for the exact message.
///
/// `role` is the caller's own role byte (for example "may write" versus
/// "may only observe"): a proof made for one role never matches another.
/// A binding longer than `u32::MAX` bytes has its length prefix saturated;
/// the whole binding is still authenticated.
pub fn link_proof(
    secret: &[u8],
    role: u8,
    direction: LinkRole,
    client_nonce: &[u8; NONCE_BYTES],
    server_nonce: &[u8; NONCE_BYTES],
    cx: &LinkContext<'_>,
) -> [u8; PROOF_BYTES] {
    let binding_len = u32::try_from(cx.binding.len()).unwrap_or(u32::MAX);
    let mut message =
        Vec::with_capacity(cx.domain.len() + 2 + 2 * NONCE_BYTES + 4 + cx.binding.len());
    message.extend_from_slice(cx.domain);
    message.push(direction.byte());
    message.push(role);
    message.extend_from_slice(client_nonce);
    message.extend_from_slice(server_nonce);
    message.extend_from_slice(&binding_len.to_le_bytes());
    message.extend_from_slice(cx.binding);
    hmac_sha256(secret, &message)
}

/// Constant-time equality of two proofs.
pub fn proofs_match(actual: &[u8; PROOF_BYTES], expected: &[u8; PROOF_BYTES]) -> bool {
    ct_eq_array(actual, expected)
}

/// A fresh nonce from the operating system's random source.
pub fn random_nonce() -> Result<[u8; NONCE_BYTES], TransportError> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|e| TransportError::Random(e.to_string()))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CN: [u8; 32] = [3; 32];
    const SN: [u8; 32] = [7; 32];

    /// Pins the message layout field by field (not only the output).
    #[test]
    fn proof_is_an_hmac_over_exactly_this_message() {
        let cx = LinkContext::new(b"example-link-v1\0", b"{\"schema\":1}");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"example-link-v1\0");
        expected.push(1);
        expected.push(9);
        expected.extend_from_slice(&CN);
        expected.extend_from_slice(&SN);
        expected.extend_from_slice(&12u32.to_le_bytes());
        expected.extend_from_slice(b"{\"schema\":1}");
        assert_eq!(
            link_proof(b"secret", 9, LinkRole::Server, &CN, &SN, &cx),
            hmac_sha256(b"secret", &expected)
        );
    }

    #[test]
    fn proofs_are_bound_to_every_input() {
        let cx = LinkContext::new(b"d\0", b"bind");
        let base = link_proof(b"k", 1, LinkRole::Server, &CN, &SN, &cx);
        let variants = [
            link_proof(b"k2", 1, LinkRole::Server, &CN, &SN, &cx),
            link_proof(b"k", 2, LinkRole::Server, &CN, &SN, &cx),
            link_proof(b"k", 1, LinkRole::Client, &CN, &SN, &cx),
            link_proof(b"k", 1, LinkRole::Server, &SN, &CN, &cx),
            link_proof(
                b"k",
                1,
                LinkRole::Server,
                &CN,
                &SN,
                &LinkContext::new(b"e\0", b"bind"),
            ),
            link_proof(
                b"k",
                1,
                LinkRole::Server,
                &CN,
                &SN,
                &LinkContext::new(b"d\0", b"bin"),
            ),
            // Moving a byte from binding into domain changes the proof.
            link_proof(
                b"k",
                1,
                LinkRole::Server,
                &CN,
                &SN,
                &LinkContext::new(b"d\0b", b"ind"),
            ),
        ];
        for v in variants {
            assert!(!proofs_match(&base, &v));
        }
        assert!(proofs_match(&base, &base));
    }

    #[test]
    fn domain_with_label_prefixes_the_label_length() {
        assert_eq!(
            domain_with_label(b"t\0", b"abc").unwrap(),
            b"t\0\x03\x00abc".to_vec()
        );
        assert_eq!(
            domain_with_label(b"t", &vec![0u8; 70_000]),
            Err(TransportError::LabelTooLong { len: 70_000 })
        );
    }

    #[test]
    fn nonces_are_fresh() {
        let a = random_nonce().unwrap();
        let b = random_nonce().unwrap();
        assert_ne!(a, b);
    }
}
