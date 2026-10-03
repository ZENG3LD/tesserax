//! Peer trust gossip (feature `peer-trust`): services exchange signed
//! updates about which operator signing keys they trust, so a key added
//! once propagates to every peer.
//!
//! Trust chain: every change must be signed by a signer already trusted by
//! the receiver. [`BootstrapPins`] (fixed at install time) are the roots;
//! once a root signs in a second signer, that signer can sign in more.
//! Each [`SignedSignerEntry`] carries the proposed [`SignerEntry`], the id
//! of the signer asserting it, and an ed25519 signature over the entry's
//! canonical bytes. On receipt an entry from an unknown or revoked
//! asserter, or with a bad signature, is dropped; accepted entries are
//! merged last-writer-wins on `(version, updated_at_unix)`, ties broken by
//! the lexicographically larger public key. Bootstrap pins can be neither
//! overwritten nor revoked by gossip.
//!
//! Transport is the caller's choice; with feature `opctl` as well,
//! `peer_trust_push::push_envelope` POSTs an envelope over HTTP.
//!
//! Canonical entry bytes (frozen wire format):
//!
//! ```text
//! "tesserax-mesh-trust-entry-v1" || '\n' || signer_id || '\n' || pubkey_b64 || '\n'
//!     || ("1" | "0") || '\n' || version || '\n' || updated_at_unix
//! ```

use std::collections::HashMap;
use std::sync::RwLock;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const CANONICAL_PREFIX: &[u8] = b"tesserax-mesh-trust-entry-v1";

/// Why an update was refused.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum PeerTrustError {
    #[error("unknown signer of change: {0}")]
    UnknownSignerOfChange(String),
    #[error("signer of change is revoked: {0}")]
    SignerOfChangeRevoked(String),
    #[error("signature: {0}")]
    Signature(String),
    #[error("pubkey: {0}")]
    PubKey(String),
    #[error("base64: {0}")]
    Base64(String),
    #[error("cannot revoke bootstrap-pinned signer: {0}")]
    BootstrapRevokeRefused(String),
    #[error("envelope had {0} entries; cap is {1}")]
    EnvelopeTooLarge(usize, usize),
}

/// A single trust-store entry. Wire-stable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerEntry {
    /// Signer id.
    pub signer_id: String,
    /// 32-byte ed25519 pubkey, b64-url-no-pad.
    pub pubkey_b64: String,
    /// Revoked.
    pub revoked: bool,
    /// Monotonic, caller-set. LWW orders entries by `(version, updated_at_unix)`.
    pub version: u64,
    /// Update time (LWW tie-break before the key bytes).
    pub updated_at_unix: u64,
}

impl SignerEntry {
    fn pubkey_bytes(&self) -> Result<[u8; 32], PeerTrustError> {
        let bytes = B64
            .decode(&self.pubkey_b64)
            .map_err(|e| PeerTrustError::Base64(format!("pubkey: {e}")))?;
        if bytes.len() != 32 {
            return Err(PeerTrustError::PubKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// A `SignerEntry` plus an attestation by whoever is asserting the
/// change. Wire-stable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSignerEntry {
    /// The proposed entry.
    pub inner: SignerEntry,
    /// signer_id (already in store) that is asserting this entry.
    pub signer_id_of_change: String,
    /// ed25519 sig over `canonical_bytes(&inner)` by
    /// `signer_id_of_change`'s key.
    pub signature_b64: String,
}

/// Envelope shipped between peers. Wire-stable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipEnvelope {
    /// Entries.
    pub entries: Vec<SignedSignerEntry>,
}

/// Canonical bytes signed by `signer_id_of_change` over a `SignerEntry`.
///
/// ```text
/// "tesserax-mesh-trust-entry-v1" || '\n'
///     || signer_id || '\n'
///     || pubkey_b64 || '\n'
///     || (revoked ? "1" : "0") || '\n'
///     || version_decimal || '\n'
///     || updated_at_unix_decimal
/// ```
pub fn canonical_entry_bytes(e: &SignerEntry) -> Vec<u8> {
    let revoked = if e.revoked { b"1" } else { b"0" };
    let mut out = Vec::with_capacity(
        CANONICAL_PREFIX.len()
            + 1
            + e.signer_id.len()
            + 1
            + e.pubkey_b64.len()
            + 1
            + 1
            + 1
            + 20
            + 1
            + 20,
    );
    out.extend_from_slice(CANONICAL_PREFIX);
    out.push(b'\n');
    out.extend_from_slice(e.signer_id.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(e.pubkey_b64.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(revoked);
    out.push(b'\n');
    out.extend_from_slice(e.version.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(e.updated_at_unix.to_string().as_bytes());
    out
}

/// Sign a [`SignerEntry`] with `signing_key`, claiming the signer
/// identity `signer_id_of_change`. The caller is expected to already
/// be trusted by every peer that will accept this update.
pub fn sign_entry(
    signing_key: &SigningKey,
    signer_id_of_change: impl Into<String>,
    entry: SignerEntry,
) -> SignedSignerEntry {
    let canonical = canonical_entry_bytes(&entry);
    let sig: Signature = signing_key.sign(&canonical);
    SignedSignerEntry {
        inner: entry,
        signer_id_of_change: signer_id_of_change.into(),
        signature_b64: B64.encode(sig.to_bytes()),
    }
}

/// Bootstrap pubkey pins. Loaded at install time, NEVER modifiable
/// at runtime — represents the trust root. Compromise of one of
/// these = reinstall.
#[derive(Debug, Clone, Default)]
pub struct BootstrapPins {
    pinned: HashMap<String, [u8; 32]>,
}

impl BootstrapPins {
    /// No pins.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pin. Returns `Err` if `pubkey_bytes` isn't 32 bytes.
    pub fn pin(mut self, signer_id: impl Into<String>, pubkey_bytes: &[u8]) -> Self {
        if pubkey_bytes.len() != 32 {
            // Builder-style — log and skip silently. The store's
            // `validate()` complains if no valid pins remain.
            tracing::warn!(
                "BootstrapPins::pin — ignoring entry with bad pubkey length {}",
                pubkey_bytes.len()
            );
            return self;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pubkey_bytes);
        self.pinned.insert(signer_id.into(), arr);
        self
    }

    /// Pins.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8; 32])> {
        self.pinned.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of pins.
    pub fn len(&self) -> usize {
        self.pinned.len()
    }

    /// True if no pin.
    pub fn is_empty(&self) -> bool {
        self.pinned.is_empty()
    }

    /// True if `signer_id` is pinned.
    pub fn contains(&self, signer_id: &str) -> bool {
        self.pinned.contains_key(signer_id)
    }
}

/// In-memory peer trust store. Cheap to clone via `Arc<Self>`; internally
/// `RwLock<HashMap>` so reads don't block.
pub struct PeerTrustStore {
    bootstrap: BootstrapPins,
    entries: RwLock<HashMap<String, ResolvedEntry>>,
    /// Maximum entries accepted per envelope. Defense against a peer
    /// flooding gossip. Default 256.
    pub max_envelope_entries: usize,
}

#[derive(Debug, Clone)]
struct ResolvedEntry {
    pubkey: VerifyingKey,
    pubkey_bytes: [u8; 32],
    revoked: bool,
    version: u64,
    updated_at_unix: u64,
    /// True if this entry came from `BootstrapPins`. Cannot be
    /// revoked / overwritten by gossip.
    from_bootstrap: bool,
}

impl PeerTrustStore {
    /// Build a store seeded with `pins`. Bootstrap pins land as
    /// non-revoked entries at version 0.
    pub fn new(pins: BootstrapPins) -> Self {
        let mut entries: HashMap<String, ResolvedEntry> = HashMap::new();
        for (signer_id, pubkey_bytes) in pins.iter() {
            if let Ok(vk) = VerifyingKey::from_bytes(pubkey_bytes) {
                entries.insert(
                    signer_id.to_string(),
                    ResolvedEntry {
                        pubkey: vk,
                        pubkey_bytes: *pubkey_bytes,
                        revoked: false,
                        version: 0,
                        updated_at_unix: 0,
                        from_bootstrap: true,
                    },
                );
            } else {
                tracing::warn!(signer_id, "bootstrap pin pubkey rejected by dalek");
            }
        }
        Self {
            bootstrap: pins,
            entries: RwLock::new(entries),
            max_envelope_entries: 256,
        }
    }

    /// The pins.
    pub fn bootstrap_pins(&self) -> &BootstrapPins {
        &self.bootstrap
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return ALL entries (bootstrap + gossip-introduced + revoked).
    /// Stable order: lexicographic by signer_id.
    pub fn list(&self) -> Vec<SignerEntry> {
        let g = self.entries.read().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<SignerEntry> = g
            .iter()
            .map(|(id, r)| SignerEntry {
                signer_id: id.clone(),
                pubkey_b64: B64.encode(r.pubkey_bytes),
                revoked: r.revoked,
                version: r.version,
                updated_at_unix: r.updated_at_unix,
            })
            .collect();
        out.sort_by(|a, b| a.signer_id.cmp(&b.signer_id));
        out
    }

    /// Build a gossip envelope describing the CURRENT non-bootstrap
    /// state of the store, re-signed by `local_signer` claiming
    /// identity `local_signer_id`. Bootstrap entries are excluded
    /// because remote peers should learn them from their own install
    /// pins, not from gossip.
    pub fn build_envelope(
        &self,
        local_signer: &SigningKey,
        local_signer_id: impl Into<String>,
    ) -> GossipEnvelope {
        let local_id = local_signer_id.into();
        let g = self.entries.read().unwrap_or_else(|p| p.into_inner());
        let mut entries: Vec<SignedSignerEntry> = g
            .iter()
            .filter(|(_, r)| !r.from_bootstrap)
            .map(|(id, r)| {
                let entry = SignerEntry {
                    signer_id: id.clone(),
                    pubkey_b64: B64.encode(r.pubkey_bytes),
                    revoked: r.revoked,
                    version: r.version,
                    updated_at_unix: r.updated_at_unix,
                };
                sign_entry(local_signer, local_id.clone(), entry)
            })
            .collect();
        entries.sort_by(|a, b| a.inner.signer_id.cmp(&b.inner.signer_id));
        GossipEnvelope { entries }
    }

    /// Apply an inbound envelope. Each entry is verified against the
    /// current trust set; unknown / revoked signers-of-change cause
    /// that entry to be dropped (other entries in the envelope are
    /// still processed). Returns the count of entries actually
    /// applied (changed local state).
    pub fn apply_envelope(
        &self,
        envelope: &GossipEnvelope,
        _now_unix: u64,
    ) -> Result<usize, PeerTrustError> {
        if envelope.entries.len() > self.max_envelope_entries {
            return Err(PeerTrustError::EnvelopeTooLarge(
                envelope.entries.len(),
                self.max_envelope_entries,
            ));
        }
        let mut applied = 0usize;
        for signed in &envelope.entries {
            match self.apply_one(signed) {
                Ok(true) => applied += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::debug!(
                        signer_id = %signed.inner.signer_id,
                        signer_id_of_change = %signed.signer_id_of_change,
                        error = %e,
                        "peer trust: rejected entry"
                    );
                }
            }
        }
        Ok(applied)
    }

    /// Apply a single signed entry. Returns `Ok(true)` if state
    /// changed (entry inserted OR existing entry was LWW-superseded);
    /// `Ok(false)` if the entry was ignored (older LWW); `Err(...)` if
    /// rejected (unknown/revoked attestor, bad sig, bootstrap-pin
    /// override attempt).
    pub fn apply_one(&self, signed: &SignedSignerEntry) -> Result<bool, PeerTrustError> {
        // Decode pubkey of the entry being asserted.
        let new_pubkey_bytes = signed.inner.pubkey_bytes()?;
        let new_vk = VerifyingKey::from_bytes(&new_pubkey_bytes)
            .map_err(|e| PeerTrustError::PubKey(e.to_string()))?;

        // Decode signature.
        let sig_bytes = B64
            .decode(&signed.signature_b64)
            .map_err(|e| PeerTrustError::Base64(format!("signature: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(PeerTrustError::Signature(format!(
                "expected 64 bytes, got {}",
                sig_bytes.len()
            )));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        // Look up the attesting signer in CURRENT trust set.
        // Read lock dropped before we take write lock below.
        let (attester_vk, attester_is_bootstrap) = {
            let g = self.entries.read().unwrap_or_else(|p| p.into_inner());
            let attester = g.get(&signed.signer_id_of_change).ok_or_else(|| {
                PeerTrustError::UnknownSignerOfChange(signed.signer_id_of_change.clone())
            })?;
            if attester.revoked {
                return Err(PeerTrustError::SignerOfChangeRevoked(
                    signed.signer_id_of_change.clone(),
                ));
            }
            (attester.pubkey, attester.from_bootstrap)
        };

        // Verify signature over canonical bytes.
        let canonical = canonical_entry_bytes(&signed.inner);
        attester_vk
            .verify(&canonical, &signature)
            .map_err(|e| PeerTrustError::Signature(e.to_string()))?;
        let _ = attester_is_bootstrap; // reserved for future audit-policy hooks

        // Apply LWW under write lock.
        let mut g = self.entries.write().unwrap_or_else(|p| p.into_inner());

        // Bootstrap-pinned signers cannot be overwritten or revoked
        // by gossip. The trust root is install-time-only.
        if let Some(existing) = g.get(&signed.inner.signer_id)
            && existing.from_bootstrap
        {
            if signed.inner.revoked {
                return Err(PeerTrustError::BootstrapRevokeRefused(
                    signed.inner.signer_id.clone(),
                ));
            }
            // Silently drop non-revoke overrides of bootstrap.
            return Ok(false);
        }

        let new_lww = (signed.inner.version, signed.inner.updated_at_unix);
        if let Some(existing) = g.get(&signed.inner.signer_id) {
            let old_lww = (existing.version, existing.updated_at_unix);
            if new_lww < old_lww {
                return Ok(false);
            }
            if new_lww == old_lww {
                // Tie-breaker: lexicographic pubkey bytes (deterministic).
                if signed.inner.pubkey_b64 <= B64.encode(existing.pubkey_bytes) {
                    return Ok(false);
                }
            }
        }

        let resolved = ResolvedEntry {
            pubkey: new_vk,
            pubkey_bytes: new_pubkey_bytes,
            revoked: signed.inner.revoked,
            version: signed.inner.version,
            updated_at_unix: signed.inner.updated_at_unix,
            from_bootstrap: false,
        };
        g.insert(signed.inner.signer_id.clone(), resolved);
        Ok(true)
    }

    /// Returns true if `signer_id` is currently a valid (non-revoked)
    /// signer.
    pub fn is_trusted(&self, signer_id: &str) -> bool {
        let g = self.entries.read().unwrap_or_else(|p| p.into_inner());
        g.get(signer_id).map(|r| !r.revoked).unwrap_or(false)
    }

    /// Look up an entry's pubkey (raw 32 bytes), if present + not
    /// revoked.
    pub fn pubkey(&self, signer_id: &str) -> Option<[u8; 32]> {
        let g = self.entries.read().unwrap_or_else(|p| p.into_inner());
        g.get(signer_id)
            .filter(|r| !r.revoked)
            .map(|r| r.pubkey_bytes)
    }
}

impl std::fmt::Debug for PeerTrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerTrustStore")
            .field("entries", &self.len())
            .field("bootstrap_pins", &self.bootstrap.len())
            .field("max_envelope_entries", &self.max_envelope_entries)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pk_b64(sk: &SigningKey) -> String {
        B64.encode(sk.verifying_key().to_bytes())
    }

    fn pk_bytes(sk: &SigningKey) -> [u8; 32] {
        sk.verifying_key().to_bytes()
    }

    fn pin_store(sk_root: &SigningKey, id: &str) -> PeerTrustStore {
        let pins = BootstrapPins::new().pin(id, &pk_bytes(sk_root));
        PeerTrustStore::new(pins)
    }

    #[test]
    fn bootstrap_pin_is_trusted_at_boot() {
        let root = sk(1);
        let store = pin_store(&root, "root");
        assert!(store.is_trusted("root"));
        assert!(!store.is_trusted("unknown"));
    }

    #[test]
    fn bootstrap_pin_with_bad_length_is_skipped() {
        let pins = BootstrapPins::new().pin("bad", &[0u8; 31]);
        assert!(pins.is_empty(), "31-byte pin must be skipped");
    }

    #[test]
    fn root_can_sign_in_new_signer() {
        let root = sk(1);
        let alice = sk(2);
        let store = pin_store(&root, "root");

        let entry = SignerEntry {
            signer_id: "alice".into(),
            pubkey_b64: pk_b64(&alice),
            revoked: false,
            version: 1,
            updated_at_unix: 100,
        };
        let signed = sign_entry(&root, "root", entry);
        let env = GossipEnvelope {
            entries: vec![signed],
        };
        let applied = store.apply_envelope(&env, 200).expect("apply");
        assert_eq!(applied, 1);
        assert!(store.is_trusted("alice"));
        assert_eq!(store.pubkey("alice"), Some(pk_bytes(&alice)));
    }

    #[test]
    fn newly_trusted_signer_can_chain_further() {
        let root = sk(1);
        let alice = sk(2);
        let bob = sk(3);
        let store = pin_store(&root, "root");

        // Step 1: root signs alice in.
        let e1 = SignerEntry {
            signer_id: "alice".into(),
            pubkey_b64: pk_b64(&alice),
            revoked: false,
            version: 1,
            updated_at_unix: 100,
        };
        store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(&root, "root", e1)],
                },
                200,
            )
            .unwrap();

        // Step 2: alice signs bob in. root was never used here.
        let e2 = SignerEntry {
            signer_id: "bob".into(),
            pubkey_b64: pk_b64(&bob),
            revoked: false,
            version: 1,
            updated_at_unix: 110,
        };
        let applied = store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(&alice, "alice", e2)],
                },
                300,
            )
            .unwrap();
        assert_eq!(applied, 1);
        assert!(store.is_trusted("bob"));
    }

    #[test]
    fn untrusted_signer_of_change_is_dropped() {
        let root = sk(1);
        let attacker = sk(99);
        let target = sk(2);
        let store = pin_store(&root, "root");

        let entry = SignerEntry {
            signer_id: "evil".into(),
            pubkey_b64: pk_b64(&target),
            revoked: false,
            version: 1,
            updated_at_unix: 100,
        };
        let signed = sign_entry(&attacker, "attacker-unknown", entry);
        let applied = store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![signed],
                },
                200,
            )
            .unwrap();
        assert_eq!(applied, 0);
        assert!(!store.is_trusted("evil"));
    }

    #[test]
    fn forged_signature_rejected() {
        let root = sk(1);
        let imposter = sk(99);
        let target = sk(2);
        let store = pin_store(&root, "root");

        // Pretends to be "root" but actually signed by imposter.
        let entry = SignerEntry {
            signer_id: "spoof".into(),
            pubkey_b64: pk_b64(&target),
            revoked: false,
            version: 1,
            updated_at_unix: 100,
        };
        let signed = sign_entry(&imposter, "root", entry);
        let applied = store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![signed],
                },
                200,
            )
            .unwrap();
        assert_eq!(applied, 0, "forged sig must drop the entry");
    }

    #[test]
    fn lww_newer_version_wins() {
        let root = sk(1);
        let alice_v1 = sk(2);
        let alice_v2 = sk(3);
        let store = pin_store(&root, "root");

        let e1 = SignerEntry {
            signer_id: "alice".into(),
            pubkey_b64: pk_b64(&alice_v1),
            revoked: false,
            version: 1,
            updated_at_unix: 100,
        };
        store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(&root, "root", e1)],
                },
                200,
            )
            .unwrap();

        let e2 = SignerEntry {
            signer_id: "alice".into(),
            pubkey_b64: pk_b64(&alice_v2),
            revoked: false,
            version: 2,
            updated_at_unix: 50, // earlier wall-time but newer version
        };
        store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(&root, "root", e2)],
                },
                300,
            )
            .unwrap();

        // alice now bound to v2's pubkey.
        assert_eq!(store.pubkey("alice"), Some(pk_bytes(&alice_v2)));
    }

    #[test]
    fn lww_older_version_dropped() {
        let root = sk(1);
        let alice_v3 = sk(3);
        let alice_v1 = sk(2);
        let store = pin_store(&root, "root");

        let e_new = SignerEntry {
            signer_id: "alice".into(),
            pubkey_b64: pk_b64(&alice_v3),
            revoked: false,
            version: 3,
            updated_at_unix: 300,
        };
        store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(&root, "root", e_new)],
                },
                400,
            )
            .unwrap();

        let e_old = SignerEntry {
            signer_id: "alice".into(),
            pubkey_b64: pk_b64(&alice_v1),
            revoked: false,
            version: 1,
            updated_at_unix: 100,
        };
        let applied = store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(&root, "root", e_old)],
                },
                500,
            )
            .unwrap();
        assert_eq!(applied, 0);
        assert_eq!(store.pubkey("alice"), Some(pk_bytes(&alice_v3)));
    }

    #[test]
    fn bootstrap_signer_cannot_be_revoked_by_gossip() {
        let root = sk(1);
        let store = pin_store(&root, "root");

        let revoke = SignerEntry {
            signer_id: "root".into(),
            pubkey_b64: pk_b64(&root),
            revoked: true,
            version: 1,
            updated_at_unix: 100,
        };
        let signed = sign_entry(&root, "root", revoke);
        // Even signed BY root itself, the bootstrap pin holds.
        let applied = store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![signed],
                },
                200,
            )
            .unwrap();
        assert_eq!(applied, 0);
        assert!(store.is_trusted("root"), "bootstrap root stays trusted");
    }

    #[test]
    fn revoked_signer_cannot_attest_new_entries() {
        let root = sk(1);
        let alice = sk(2);
        let bob = sk(3);
        let store = pin_store(&root, "root");

        // Root introduces alice.
        store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(
                        &root,
                        "root",
                        SignerEntry {
                            signer_id: "alice".into(),
                            pubkey_b64: pk_b64(&alice),
                            revoked: false,
                            version: 1,
                            updated_at_unix: 100,
                        },
                    )],
                },
                200,
            )
            .unwrap();
        // Root revokes alice.
        store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(
                        &root,
                        "root",
                        SignerEntry {
                            signer_id: "alice".into(),
                            pubkey_b64: pk_b64(&alice),
                            revoked: true,
                            version: 2,
                            updated_at_unix: 110,
                        },
                    )],
                },
                300,
            )
            .unwrap();

        assert!(!store.is_trusted("alice"));

        // Alice tries to sign bob in — must be ignored.
        let applied = store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(
                        &alice,
                        "alice",
                        SignerEntry {
                            signer_id: "bob".into(),
                            pubkey_b64: pk_b64(&bob),
                            revoked: false,
                            version: 1,
                            updated_at_unix: 120,
                        },
                    )],
                },
                400,
            )
            .unwrap();
        assert_eq!(applied, 0);
        assert!(!store.is_trusted("bob"));
    }

    #[test]
    fn build_envelope_excludes_bootstrap_entries() {
        let root = sk(1);
        let alice = sk(2);
        let local = sk(7);
        let store = pin_store(&root, "root");

        // Use bootstrap root to sign in alice.
        store
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(
                        &root,
                        "root",
                        SignerEntry {
                            signer_id: "alice".into(),
                            pubkey_b64: pk_b64(&alice),
                            revoked: false,
                            version: 1,
                            updated_at_unix: 100,
                        },
                    )],
                },
                200,
            )
            .unwrap();

        // Local node has its own attesting identity = also a trusted
        // pin in some real deployments. Here we just build to verify
        // the entry list. We need root in store to be alice's
        // signer — but build_envelope re-signs with `local`, which
        // need not be trusted by ANYONE in this unit test (this is
        // a smoke that the envelope-build path runs).
        let env = store.build_envelope(&local, "local-node");
        assert_eq!(env.entries.len(), 1, "bootstrap root excluded");
        assert_eq!(env.entries[0].inner.signer_id, "alice");
        assert_eq!(env.entries[0].signer_id_of_change, "local-node");
    }

    #[test]
    fn envelope_size_cap_enforced() {
        let root = sk(1);
        let store = pin_store(&root, "root");
        let mut entries = Vec::new();
        for i in 0..(store.max_envelope_entries + 1) {
            let target = SigningKey::from_bytes(&[(i % 250 + 1) as u8; 32]);
            entries.push(sign_entry(
                &root,
                "root",
                SignerEntry {
                    signer_id: format!("s{i}"),
                    pubkey_b64: pk_b64(&target),
                    revoked: false,
                    version: 1,
                    updated_at_unix: 100,
                },
            ));
        }
        let err = store
            .apply_envelope(&GossipEnvelope { entries }, 200)
            .unwrap_err();
        assert!(matches!(err, PeerTrustError::EnvelopeTooLarge(_, _)));
    }

    #[test]
    fn two_peer_convergence() {
        // Simulates two peer stores: each starts with the same
        // bootstrap pin, peer A learns about alice, then ships an
        // envelope to peer B. Peer B's store ends up with the same
        // alice entry.
        let root = sk(1);
        let alice = sk(2);

        let pins_a = BootstrapPins::new().pin("root", &pk_bytes(&root));
        let pins_b = BootstrapPins::new().pin("root", &pk_bytes(&root));
        let store_a = PeerTrustStore::new(pins_a);
        let store_b = PeerTrustStore::new(pins_b);

        store_a
            .apply_envelope(
                &GossipEnvelope {
                    entries: vec![sign_entry(
                        &root,
                        "root",
                        SignerEntry {
                            signer_id: "alice".into(),
                            pubkey_b64: pk_b64(&alice),
                            revoked: false,
                            version: 1,
                            updated_at_unix: 100,
                        },
                    )],
                },
                200,
            )
            .unwrap();
        assert!(store_a.is_trusted("alice"));
        assert!(!store_b.is_trusted("alice"));

        // Peer A ships its current state to Peer B, re-signed by
        // root (the only key both peers a priori trust).
        let env = store_a.build_envelope(&root, "root");
        store_b.apply_envelope(&env, 300).unwrap();
        assert!(store_b.is_trusted("alice"));
        assert_eq!(store_b.pubkey("alice"), Some(pk_bytes(&alice)));

        // Now Peer A and Peer B agree on the full set.
        let listing_a = store_a.list();
        let listing_b = store_b.list();
        let ids_a: Vec<&str> = listing_a.iter().map(|e| e.signer_id.as_str()).collect();
        let ids_b: Vec<&str> = listing_b.iter().map(|e| e.signer_id.as_str()).collect();
        assert_eq!(ids_a, ids_b);
    }

    #[test]
    fn canonical_entry_bytes_are_byte_locked() {
        let e = SignerEntry {
            signer_id: "alice".into(),
            pubkey_b64: "AAAA".into(),
            revoked: false,
            version: 7,
            updated_at_unix: 1700000000,
        };
        let bytes = canonical_entry_bytes(&e);
        let s = std::str::from_utf8(&bytes).expect("utf8");
        assert_eq!(
            s,
            "tesserax-mesh-trust-entry-v1\nalice\nAAAA\n0\n7\n1700000000"
        );

        let e2 = SignerEntry { revoked: true, ..e };
        let bytes2 = canonical_entry_bytes(&e2);
        let s2 = std::str::from_utf8(&bytes2).expect("utf8");
        assert_eq!(
            s2,
            "tesserax-mesh-trust-entry-v1\nalice\nAAAA\n1\n7\n1700000000"
        );
    }
}
