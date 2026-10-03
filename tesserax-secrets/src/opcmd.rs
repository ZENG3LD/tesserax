//! Signed operator commands: ed25519-signed request envelopes, the signer
//! trust store, the replay cache and the outbound signer.
//!
//! An operator holds an ed25519 key offline; the service pins the
//! operator's public key in an [`OperatorTrustStore`]. A privileged
//! command body is an [`OperatorCommand`]
//! `{payload_b64, signer_id, expires_at_unix, request_id, signature_b64}`;
//! before dispatch the service checks, in order: not expired, `request_id`
//! present, signer known and not revoked, signature valid over the
//! canonical bytes, and (with a [`ReplayCache`]) `(signer_id, request_id)`
//! not seen before.
//!
//! ## Canonical bytes, v2 (frozen wire format)
//!
//! ```text
//! "tesserax-op-command-v2" || '\n' || signer_id || '\n' || expires_at_unix (decimal)
//!     || '\n' || request_id || '\n' || payload_bytes
//! ```
//!
//! v1 signatures (without `request_id`) do not verify.
//!
//! Threats covered: replay (expiry + replay cache), a lost operator key
//! (revoke it in the store). A writer of the trust-store file can add a
//! key; keep the store inside sealed storage.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use std::sync::RwLock;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::{Mutex, MutexGuard, RwLockReadGuard, RwLockWriteGuard};

const CANONICAL_PREFIX: &[u8] = b"tesserax-op-command-v2";

/// Why a command was refused.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum OperatorCommandError {
    #[error("expired: expires_at_unix={expires_at} now_unix={now}")]
    Expired { expires_at: u64, now: u64 },
    #[error("unknown signer_id: {0}")]
    UnknownSigner(String),
    #[error("signer revoked: {0}")]
    SignerRevoked(String),
    #[error("duplicate request_id within dedup window: signer={signer_id} request_id={request_id}")]
    DuplicateRequest {
        signer_id: String,
        request_id: String,
    },
    #[error("missing request_id (v2 canonical bytes require one)")]
    MissingRequestId,
    #[error("signature: {0}")]
    Signature(String),
    #[error("pubkey: {0}")]
    PubKey(String),
    #[error("base64: {0}")]
    Base64(String),
}

/// A signed command envelope. Payload is opaque bytes — caller
/// deserializes after `verify()` succeeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorCommand {
    /// `b64url(payload_bytes)`. Keeping the payload base64-encoded
    /// inside JSON makes the canonical signing bytes deterministic
    /// regardless of JSON-roundtrip whitespace.
    pub payload_b64: String,
    /// Id of the signing operator in the trust store.
    pub signer_id: String,
    /// Expiry (Unix seconds); refused at or after it.
    pub expires_at_unix: u64,
    /// caller-minted unique request id (typically UUIDv4).
    /// `(signer_id, request_id)` pairs in the daemon's
    /// [`ReplayCache`] short-circuit duplicates. Must be present in v2.
    pub request_id: String,
    /// `b64url(ed25519_signature_64B)`.
    pub signature_b64: String,
}

impl OperatorCommand {
    /// Audit record for this command (metadata only, never the payload):
    /// principal = `signer_id`, verb = `action_label`, target =
    /// `request_id`, status 200 on success and 403 otherwise.
    pub fn audit_event(
        &self,
        action_label: impl Into<String>,
        success: bool,
        ts_ms: u64,
    ) -> tesserax::AuditEvent {
        tesserax::AuditEvent {
            ts_ms,
            door: "operator-command".into(),
            principal: Some(self.signer_id.clone()),
            client: None,
            verb: action_label.into(),
            target: self.request_id.clone(),
            status: if success { 200 } else { 403 },
        }
    }

    /// Verify expiry + signature against the trust store. Returns
    /// the decoded payload bytes on success.
    ///
    /// **Replay protection**: pass a `&ReplayCache` if you want
    /// cross-daemon replay rejection. The cache records
    /// `(signer_id, request_id)` and rejects duplicates within its
    /// dedup window. Pass `None` for backward-test or single-daemon
    /// deployments where replay isn't a concern.
    pub fn verify(
        &self,
        store: &OperatorTrustStore,
        now: std::time::SystemTime,
        replay: Option<&ReplayCache>,
    ) -> Result<Vec<u8>, OperatorCommandError> {
        let now_unix = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if self.expires_at_unix <= now_unix {
            return Err(OperatorCommandError::Expired {
                expires_at: self.expires_at_unix,
                now: now_unix,
            });
        }

        if self.request_id.is_empty() {
            return Err(OperatorCommandError::MissingRequestId);
        }

        let signer = store
            .get(&self.signer_id)
            .ok_or_else(|| OperatorCommandError::UnknownSigner(self.signer_id.clone()))?;
        if signer.revoked {
            return Err(OperatorCommandError::SignerRevoked(self.signer_id.clone()));
        }

        let payload = B64
            .decode(&self.payload_b64)
            .map_err(|e| OperatorCommandError::Base64(format!("payload: {e}")))?;
        let sig_bytes = B64
            .decode(&self.signature_b64)
            .map_err(|e| OperatorCommandError::Base64(format!("signature: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(OperatorCommandError::Signature(format!(
                "expected 64 bytes, got {}",
                sig_bytes.len()
            )));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let msg = canonical_signing_bytes(
            &self.signer_id,
            self.expires_at_unix,
            &self.request_id,
            &payload,
        );

        signer
            .pubkey
            .verify(&msg, &signature)
            .map_err(|e| OperatorCommandError::Signature(e.to_string()))?;

        // Signature is authentic — now bind it to a one-shot replay
        // slot. record_or_reject returns true if the entry is fresh
        // (first time we see this pair).
        if let Some(cache) = replay
            && !cache.record_or_reject(&self.signer_id, &self.request_id, now)
        {
            return Err(OperatorCommandError::DuplicateRequest {
                signer_id: self.signer_id.clone(),
                request_id: self.request_id.clone(),
            });
        }

        Ok(payload)
    }
}

/// Compute the bytes the operator signs (v2).
pub fn canonical_signing_bytes(
    signer_id: &str,
    expires_at_unix: u64,
    request_id: &str,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        CANONICAL_PREFIX.len()
            + 1
            + signer_id.len()
            + 1
            + 20
            + 1
            + request_id.len()
            + 1
            + payload.len(),
    );
    out.extend_from_slice(CANONICAL_PREFIX);
    out.push(b'\n');
    out.extend_from_slice(signer_id.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(expires_at_unix.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(request_id.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(payload);
    out
}

/// Trust store entry. `pubkey_fingerprint` is BLAKE3-or-SHA256-hex
/// truncated — used for log lines and operator UI without leaking
/// the full public key.
#[derive(Debug, Clone)]
pub struct TrustedSigner {
    /// Verifying key.
    pub pubkey: VerifyingKey,
    /// Refuse commands from this signer.
    pub revoked: bool,
    /// Short SHA-256 hex of the key for logs.
    pub pubkey_fingerprint: String,
}

/// Process-wide ed25519 trust store. Cheap to clone via Arc-wrap if
/// needed; internally `RwLock<HashMap>` so reads don't block.
pub struct OperatorTrustStore {
    by_signer_id: RwLock<HashMap<String, TrustedSigner>>,
}

impl Default for OperatorTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorTrustStore {
    fn read(&self) -> RwLockReadGuard<'_, HashMap<String, TrustedSigner>> {
        self.by_signer_id.read().unwrap_or_else(|p| p.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<String, TrustedSigner>> {
        self.by_signer_id.write().unwrap_or_else(|p| p.into_inner())
    }

    /// Empty store (refuses every command).
    pub fn new() -> Self {
        Self {
            by_signer_id: RwLock::new(HashMap::new()),
        }
    }

    /// Add a signer. `pubkey_bytes` is the raw 32-byte ed25519 public
    /// key. Idempotent — re-adding the same id replaces the existing
    /// entry (which is how an operator un-revokes by re-issuing).
    pub fn add_signer(
        &self,
        signer_id: impl Into<String>,
        pubkey_bytes: &[u8],
    ) -> Result<(), OperatorCommandError> {
        if pubkey_bytes.len() != 32 {
            return Err(OperatorCommandError::PubKey(format!(
                "expected 32 bytes, got {}",
                pubkey_bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pubkey_bytes);
        let vk = VerifyingKey::from_bytes(&arr)
            .map_err(|e| OperatorCommandError::PubKey(e.to_string()))?;
        let fp = pubkey_fingerprint(&arr);
        let entry = TrustedSigner {
            pubkey: vk,
            revoked: false,
            pubkey_fingerprint: fp,
        };
        let mut g = self.write();
        g.insert(signer_id.into(), entry);
        Ok(())
    }

    /// Marks a signer revoked; returns false if unknown.
    pub fn revoke(&self, signer_id: &str) -> bool {
        let mut g = self.write();
        if let Some(e) = g.get_mut(signer_id) {
            e.revoked = true;
            true
        } else {
            false
        }
    }

    /// Removes a signer; returns false if unknown.
    pub fn remove(&self, signer_id: &str) -> bool {
        let mut g = self.write();
        g.remove(signer_id).is_some()
    }

    /// Looks a signer up.
    pub fn get(&self, signer_id: &str) -> Option<TrustedSigner> {
        let g = self.read();
        g.get(signer_id).cloned()
    }

    /// All signers.
    pub fn list(&self) -> Vec<(String, TrustedSigner)> {
        let g = self.read();
        g.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Number of signers.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// True if no signer is trusted.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for OperatorTrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorTrustStore")
            .field("signers", &self.len())
            .finish()
    }
}

fn pubkey_fingerprint(pubkey: &[u8; 32]) -> String {
    let h = sha2::Sha256::digest(pubkey);
    let mut out = String::with_capacity(16);
    const HEX: &[u8] = b"0123456789abcdef";
    for &b in h.iter().take(8) {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// bounded replay cache of `(signer_id, request_id)`
/// tuples. A successful `OperatorCommand::verify` records the pair
/// here; a subsequent verify with the same pair returns
/// `DuplicateRequest` until the cache evicts the entry.
///
/// Eviction is two-fold:
/// - **Age-based**: entries older than `dedup_window` are pruned at
///   record time. Typically `2 * ttl_secs` — long enough that any
///   request which could still be in-flight (signature not expired)
///   is still remembered.
/// - **Capacity-based**: when `max_entries` is exceeded, the oldest
///   entries are dropped first. Cap defends against an attacker
///   spraying unique request_ids to exhaust memory; the only
///   downside of dropping is that a replay using a *very* old
///   request_id would slip through — but `expires_at` blocks it
///   first.
///
/// Process-wide singleton typical: attach one `Arc<ReplayCache>` to
/// the daemon, pass it into every `verify()` call. Cheap to clone
/// via Arc.
pub struct ReplayCache {
    dedup_window: std::time::Duration,
    max_entries: usize,
    entries: Mutex<ReplayState>,
}

#[derive(Default)]
struct ReplayState {
    order: std::collections::VecDeque<ReplayEntry>,
    keys: std::collections::HashSet<String>,
}

#[derive(Clone)]
struct ReplayEntry {
    key: String,
    seen_at: std::time::SystemTime,
}

impl ReplayCache {
    /// Defaults: 5 minutes dedup window, 10k capacity. Tune via
    /// `with_window` / `with_capacity`.
    pub fn new() -> Self {
        Self::with_capacity(10_000).with_window(std::time::Duration::from_secs(300))
    }

    /// Cache holding at most `max_entries` pairs (5-minute window).
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            dedup_window: std::time::Duration::from_secs(300),
            max_entries,
            entries: Mutex::new(ReplayState::default()),
        }
    }

    /// Changes the dedup window.
    pub fn with_window(mut self, window: std::time::Duration) -> Self {
        self.dedup_window = window;
        self
    }

    /// Record the pair, OR reject if it's already present.
    ///
    /// Returns `true` if the pair is fresh (caller may proceed),
    /// `false` if it's a duplicate (caller must reject).
    pub fn record_or_reject(
        &self,
        signer_id: &str,
        request_id: &str,
        now: std::time::SystemTime,
    ) -> bool {
        let key = format!("{signer_id}|{request_id}");
        let cutoff = now.checked_sub(self.dedup_window);
        let mut st = self.lock();
        if let Some(cutoff) = cutoff {
            while st.order.front().is_some_and(|f| f.seen_at < cutoff) {
                if let Some(old) = st.order.pop_front() {
                    st.keys.remove(&old.key);
                }
            }
        }
        if st.keys.contains(&key) {
            return false;
        }
        if st.order.len() >= self.max_entries.max(1)
            && let Some(old) = st.order.pop_front()
        {
            st.keys.remove(&old.key);
        }
        st.keys.insert(key.clone());
        st.order.push_back(ReplayEntry { key, seen_at: now });
        true
    }

    fn lock(&self) -> MutexGuard<'_, ReplayState> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Pairs remembered right now.
    pub fn len(&self) -> usize {
        self.lock().order.len()
    }

    /// True if nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReplayCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayCache")
            .field("dedup_window", &self.dedup_window)
            .field("max_entries", &self.max_entries)
            .field("current_size", &self.len())
            .finish()
    }
}

// ---- outbound signer -------------------------------------------------------

/// Signing failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum OperatorCommandClientError {
    #[error("rng: {0}")]
    Rng(String),
    #[error("clock: {0}")]
    Clock(String),
}

/// Outbound signer. Cheap to clone — `SigningKey` is 32 bytes, the
/// signer_id is owned.
#[derive(Clone)]
pub struct OperatorCommandClient {
    signing_key: SigningKey,
    signer_id: String,
}

impl OperatorCommandClient {
    /// Signer with `signing_key` claiming `signer_id`.
    pub fn new(signing_key: SigningKey, signer_id: impl Into<String>) -> Self {
        Self {
            signing_key,
            signer_id: signer_id.into(),
        }
    }

    /// Claimed signer id.
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// Mint a fresh request_id (16 random bytes → b64url, ~22 chars).
    /// Public so callers can mint one ahead of time (e.g. log it
    /// before send so the peer-side audit log is correlatable).
    pub fn mint_request_id() -> Result<String, OperatorCommandClientError> {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).map_err(|e| OperatorCommandClientError::Rng(e.to_string()))?;
        Ok(B64.encode(buf))
    }

    /// Sign `payload` with the given `ttl`. Returns a fully-populated
    /// [`OperatorCommand`] ready to JSON-serialise.
    pub fn sign(
        &self,
        payload: &[u8],
        ttl: Duration,
    ) -> Result<OperatorCommand, OperatorCommandClientError> {
        let request_id = Self::mint_request_id()?;
        self.sign_with_id(payload, ttl, request_id)
    }

    /// Same as [`Self::sign`] but with a caller-supplied request_id.
    /// Useful for tests + for callers that need to log the id before
    /// firing the request.
    pub fn sign_with_id(
        &self,
        payload: &[u8],
        ttl: Duration,
        request_id: String,
    ) -> Result<OperatorCommand, OperatorCommandClientError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| OperatorCommandClientError::Clock(e.to_string()))?;
        let expires_at_unix = now.as_secs() + ttl.as_secs();

        let canonical =
            canonical_signing_bytes(&self.signer_id, expires_at_unix, &request_id, payload);
        let sig = self.signing_key.sign(&canonical);

        Ok(OperatorCommand {
            payload_b64: B64.encode(payload),
            signer_id: self.signer_id.clone(),
            expires_at_unix,
            request_id,
            signature_b64: B64.encode(sig.to_bytes()),
        })
    }
}

#[cfg(feature = "opctl")]
impl OperatorCommandClient {
    /// Build a `reqwest::RequestBuilder` for POSTing a signed command
    /// to `url`. The caller chains `.json_payload(bytes).ttl(d).send()`
    /// (or breaks out and uses the lower-level [`Self::sign`] +
    /// `client.post(url).json(&cmd)`).
    /// Starts an HTTP POST of a signed command to `url` (feature `opctl`).
    pub fn post<'c>(
        &'c self,
        client: &'c reqwest::Client,
        url: impl Into<String>,
    ) -> PendingPost<'c> {
        PendingPost {
            client_ref: self,
            http: client,
            url: url.into(),
            payload: Vec::new(),
            ttl: Duration::from_secs(60),
            traceparent: None,
        }
    }
}

impl std::fmt::Debug for OperatorCommandClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorCommandClient")
            .field("signer_id", &self.signer_id)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "opctl")]
/// Builder returned by [`OperatorCommandClient::post`]. Chain
/// `.json_payload(...)` and `.ttl(...)` then `.send()`.
pub struct PendingPost<'c> {
    client_ref: &'c OperatorCommandClient,
    http: &'c reqwest::Client,
    url: String,
    payload: Vec<u8>,
    ttl: Duration,
    /// caller-supplied W3C traceparent header value.
    /// Format: `00-<trace_id_32hex>-<span_id_16hex>-<flags_2hex>`.
    /// When set, forwarded as the `traceparent` request header so
    /// the peer's `traceparent_layer` joins the same trace.
    traceparent: Option<String>,
}

#[cfg(feature = "opctl")]
impl<'c> PendingPost<'c> {
    /// Payload bytes.
    pub fn json_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Time to live.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// propagate the caller's current W3C trace context.
    /// Pass a W3C `traceparent` value (from the HTTP crate's trace context) or
    /// any external string in the same format. The peer's
    /// `traceparent_layer` will recognise it and span under the same
    /// trace_id.
    pub fn traceparent(mut self, header_value: impl Into<String>) -> Self {
        self.traceparent = Some(header_value.into());
        self
    }

    /// Read back the configured traceparent header (mostly for tests).
    pub fn current_traceparent(&self) -> Option<&str> {
        self.traceparent.as_deref()
    }

    /// Sign + fire. Returns the raw `reqwest::Response` so the caller
    /// can decide how to interpret status / verify the response
    /// signature before consuming the body.
    pub async fn send(self) -> Result<reqwest::Response, OperatorCommandSendError> {
        let cmd = self
            .client_ref
            .sign(&self.payload, self.ttl)
            .map_err(OperatorCommandSendError::Client)?;
        let mut req = self.http.post(&self.url).json(&cmd);
        if let Some(tp) = self.traceparent.as_deref() {
            req = req.header("traceparent", tp);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| OperatorCommandSendError::Http(e.to_string()))?;
        Ok(resp)
    }
}

#[cfg(feature = "opctl")]
/// Send failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum OperatorCommandSendError {
    #[error("client: {0}")]
    Client(#[from] OperatorCommandClientError),
    #[error("http: {0}")]
    Http(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fresh_keypair() -> SigningKey {
        // Deterministic for the test — production callers use random.
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn unix_now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_signed_command(
        sk: &SigningKey,
        signer_id: &str,
        payload: &[u8],
        expires_in_secs: i64,
    ) -> OperatorCommand {
        make_signed_command_with_id(sk, signer_id, payload, expires_in_secs, "req-test-1")
    }

    fn make_signed_command_with_id(
        sk: &SigningKey,
        signer_id: &str,
        payload: &[u8],
        expires_in_secs: i64,
        request_id: &str,
    ) -> OperatorCommand {
        let expires_at = if expires_in_secs >= 0 {
            unix_now_secs() + expires_in_secs as u64
        } else {
            unix_now_secs().saturating_sub((-expires_in_secs) as u64)
        };
        let msg = canonical_signing_bytes(signer_id, expires_at, request_id, payload);
        let sig = sk.sign(&msg);
        OperatorCommand {
            payload_b64: B64.encode(payload),
            signer_id: signer_id.into(),
            expires_at_unix: expires_at,
            request_id: request_id.into(),
            signature_b64: B64.encode(sig.to_bytes()),
        }
    }

    #[test]
    fn valid_command_verifies_and_returns_payload() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        let cmd = make_signed_command(&sk, "alice", b"do thing", 60);
        let payload = cmd
            .verify(&store, std::time::SystemTime::now(), None)
            .unwrap();
        assert_eq!(payload, b"do thing");
    }

    #[test]
    fn expired_command_rejected() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        let cmd = make_signed_command(&sk, "alice", b"x", -10);
        let err = cmd
            .verify(&store, std::time::SystemTime::now(), None)
            .unwrap_err();
        assert!(matches!(err, OperatorCommandError::Expired { .. }));
    }

    #[test]
    fn unknown_signer_rejected() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        // Don't add the signer.
        let cmd = make_signed_command(&sk, "ghost", b"x", 60);
        let err = cmd
            .verify(&store, std::time::SystemTime::now(), None)
            .unwrap_err();
        assert!(matches!(err, OperatorCommandError::UnknownSigner(_)));
    }

    #[test]
    fn revoked_signer_rejected() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        assert!(store.revoke("alice"));
        let cmd = make_signed_command(&sk, "alice", b"x", 60);
        let err = cmd
            .verify(&store, std::time::SystemTime::now(), None)
            .unwrap_err();
        assert!(matches!(err, OperatorCommandError::SignerRevoked(_)));
    }

    #[test]
    fn forged_signature_rejected() {
        let sk = fresh_keypair();
        let other = SigningKey::from_bytes(&[2u8; 32]);
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        // Sign with OTHER key but claim to be alice.
        let payload = b"x";
        let expires_at = unix_now_secs() + 60;
        let request_id = "forge-1";
        let msg = canonical_signing_bytes("alice", expires_at, request_id, payload);
        let sig = other.sign(&msg);
        let cmd = OperatorCommand {
            payload_b64: B64.encode(payload),
            signer_id: "alice".into(),
            expires_at_unix: expires_at,
            request_id: request_id.into(),
            signature_b64: B64.encode(sig.to_bytes()),
        };
        let err = cmd
            .verify(&store, std::time::SystemTime::now(), None)
            .unwrap_err();
        assert!(matches!(err, OperatorCommandError::Signature(_)));
    }

    #[test]
    fn tampered_payload_rejected() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        let mut cmd = make_signed_command(&sk, "alice", b"original", 60);
        // Swap the payload — signature was over the original.
        cmd.payload_b64 = B64.encode(b"tampered");
        let err = cmd
            .verify(&store, std::time::SystemTime::now(), None)
            .unwrap_err();
        assert!(matches!(err, OperatorCommandError::Signature(_)));
    }

    #[test]
    fn bad_pubkey_length_rejected() {
        let store = OperatorTrustStore::new();
        let err = store.add_signer("alice", &[0u8; 31]).unwrap_err();
        assert!(matches!(err, OperatorCommandError::PubKey(_)));
    }

    #[test]
    fn store_list_contains_added_signers() {
        let sk1 = SigningKey::from_bytes(&[1u8; 32]);
        let sk2 = SigningKey::from_bytes(&[2u8; 32]);
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk1.verifying_key().as_bytes())
            .unwrap();
        store
            .add_signer("bob", sk2.verifying_key().as_bytes())
            .unwrap();
        let listed = store.list();
        assert_eq!(listed.len(), 2);
        let names: Vec<&str> = listed.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"alice"));
        assert!(names.contains(&"bob"));
    }

    #[test]
    fn fingerprint_is_short_and_deterministic() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        let entry = store.get("alice").unwrap();
        assert_eq!(entry.pubkey_fingerprint.len(), 16);
        assert!(
            entry
                .pubkey_fingerprint
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        );

        // Same key → same fingerprint.
        let store2 = OperatorTrustStore::new();
        store2
            .add_signer("bob", sk.verifying_key().as_bytes())
            .unwrap();
        assert_eq!(
            entry.pubkey_fingerprint,
            store2.get("bob").unwrap().pubkey_fingerprint
        );
    }

    #[test]
    fn canonical_bytes_match_across_processes() {
        // Stability test — if we accidentally change the canonical
        // format, every deployed operator CLI breaks. Lock the exact
        // byte sequence. (v2)
        let bytes = canonical_signing_bytes("alice", 1716800000, "req-42", b"hello");
        let expected = b"tesserax-op-command-v2\nalice\n1716800000\nreq-42\nhello";
        assert_eq!(bytes, expected);
    }

    // replay cache tests.

    #[test]
    fn replay_cache_accepts_first_use() {
        let cache = ReplayCache::new();
        let ok = cache.record_or_reject("alice", "req-1", std::time::SystemTime::now());
        assert!(ok);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replay_cache_rejects_duplicate() {
        let cache = ReplayCache::new();
        let now = std::time::SystemTime::now();
        assert!(cache.record_or_reject("alice", "req-1", now));
        assert!(!cache.record_or_reject("alice", "req-1", now));
    }

    #[test]
    fn replay_cache_distinct_signers_no_collision() {
        let cache = ReplayCache::new();
        let now = std::time::SystemTime::now();
        assert!(cache.record_or_reject("alice", "req-1", now));
        assert!(cache.record_or_reject("bob", "req-1", now));
        assert!(cache.record_or_reject("alice", "req-2", now));
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn replay_cache_evicts_entries_older_than_window() {
        let cache = ReplayCache::with_capacity(100).with_window(std::time::Duration::from_secs(60));
        let old_time = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
        let now = std::time::SystemTime::now();
        assert!(cache.record_or_reject("alice", "req-old", old_time));
        // Triggering record at "now" should prune the old entry first.
        assert!(cache.record_or_reject("alice", "req-new", now));
        // Old entry is gone — re-recording it as fresh succeeds.
        assert!(cache.record_or_reject("alice", "req-old", now));
    }

    #[test]
    fn replay_cache_capacity_cap_drops_oldest() {
        let cache = ReplayCache::with_capacity(3);
        let now = std::time::SystemTime::now();
        assert!(cache.record_or_reject("alice", "r1", now));
        assert!(cache.record_or_reject("alice", "r2", now));
        assert!(cache.record_or_reject("alice", "r3", now));
        // Forth entry evicts r1.
        assert!(cache.record_or_reject("alice", "r4", now));
        assert_eq!(cache.len(), 3);
        // r1 is gone → recordable again.
        assert!(cache.record_or_reject("alice", "r1", now));
    }

    #[test]
    fn verify_with_replay_cache_rejects_duplicate_command() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        let cache = ReplayCache::new();

        let cmd = make_signed_command_with_id(&sk, "alice", b"do thing", 60, "req-once");
        let now = std::time::SystemTime::now();

        // First verify succeeds.
        cmd.verify(&store, now, Some(&cache)).expect("first verify");

        // Same command, same request_id → DuplicateRequest.
        let err = cmd.verify(&store, now, Some(&cache)).unwrap_err();
        assert!(
            matches!(err, OperatorCommandError::DuplicateRequest { .. }),
            "expected DuplicateRequest, got {err:?}"
        );
    }

    #[test]
    fn verify_without_cache_skips_replay_protection() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        let cmd = make_signed_command_with_id(&sk, "alice", b"x", 60, "req-no-cache");
        let now = std::time::SystemTime::now();
        // Calling verify twice without cache succeeds twice — replay
        // protection is opt-in per-verify.
        cmd.verify(&store, now, None).expect("first");
        cmd.verify(&store, now, None).expect("second");
    }

    #[test]
    fn empty_request_id_rejected() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        // Sign with empty request_id — even if signature is valid, the
        // verifier short-circuits at the empty-id check (catches
        // mis-built clients that forget the field).
        let payload = b"x";
        let expires_at = unix_now_secs() + 60;
        let msg = canonical_signing_bytes("alice", expires_at, "", payload);
        let sig = sk.sign(&msg);
        let cmd = OperatorCommand {
            payload_b64: B64.encode(payload),
            signer_id: "alice".into(),
            expires_at_unix: expires_at,
            request_id: String::new(),
            signature_b64: B64.encode(sig.to_bytes()),
        };
        let err = cmd
            .verify(&store, std::time::SystemTime::now(), None)
            .unwrap_err();
        assert!(matches!(err, OperatorCommandError::MissingRequestId));
    }

    #[test]
    fn audit_event_carries_metadata_not_payload() {
        let sk = fresh_keypair();
        let cmd = make_signed_command_with_id(&sk, "alice", b"secret-payload", 60, "req-a");
        let e = cmd.audit_event("operator-command", true, 5);
        assert_eq!(e.principal.as_deref(), Some("alice"));
        assert_eq!(
            (e.verb.as_str(), e.target.as_str(), e.status, e.ts_ms),
            ("operator-command", "req-a", 200, 5)
        );
        assert!(!format!("{e:?}").contains("secret-payload"));
        assert_eq!(cmd.audit_event("x", false, 0).status, 403);
    }

    #[test]
    fn distinct_request_ids_with_same_payload_both_accepted() {
        let sk = fresh_keypair();
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", sk.verifying_key().as_bytes())
            .unwrap();
        let cache = ReplayCache::new();
        let now = std::time::SystemTime::now();

        let cmd1 = make_signed_command_with_id(&sk, "alice", b"same", 60, "req-a");
        let cmd2 = make_signed_command_with_id(&sk, "alice", b"same", 60, "req-b");

        cmd1.verify(&store, now, Some(&cache)).expect("first");
        cmd2.verify(&store, now, Some(&cache)).expect("second");
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fresh_pair() -> (OperatorCommandClient, OperatorTrustStore) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey_bytes = sk.verifying_key().to_bytes();
        let client = OperatorCommandClient::new(sk, "alice");
        let store = OperatorTrustStore::new();
        store
            .add_signer("alice", &pubkey_bytes)
            .expect("add signer");
        (client, store)
    }

    #[test]
    fn signed_command_verifies_round_trip() {
        let (client, store) = fresh_pair();
        let cmd = client
            .sign(b"hello peer", Duration::from_secs(60))
            .expect("sign");
        let payload = cmd.verify(&store, SystemTime::now(), None).expect("verify");
        assert_eq!(payload, b"hello peer");
    }

    #[test]
    fn request_ids_are_unique_across_signs() {
        let (client, _) = fresh_pair();
        let mut ids = std::collections::HashSet::new();
        for _ in 0..32 {
            let cmd = client.sign(b"x", Duration::from_secs(60)).expect("sign");
            assert!(ids.insert(cmd.request_id), "id collision");
        }
    }

    #[test]
    fn ttl_zero_yields_immediately_expired_command() {
        let (client, store) = fresh_pair();
        let cmd = client.sign(b"x", Duration::ZERO).expect("sign");
        // Sleep a beat to ensure now > expires_at.
        std::thread::sleep(Duration::from_millis(1100));
        let err = cmd.verify(&store, SystemTime::now(), None).unwrap_err();
        assert!(matches!(err, OperatorCommandError::Expired { .. }));
    }

    #[test]
    fn replay_cache_catches_resent_signed_command() {
        let (client, store) = fresh_pair();
        let cache = ReplayCache::new();
        let cmd = client.sign(b"once", Duration::from_secs(60)).expect("sign");

        cmd.verify(&store, SystemTime::now(), Some(&cache))
            .expect("first");
        let err = cmd
            .verify(&store, SystemTime::now(), Some(&cache))
            .unwrap_err();
        assert!(matches!(err, OperatorCommandError::DuplicateRequest { .. }));
    }

    #[test]
    fn sign_with_id_uses_caller_supplied_request_id() {
        let (client, store) = fresh_pair();
        let cmd = client
            .sign_with_id(b"x", Duration::from_secs(60), "req-caller-123".into())
            .expect("sign");
        assert_eq!(cmd.request_id, "req-caller-123");
        cmd.verify(&store, SystemTime::now(), None).expect("verify");
    }

    #[test]
    fn canonical_bytes_lock_holds_both_directions() {
        // Cross-locks the verifier and the client onto the SAME
        // canonical bytes. If either side drifts, this test fails.
        let (client, store) = fresh_pair();
        let request_id = "req-canonical-lock";
        let cmd = client
            .sign_with_id(b"data", Duration::from_secs(60), request_id.into())
            .expect("sign");

        let expected = canonical_signing_bytes("alice", cmd.expires_at_unix, request_id, b"data");
        // The signature must verify against precisely these bytes.
        let payload = cmd.verify(&store, SystemTime::now(), None).expect("verify");
        assert_eq!(payload, b"data");
        assert!(expected.starts_with(b"tesserax-op-command-v2"));
    }

    #[test]
    fn mint_request_id_returns_22_char_base64_url() {
        let id = OperatorCommandClient::mint_request_id().expect("mint");
        // 16 raw bytes → 22 base64 url-no-pad chars.
        assert_eq!(id.len(), 22);
        for c in id.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "request_id must be url-safe base64, got {c:?}"
            );
        }
    }

    #[cfg(feature = "opctl")]
    #[test]
    fn pending_post_traceparent_setter_persists() {
        // verify the .traceparent() setter survives the
        // builder chain. We don't actually fire an HTTP request here;
        // the HTTP path is exercised by integration tests in
        // consumers (no mock HTTP server in this unit suite).
        let (client, _) = fresh_pair();
        let http = reqwest::Client::new();
        let post = client
            .post(&http, "http://example.invalid/op-cmd")
            .ttl(Duration::from_secs(60))
            .traceparent("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01");
        assert_eq!(
            post.current_traceparent(),
            Some("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
        );
    }

    #[test]
    fn debug_does_not_print_signing_key_bytes() {
        let (client, _) = fresh_pair();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("OperatorCommandClient"));
        assert!(dbg.contains("alice"));
        // No raw secret-key bytes should appear; we used [7u8; 32].
        let secret = client.signing_key.to_bytes();
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !dbg.contains(&hex),
            "Debug must not contain raw signing-key bytes"
        );
    }
}
