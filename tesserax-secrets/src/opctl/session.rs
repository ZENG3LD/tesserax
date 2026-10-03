//! [`Session`]: a signing key, an HTTP client, a service URL and the pinned
//! service identity; each call signs, sends and verifies the signed
//! response.

use std::time::Duration;

use crate::opcmd::{OperatorCommandClient, OperatorCommandSendError};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::opctl::response_verify::{
    ResponseVerifyError, VerifiedResponse, verify_response_signature,
};

/// Call failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SessionError {
    #[error("http client: {0}")]
    HttpClient(String),
    #[error("sign / send: {0}")]
    Send(#[from] OperatorCommandSendError),
    #[error("verify: {0}")]
    Verify(#[from] ResponseVerifyError),
}

/// A signed-call session.
pub struct Session {
    client: OperatorCommandClient,
    http: reqwest::Client,
    daemon_url: String,
    op_cmd_path: String,
    pinned_pubkey: VerifyingKey,
    pinned_fingerprint: String,
    default_ttl: Duration,
    max_skew_secs: u64,
}

impl Session {
    /// Build a new session.
    ///
    /// `daemon_url` is the base (`https://host[:port]`), NOT including
    /// the op-cmd path. The default path `/admin/op-cmd` is appended
    /// internally; override with [`Self::with_op_cmd_path`] if your
    /// consumer mounts somewhere else.
    pub fn new(
        signing_key: SigningKey,
        signer_id: impl Into<String>,
        daemon_url: impl Into<String>,
        pinned_pubkey: VerifyingKey,
        pinned_fingerprint: impl Into<String>,
    ) -> Result<Self, SessionError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("tesserax-opctl/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| SessionError::HttpClient(e.to_string()))?;
        Ok(Self {
            client: OperatorCommandClient::new(signing_key, signer_id),
            http,
            daemon_url: daemon_url.into().trim_end_matches('/').to_string(),
            op_cmd_path: "/admin/op-cmd".to_string(),
            pinned_pubkey,
            pinned_fingerprint: pinned_fingerprint.into(),
            default_ttl: Duration::from_secs(60),
            max_skew_secs: 300,
        })
    }

    /// Changes the command path (default `/admin/op-cmd`).
    pub fn with_op_cmd_path(mut self, path: impl Into<String>) -> Self {
        let p = path.into();
        self.op_cmd_path = if p.starts_with('/') {
            p
        } else {
            format!("/{p}")
        };
        self
    }

    /// Changes the default TTL (60 s).
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Changes the accepted clock skew (300 s).
    pub fn with_max_skew(mut self, max_skew_secs: u64) -> Self {
        self.max_skew_secs = max_skew_secs;
        self
    }

    /// Pinned fingerprint.
    pub fn pinned_fingerprint(&self) -> &str {
        &self.pinned_fingerprint
    }

    /// Signer id.
    pub fn signer_id(&self) -> &str {
        self.client.signer_id()
    }

    /// Full command URL.
    pub fn op_cmd_url(&self) -> String {
        format!("{}{}", self.daemon_url, self.op_cmd_path)
    }

    /// Sign + ship + verify. `payload` is the action body the daemon
    /// expects (free-form, deserialised on the daemon side).
    pub async fn call(&self, payload: &[u8]) -> Result<VerifiedResponse, SessionError> {
        self.call_with_ttl(payload, self.default_ttl).await
    }

    /// [`call`](Self::call) with an explicit TTL.
    pub async fn call_with_ttl(
        &self,
        payload: &[u8],
        ttl: Duration,
    ) -> Result<VerifiedResponse, SessionError> {
        let url = self.op_cmd_url();
        let resp = self
            .client
            .post(&self.http, &url)
            .json_payload(payload.to_vec())
            .ttl(ttl)
            .send()
            .await?;
        let verified = verify_response_signature(
            resp,
            &self.op_cmd_path,
            &self.pinned_pubkey,
            &self.pinned_fingerprint,
            self.max_skew_secs,
        )
        .await?;
        Ok(verified)
    }
}
