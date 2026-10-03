//! HTTP push of a gossip envelope (features `peer-trust` + `opctl`).

use crate::peer_trust::GossipEnvelope;

/// Push failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum GossipPushError {
    #[error("http: {0}")]
    Http(String),
    #[error("peer returned {status}: {body}")]
    PeerRejected { status: u16, body: String },
}

/// Result returned by [`push_envelope`].
#[derive(Debug, Clone)]
pub struct GossipPushResult {
    /// HTTP status.
    pub status: u16,
    /// Raw response body. Caller decodes JSON if they need the
    /// `{"applied": N}` counter; we don't enforce a schema here so
    /// peer implementations can vary.
    pub body: String,
}

/// Ship `env` to `peer_url` via HTTP POST with JSON content-type.
/// Caller decides whether to consider non-2xx an error.
pub async fn push_envelope(
    client: &reqwest::Client,
    peer_url: &str,
    env: &GossipEnvelope,
) -> Result<GossipPushResult, GossipPushError> {
    let resp = client
        .post(peer_url)
        .json(env)
        .send()
        .await
        .map_err(|e| GossipPushError::Http(e.to_string()))?;
    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| GossipPushError::Http(format!("read body: {e}")))?;
    if !(200..300).contains(&status) {
        return Err(GossipPushError::PeerRejected { status, body });
    }
    Ok(GossipPushResult { status, body })
}
