//! The call-home preface: one frame, sent by a peer that dialled out
//! instead of waiting to be dialled.
//!
//! Normally the dialling side knows whose socket it holds. A peer with no
//! reachable address connects out to a relay instead, and the relay then
//! holds an accepted socket without knowing which peer is on it — and
//! cannot verify that peer's proof, because the proof is keyed by that
//! peer's own secret. So the peer names itself first; the relay uses the
//! name only to select which configured secret the handshake that follows
//! is checked against. The name is a claim, not a credential: a peer that
//! announces a name it holds no secret for fails at the next frame, exactly
//! as an impostor on a dialled connection would.
//!
//! Wire form (frozen, byte-identical to deployed peers): a `u32`
//! little-endian length, then that many bytes of JSON
//! `{"build_stamp": <label>, "node_id": <peer id>}`. `label` is the
//! caller's compatibility label (both ends must agree on it); a mismatch is
//! reported as its own error because it means a mixed deployment, not a
//! hostile peer.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound of the preface body in bytes.
pub const MAX_ANNOUNCE_BYTES: usize = 8 * 1024;

/// How long [`read_announce`] waits for the whole preface. Short on
/// purpose: an accepted socket that has said nothing costs only the
/// relay.
pub const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(2);

/// The preface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Announce {
    /// Compatibility label both ends must share (wire key `build_stamp`).
    #[serde(rename = "build_stamp")]
    pub label: String,
    /// The peer's claimed id (wire key `node_id`).
    #[serde(rename = "node_id")]
    pub peer_id: String,
}

/// Why a preface could not be written or read.
#[derive(Debug, Error)]
pub enum CallHomeError {
    /// Nothing, or not enough, arrived before [`ANNOUNCE_TIMEOUT`].
    #[error("call-home peer did not announce itself in time")]
    TimedOut,
    /// Stream failure.
    #[error("call-home preface io: {0}")]
    Io(#[from] std::io::Error),
    /// The body was not the preface JSON.
    #[error("call-home preface is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The length prefix is 0 or above [`MAX_ANNOUNCE_BYTES`].
    #[error("call-home preface length {length} is outside 1..={max}")]
    InvalidLength {
        /// Announced (or produced) length.
        length: usize,
        /// Limit.
        max: usize,
    },
    /// The peer runs with another compatibility label.
    #[error("call-home label mismatch: local={local} remote={announced}")]
    LabelMismatch {
        /// This side's label.
        local: String,
        /// The peer's label.
        announced: String,
    },
    /// The announced id failed the caller's syntax check.
    #[error("call-home preface carried an invalid peer id")]
    InvalidPeerId,
}

/// Dialling side: names itself on a socket it just opened.
pub async fn write_announce<W>(
    writer: &mut W,
    label: &str,
    peer_id: &str,
) -> Result<(), CallHomeError>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(&Announce {
        label: label.to_owned(),
        peer_id: peer_id.to_owned(),
    })?;
    if payload.is_empty() || payload.len() > MAX_ANNOUNCE_BYTES {
        return Err(CallHomeError::InvalidLength {
            length: payload.len(),
            max: MAX_ANNOUNCE_BYTES,
        });
    }
    // Length is bounded above, so it fits in u32.
    writer.write_u32_le(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Accepting side: reads the preface within [`ANNOUNCE_TIMEOUT`], checks
/// the label, and returns the announced peer id if `valid_peer_id`
/// accepts its syntax. The caller then looks up that peer's secret and
/// runs the handshake.
pub async fn read_announce<R>(
    reader: &mut R,
    expected_label: &str,
    valid_peer_id: impl FnOnce(&str) -> bool,
) -> Result<String, CallHomeError>
where
    R: AsyncRead + Unpin,
{
    read_announce_within(reader, expected_label, valid_peer_id, ANNOUNCE_TIMEOUT).await
}

/// [`read_announce`] with an explicit deadline.
pub async fn read_announce_within<R>(
    reader: &mut R,
    expected_label: &str,
    valid_peer_id: impl FnOnce(&str) -> bool,
    deadline: Duration,
) -> Result<String, CallHomeError>
where
    R: AsyncRead + Unpin,
{
    let announce = tokio::time::timeout(deadline, read_frame(reader))
        .await
        .map_err(|_| CallHomeError::TimedOut)??;
    if announce.label != expected_label {
        return Err(CallHomeError::LabelMismatch {
            local: expected_label.to_owned(),
            announced: announce.label,
        });
    }
    if !valid_peer_id(&announce.peer_id) {
        return Err(CallHomeError::InvalidPeerId);
    }
    Ok(announce.peer_id)
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Announce, CallHomeError> {
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > MAX_ANNOUNCE_BYTES {
        return Err(CallHomeError::InvalidLength {
            length,
            max: MAX_ANNOUNCE_BYTES,
        });
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &str = "0123456789abcdef";

    fn any_id(s: &str) -> bool {
        !s.is_empty()
    }

    #[tokio::test]
    async fn a_peer_names_itself_and_the_relay_reads_the_name() {
        let mut wire = Vec::new();
        write_announce(&mut wire, LABEL, "edge-7").await.unwrap();
        let id = read_announce(&mut wire.as_slice(), LABEL, any_id)
            .await
            .unwrap();
        assert_eq!(id, "edge-7");
    }

    /// The frozen wire form, byte for byte.
    #[tokio::test]
    async fn wire_form_is_length_prefixed_json_with_the_frozen_keys() {
        let mut wire = Vec::new();
        write_announce(&mut wire, "L", "p").await.unwrap();
        let body = br#"{"build_stamp":"L","node_id":"p"}"#;
        let mut expected = (body.len() as u32).to_le_bytes().to_vec();
        expected.extend_from_slice(body);
        assert_eq!(wire, expected);
    }

    #[tokio::test]
    async fn a_label_mismatch_names_itself() {
        let foreign = "f".repeat(LABEL.len());
        let mut wire = Vec::new();
        write_announce(&mut wire, &foreign, "edge-7").await.unwrap();
        let err = read_announce(&mut wire.as_slice(), LABEL, any_id)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, CallHomeError::LabelMismatch { announced, .. } if *announced == foreign),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("call-home label mismatch: local={LABEL} remote={foreign}")
        );
    }

    #[tokio::test]
    async fn the_caller_rejects_a_malformed_id() {
        let mut wire = Vec::new();
        write_announce(&mut wire, LABEL, "bad id").await.unwrap();
        let err = read_announce(&mut wire.as_slice(), LABEL, |s| !s.contains(' '))
            .await
            .unwrap_err();
        assert!(matches!(err, CallHomeError::InvalidPeerId));
    }

    #[tokio::test]
    async fn oversized_and_empty_frames_are_refused() {
        for len in [0u32, (MAX_ANNOUNCE_BYTES + 1) as u32] {
            let wire = len.to_le_bytes().to_vec();
            let err = read_announce(&mut wire.as_slice(), LABEL, any_id)
                .await
                .unwrap_err();
            assert!(
                matches!(err, CallHomeError::InvalidLength { .. }),
                "{err:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_socket_that_says_nothing_is_dropped_rather_than_held() {
        let (client, mut server) = tokio::io::duplex(64);
        let err = read_announce_within(&mut server, LABEL, any_id, Duration::from_millis(50))
            .await
            .unwrap_err();
        drop(client);
        assert!(matches!(err, CallHomeError::TimedOut), "{err:?}");
    }
}
