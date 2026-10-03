//! Local link plumbing shared by [`local_shell`](super::local_shell) and
//! the local [`RemoteHandle`](super::RemoteHandle): per-door secrets,
//! bounded NDJSON line IO and the mutual proof handshake.
//!
//! The handshake follows [`tesserax_transport::proof`]: the client names a
//! door and sends a nonce; the server answers its own nonce and proof; the
//! client checks it and only then answers its proof; the server checks
//! that and says `Ready`. Neither end sends application data before the
//! peer's proof matched, and the door's role byte is bound into both
//! proofs. Each door has its own secret, so a client holding only the
//! observe secret cannot open the control door.

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tesserax_transport::proof::{
    LinkContext, LinkRole, NONCE_BYTES, PROOF_BYTES, link_proof, proofs_match, random_nonce,
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::wire::{LinkAuthenticate, LinkDoor, LinkHello, LinkServerFrame, hex_decode, hex_encode};
use crate::error::ShellError;

/// Largest handshake line either end reads.
pub(crate) const MAX_HANDSHAKE_LINE: usize = 4 * 1024;
/// Default largest frame (one NDJSON line) of a link.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Default time a handshake may take.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Secrets of the doors of one local link, plus the proof context both
/// ends bind their proofs to.
///
/// A server holds the secret of every door it serves; a client holds the
/// secrets of the doors it may use. A secret must not be empty.
#[derive(Clone)]
pub struct LinkKeys {
    control: Option<Zeroizing<Vec<u8>>>,
    observe: Option<Zeroizing<Vec<u8>>>,
    domain: Vec<u8>,
    binding: Vec<u8>,
}

impl core::fmt::Debug for LinkKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinkKeys")
            .field("control", &self.control.is_some())
            .field("observe", &self.observe.is_some())
            .field("domain_len", &self.domain.len())
            .field("binding_len", &self.binding.len())
            .finish()
    }
}

impl LinkKeys {
    /// No door yet; proofs bound to `cx` (a protocol domain that no other
    /// domain is a prefix of, and the negotiated binding).
    pub fn new(cx: LinkContext<'_>) -> Self {
        Self {
            control: None,
            observe: None,
            domain: cx.domain.to_vec(),
            binding: cx.binding.to_vec(),
        }
    }

    /// Serves (or may use) the control door with `secret`.
    pub fn control(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.control = Some(Zeroizing::new(secret.into()));
        self
    }

    /// Serves (or may use) the observe door with `secret`.
    pub fn observe(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.observe = Some(Zeroizing::new(secret.into()));
        self
    }

    /// True iff `door` has a secret.
    pub fn has(&self, door: LinkDoor) -> bool {
        self.secret(door).is_some()
    }

    fn secret(&self, door: LinkDoor) -> Option<&[u8]> {
        match door {
            LinkDoor::Control => self.control.as_deref().map(Vec::as_slice),
            LinkDoor::Observe => self.observe.as_deref().map(Vec::as_slice),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ShellError> {
        if self.domain.is_empty() {
            return Err(ShellError::Config("link proof domain is empty".into()));
        }
        if self.control.is_none() && self.observe.is_none() {
            return Err(ShellError::Config("no door has a secret".into()));
        }
        if [&self.control, &self.observe]
            .into_iter()
            .flatten()
            .any(|s| s.is_empty())
        {
            return Err(ShellError::Config("a door secret is empty".into()));
        }
        Ok(())
    }

    fn proof(
        &self,
        door: LinkDoor,
        direction: LinkRole,
        client_nonce: &[u8; NONCE_BYTES],
        server_nonce: &[u8; NONCE_BYTES],
    ) -> Option<[u8; PROOF_BYTES]> {
        let secret = self.secret(door)?;
        let cx = LinkContext::new(&self.domain, &self.binding);
        Some(link_proof(
            secret,
            door.role_byte(),
            direction,
            client_nonce,
            server_nonce,
            &cx,
        ))
    }
}

/// Reads one `\n`-terminated line of at most `max` bytes (the terminator
/// and a preceding `\r` are stripped). `Ok(None)` at a clean end of stream.
pub(crate) async fn read_line<R>(reader: &mut R, max: usize) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            };
        }
        let (take, done) = match available.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (available.len(), false),
        };
        if line.len() + take > max.saturating_add(1) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame longer than {max} bytes"),
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if done {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

/// Reads and decodes one line as `T`.
pub(crate) async fn read_json<R, T>(reader: &mut R, max: usize) -> Result<Option<T>, ShellError>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    match read_line(reader, max).await? {
        None => Ok(None),
        Some(line) => serde_json::from_slice(&line)
            .map(Some)
            .map_err(|e| ShellError::Codec(e.to_string())),
    }
}

/// Encodes `value` as one line (refusing lines longer than `max`) and
/// flushes it.
pub(crate) async fn write_json<W, T>(
    writer: &mut W,
    value: &T,
    max: usize,
) -> Result<(), ShellError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let mut line = serde_json::to_vec(value).map_err(|e| ShellError::Codec(e.to_string()))?;
    if line.len() > max {
        return Err(ShellError::Codec(format!(
            "frame of {} bytes exceeds {max}",
            line.len()
        )));
    }
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await?;
    Ok(())
}

fn fresh_nonce() -> Result<[u8; NONCE_BYTES], ShellError> {
    random_nonce().map_err(|e| ShellError::Handshake(e.to_string()))
}

/// Server side of the handshake. Returns the door the client proved.
#[cfg(feature = "shell")]
pub(crate) async fn accept_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    keys: &LinkKeys,
) -> Result<LinkDoor, ShellError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let refuse = |reason: &str| LinkServerFrame::Refused {
        reason: reason.to_owned(),
    };
    let hello: LinkHello = read_json(reader, MAX_HANDSHAKE_LINE)
        .await?
        .ok_or_else(|| ShellError::Handshake("link closed before hello".into()))?;
    let Some(client_nonce) = hex_decode::<NONCE_BYTES>(&hello.nonce) else {
        write_json(writer, &refuse("malformed nonce"), MAX_HANDSHAKE_LINE).await?;
        return Err(ShellError::Handshake("malformed client nonce".into()));
    };
    let server_nonce = fresh_nonce()?;
    let Some(server_proof) = keys.proof(hello.door, LinkRole::Server, &client_nonce, &server_nonce)
    else {
        write_json(writer, &refuse("door not served"), MAX_HANDSHAKE_LINE).await?;
        return Err(ShellError::Handshake(format!(
            "{} door not served",
            hello.door.as_str()
        )));
    };
    let challenge = LinkServerFrame::Challenge {
        nonce: hex_encode(&server_nonce),
        proof: hex_encode(&server_proof),
    };
    write_json(writer, &challenge, MAX_HANDSHAKE_LINE).await?;

    let auth: LinkAuthenticate = read_json(reader, MAX_HANDSHAKE_LINE)
        .await?
        .ok_or_else(|| ShellError::Handshake("link closed before proof".into()))?;
    let expected = keys.proof(hello.door, LinkRole::Client, &client_nonce, &server_nonce);
    let matched = match (hex_decode::<PROOF_BYTES>(&auth.proof), expected) {
        (Some(actual), Some(expected)) => proofs_match(&actual, &expected),
        _ => false,
    };
    if !matched {
        write_json(writer, &refuse("proof mismatch"), MAX_HANDSHAKE_LINE).await?;
        return Err(ShellError::Handshake("client proof mismatch".into()));
    }
    write_json(writer, &LinkServerFrame::Ready, MAX_HANDSHAKE_LINE).await?;
    Ok(hello.door)
}

/// Client side of the handshake for `door`.
#[cfg(feature = "client")]
pub(crate) async fn connect_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    keys: &LinkKeys,
    door: LinkDoor,
) -> Result<(), ShellError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !keys.has(door) {
        return Err(ShellError::Unauthorized {
            door: door.as_str(),
        });
    }
    let client_nonce = fresh_nonce()?;
    let hello = LinkHello {
        door,
        nonce: hex_encode(&client_nonce),
    };
    write_json(writer, &hello, MAX_HANDSHAKE_LINE).await?;
    let frame: LinkServerFrame = read_json(reader, MAX_HANDSHAKE_LINE)
        .await?
        .ok_or_else(|| ShellError::Handshake("link closed before challenge".into()))?;
    let (nonce, proof) = match frame {
        LinkServerFrame::Challenge { nonce, proof } => (nonce, proof),
        LinkServerFrame::Refused { reason } => return Err(ShellError::Handshake(reason)),
        LinkServerFrame::Ready => {
            return Err(ShellError::Protocol("ready before challenge".into()));
        }
    };
    let (Some(server_nonce), Some(server_proof)) = (
        hex_decode::<NONCE_BYTES>(&nonce),
        hex_decode::<PROOF_BYTES>(&proof),
    ) else {
        return Err(ShellError::Handshake("malformed challenge".into()));
    };
    let expected = keys.proof(door, LinkRole::Server, &client_nonce, &server_nonce);
    if !expected.is_some_and(|e| proofs_match(&server_proof, &e)) {
        return Err(ShellError::Handshake("server proof mismatch".into()));
    }
    let Some(client_proof) = keys.proof(door, LinkRole::Client, &client_nonce, &server_nonce)
    else {
        return Err(ShellError::Unauthorized {
            door: door.as_str(),
        });
    };
    let auth = LinkAuthenticate {
        proof: hex_encode(&client_proof),
    };
    write_json(writer, &auth, MAX_HANDSHAKE_LINE).await?;
    match read_json(reader, MAX_HANDSHAKE_LINE).await? {
        Some(LinkServerFrame::Ready) => Ok(()),
        Some(LinkServerFrame::Refused { reason }) => Err(ShellError::Handshake(reason)),
        Some(LinkServerFrame::Challenge { .. }) => {
            Err(ShellError::Protocol("second challenge".into()))
        }
        None => Err(ShellError::Handshake("link closed before ready".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::BufReader;

    fn keys() -> LinkKeys {
        LinkKeys::new(LinkContext::new(b"test-link\0", b"v1"))
    }

    #[test]
    fn validation_refuses_unusable_keys() {
        assert!(keys().validate().is_err());
        assert!(keys().control(Vec::new()).validate().is_err());
        assert!(
            LinkKeys::new(LinkContext::new(b"", b""))
                .control(b"s".to_vec())
                .validate()
                .is_err()
        );
        assert!(keys().observe(b"s".to_vec()).validate().is_ok());
    }

    #[test]
    fn lines_are_bounded_and_stripped() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut r = BufReader::new(&b"ab\r\ncd\nlonger-than-four\n"[..]);
            assert_eq!(read_line(&mut r, 4).await.unwrap(), Some(b"ab".to_vec()));
            assert_eq!(read_line(&mut r, 4).await.unwrap(), Some(b"cd".to_vec()));
            assert!(read_line(&mut r, 4).await.is_err());
            let mut empty = BufReader::new(&b""[..]);
            assert_eq!(read_line(&mut empty, 4).await.unwrap(), None);
            let mut cut = BufReader::new(&b"abc"[..]);
            assert!(read_line(&mut cut, 4).await.is_err());
        });
    }

    #[cfg(all(feature = "shell", feature = "client"))]
    async fn run(server: LinkKeys, client: LinkKeys, door: LinkDoor) -> (bool, bool) {
        let (a, b) = tokio::io::duplex(4096);
        let (ar, mut aw) = tokio::io::split(a);
        let (br, mut bw) = tokio::io::split(b);
        let server = tokio::spawn(async move {
            let mut r = BufReader::new(ar);
            accept_handshake(&mut r, &mut aw, &server).await
        });
        let mut r = BufReader::new(br);
        let client_ok = connect_handshake(&mut r, &mut bw, &client, door)
            .await
            .is_ok();
        drop(bw);
        drop(r);
        let server_ok = matches!(server.await, Ok(Ok(d)) if d == door);
        (client_ok, server_ok)
    }

    #[cfg(all(feature = "shell", feature = "client"))]
    #[test]
    fn handshake_admits_only_the_proven_door() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = keys()
                .control(b"c-secret".to_vec())
                .observe(b"o-secret".to_vec());
            let both = server.clone();
            assert_eq!(
                run(server.clone(), both.clone(), LinkDoor::Control).await,
                (true, true)
            );
            assert_eq!(
                run(server.clone(), both, LinkDoor::Observe).await,
                (true, true)
            );

            // An observe-only client has no control proof to offer.
            let observer = keys().observe(b"o-secret".to_vec());
            assert_eq!(
                run(server.clone(), observer.clone(), LinkDoor::Observe).await,
                (true, true)
            );
            // Claiming the control door with the observe secret fails both ways.
            let forged = keys().control(b"o-secret".to_vec());
            assert_eq!(
                run(server.clone(), forged, LinkDoor::Control).await,
                (false, false)
            );
            // Other binding: nothing matches.
            let other = LinkKeys::new(LinkContext::new(b"test-link\0", b"v2"))
                .observe(b"o-secret".to_vec());
            assert_eq!(
                run(server.clone(), other, LinkDoor::Observe).await,
                (false, false)
            );
            // A door the server does not serve.
            let only_observe = keys().observe(b"o-secret".to_vec());
            let controller = keys().control(b"c-secret".to_vec());
            assert_eq!(
                run(only_observe, controller, LinkDoor::Control).await,
                (false, false)
            );
        });
    }
}
