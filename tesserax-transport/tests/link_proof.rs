//! The link proof, and the mutual handshake it exists for, end to end over
//! a real owner-only local socket and over loopback TCP.
//!
//! Vectors are computed with secret `local-secret`, client nonce `[3; 32]`,
//! server nonce `[7; 32]`, build label `STAMP` and the compatibility
//! negotiation `BINDING` (a Linux / Unix-socket offer and selection). The
//! domain is the protocol tag followed by the length-prefixed build label,
//! which is exactly `domain_with_label(TAG, STAMP)`; the binding is passed
//! unchanged. Role bytes: 1 = may operate, 2 = may only observe.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tesserax_transport::proof::{
    LinkContext, LinkRole, NONCE_BYTES, domain_with_label, link_proof, proofs_match, random_nonce,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

/// Protocol tag for these vectors.
const TAG: &[u8] = b"tesserax-node-auth-negotiated-v1\0";
const STAMP: &[u8] = b"850d246138415fd45ad4369e12090e00f002e82b";
const BINDING: &str = r#"{"offer":{"build_stamp":"850d246138415fd45ad4369e12090e00f002e82b","capabilities":["compatibility.metadata"],"state_schema":{"versions":{"minimum":1,"maximum":1}}},"selected":{"build_stamp":"850d246138415fd45ad4369e12090e00f002e82b","capabilities":["compatibility.metadata"],"host":{"operating_system":"linux","architecture":"x86_64"},"path_semantics":{"style":"posix","encoding":"utf8"},"local_transport":"unix-domain-socket","state_schema_version":1,"provider_contracts":[]}}"#;

const OPERATOR: u8 = 1;
const OBSERVER: u8 = 2;

fn unhex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn negotiated_proof_vectors_match_the_tesserax_tag() {
    let domain = domain_with_label(TAG, STAMP).unwrap();
    let cx = LinkContext::new(&domain, BINDING.as_bytes());
    let cn = [3u8; NONCE_BYTES];
    let sn = [7u8; NONCE_BYTES];
    for (dir, role, expected) in [
        (
            LinkRole::Server,
            OPERATOR,
            "18367446a590f4c53ca0341cdd43d93cf6e1d87e052e1faaac7b6ddcb73c5ffd",
        ),
        (
            LinkRole::Server,
            OBSERVER,
            "419e6e5e6d01e00d1f7efc13a86f65c3fcb5fe92c76d68a134d131bff5bdbc7b",
        ),
        (
            LinkRole::Client,
            OPERATOR,
            "766e8c212e64b8da40ef75c62f2d3a4ca0ddea0cd808b3dae8d0eedbfdefeae3",
        ),
        (
            LinkRole::Client,
            OBSERVER,
            "7e202c553714ad1cb34fbf8b1bba87106974241ec5d11549a05c0583fd30843e",
        ),
    ] {
        let proof = link_proof(b"local-secret", role, dir, &cn, &sn, &cx);
        assert_eq!(proof, unhex(expected), "{dir:?} role {role}");
    }
    // Any change to the negotiated binding moves the proof.
    let tampered = BINDING.replace("\"posix\"", "\"windows\"");
    let other = link_proof(
        b"local-secret",
        OPERATOR,
        LinkRole::Server,
        &cn,
        &sn,
        &LinkContext::new(&domain, tampered.as_bytes()),
    );
    assert!(!proofs_match(
        &other,
        &unhex("18367446a590f4c53ca0341cdd43d93cf6e1d87e052e1faaac7b6ddcb73c5ffd")
    ));
}

// ---- the handshake the proof exists for ------------------------------------------------------

const TEST_TIMEOUT: Duration = Duration::from_secs(2);
const NEGATIVE_OBSERVATION: Duration = Duration::from_millis(250);
const MAX_FRAME: usize = 8 * 1024;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Frame {
    Hello {
        role: u8,
        client_nonce: [u8; 32],
    },
    Challenge {
        server_nonce: [u8; 32],
        server_proof: [u8; 32],
    },
    Authenticate {
        client_proof: [u8; 32],
    },
    Welcome {
        event_sequence: u64,
    },
    Request {
        request_id: u64,
    },
    Reply {
        request_id: u64,
        event_sequence: u64,
    },
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> std::io::Result<()> {
    let body = serde_json::to_vec(f)?;
    w.write_u32_le(body.len() as u32).await?;
    w.write_all(&body).await?;
    w.flush().await
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Frame> {
    let len = r.read_u32_le().await? as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame length",
        ));
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

fn context() -> (Vec<u8>, &'static [u8]) {
    (domain_with_label(TAG, STAMP).unwrap(), BINDING.as_bytes())
}

/// Client side: hello → verify the server's proof → authenticate → one
/// request. Sends nothing after a challenge whose proof does not match.
async fn client<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    secret: &[u8],
    role: u8,
) -> Result<(u64, u64), &'static str> {
    let (domain, binding) = context();
    let cx = LinkContext::new(&domain, binding);
    let client_nonce = random_nonce().map_err(|_| "rng")?;
    write_frame(&mut s, &Frame::Hello { role, client_nonce })
        .await
        .map_err(|_| "write hello")?;
    let Frame::Challenge {
        server_nonce,
        server_proof,
    } = timeout(TEST_TIMEOUT, read_frame(&mut s))
        .await
        .map_err(|_| "timeout")?
        .map_err(|_| "read")?
    else {
        return Err("expected a challenge");
    };
    let expected = link_proof(
        secret,
        role,
        LinkRole::Server,
        &client_nonce,
        &server_nonce,
        &cx,
    );
    if !proofs_match(&server_proof, &expected) {
        return Err("server proof does not match");
    }
    let client_proof = link_proof(
        secret,
        role,
        LinkRole::Client,
        &client_nonce,
        &server_nonce,
        &cx,
    );
    write_frame(&mut s, &Frame::Authenticate { client_proof })
        .await
        .map_err(|_| "write auth")?;
    let Frame::Welcome { event_sequence } = timeout(TEST_TIMEOUT, read_frame(&mut s))
        .await
        .map_err(|_| "timeout")?
        .map_err(|_| "read")?
    else {
        return Err("expected welcome");
    };
    write_frame(&mut s, &Frame::Request { request_id: 1 })
        .await
        .map_err(|_| "write request")?;
    match timeout(TEST_TIMEOUT, read_frame(&mut s))
        .await
        .map_err(|_| "timeout")?
        .map_err(|_| "read")?
    {
        Frame::Reply {
            request_id,
            event_sequence: seq,
        } if seq == event_sequence => Ok((request_id, seq)),
        _ => Err("expected reply"),
    }
}

/// What the fake server saw.
#[derive(Debug, PartialEq)]
enum ServerSaw {
    /// The client authenticated and asked for request `id`.
    Served(u64),
    /// A frame arrived after the challenge (it should not have).
    FrameAfterChallenge,
    /// Nothing arrived after the challenge.
    Silence,
}

/// Server side: challenge (optionally with a corrupted proof), then either
/// check the client's proof and serve one request, or just watch.
async fn server<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    secret: &[u8],
    expected_role: u8,
    corrupt_proof: bool,
) -> ServerSaw {
    let (domain, binding) = context();
    let cx = LinkContext::new(&domain, binding);
    let Frame::Hello { role, client_nonce } = read_frame(&mut s).await.unwrap() else {
        panic!("first frame must be hello");
    };
    assert_eq!(role, expected_role);
    let server_nonce = [0x5a; 32];
    let mut server_proof = link_proof(
        secret,
        role,
        LinkRole::Server,
        &client_nonce,
        &server_nonce,
        &cx,
    );
    if corrupt_proof {
        server_proof[0] ^= 1;
    }
    write_frame(
        &mut s,
        &Frame::Challenge {
            server_nonce,
            server_proof,
        },
    )
    .await
    .unwrap();
    match timeout(NEGATIVE_OBSERVATION, read_frame(&mut s)).await {
        Ok(Ok(Frame::Authenticate { client_proof })) => {
            let expected = link_proof(
                secret,
                role,
                LinkRole::Client,
                &client_nonce,
                &server_nonce,
                &cx,
            );
            if !proofs_match(&client_proof, &expected) {
                return ServerSaw::FrameAfterChallenge;
            }
            write_frame(&mut s, &Frame::Welcome { event_sequence: 7 })
                .await
                .unwrap();
            let Frame::Request { request_id } = read_frame(&mut s).await.unwrap() else {
                panic!("authenticated client must request");
            };
            write_frame(
                &mut s,
                &Frame::Reply {
                    request_id,
                    event_sequence: 7,
                },
            )
            .await
            .unwrap();
            ServerSaw::Served(request_id)
        }
        Ok(Ok(_)) => ServerSaw::FrameAfterChallenge,
        Ok(Err(_)) | Err(_) => ServerSaw::Silence,
    }
}

const TOKEN: &[u8] = b"unix-e2e-access-token";
const WRONG_TOKEN: &[u8] = b"unix-e2e-wrong-token";

#[cfg(unix)]
mod over_owner_only_socket {
    use super::*;
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tesserax_transport::local::{OwnerOnlyListener, connect_local};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct PrivateDir(PathBuf);

    impl PrivateDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "txp-{:x}-{:x}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn endpoint(&self) -> PathBuf {
            self.0.join("s")
        }
    }

    impl Drop for PrivateDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn run(
        client_token: &'static [u8],
        corrupt: bool,
    ) -> (Result<(u64, u64), &'static str>, ServerSaw) {
        let dir = PrivateDir::new();
        let mut listener = OwnerOnlyListener::bind(dir.endpoint()).await.unwrap();
        let srv = tokio::spawn(async move {
            let stream = timeout(TEST_TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            server(stream, TOKEN, OBSERVER, corrupt).await
        });
        let stream = connect_local(dir.endpoint()).await.unwrap();
        let outcome = timeout(TEST_TIMEOUT, client(stream, client_token, OBSERVER))
            .await
            .unwrap();
        let saw = timeout(TEST_TIMEOUT, srv).await.unwrap().unwrap();
        (outcome, saw)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authenticates_and_correlates_the_first_request() {
        let (outcome, saw) = run(TOKEN, false).await;
        assert_eq!(outcome, Ok((1, 7)));
        assert_eq!(
            saw,
            ServerSaw::Served(1),
            "first request keeps its correlation id"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_server_proof_is_refused_before_any_request() {
        let (outcome, saw) = run(TOKEN, true).await;
        assert_eq!(outcome, Err("server proof does not match"));
        assert_eq!(
            saw,
            ServerSaw::Silence,
            "client sends nothing after a bad server proof"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_token_is_refused_before_any_request() {
        let (outcome, saw) = run(WRONG_TOKEN, false).await;
        assert_eq!(outcome, Err("server proof does not match"));
        assert_eq!(saw, ServerSaw::Silence);
    }
}

mod over_loopback_tcp {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tesserax_transport::local::connect_loopback;

    #[tokio::test(flavor = "current_thread")]
    async fn authenticates_over_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            server(stream, TOKEN, OPERATOR, false).await
        });
        let stream = connect_loopback(addr).await.unwrap();
        let outcome = timeout(TEST_TIMEOUT, client(stream, TOKEN, OPERATOR))
            .await
            .unwrap();
        assert_eq!(outcome, Ok((1, 7)));
        assert_eq!(srv.await.unwrap(), ServerSaw::Served(1));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_token_over_loopback_sends_nothing_after_the_challenge() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server(stream, TOKEN, OPERATOR, false).await
        });
        let stream = connect_loopback(addr).await.unwrap();
        let outcome = timeout(TEST_TIMEOUT, client(stream, WRONG_TOKEN, OPERATOR))
            .await
            .unwrap();
        assert_eq!(outcome, Err("server proof does not match"));
        assert_eq!(srv.await.unwrap(), ServerSaw::Silence);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_non_loopback_address_is_refused_before_connect() {
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);
        let err = connect_loopback(endpoint).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
