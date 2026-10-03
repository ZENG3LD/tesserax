//! `Transport::Ipc` end to end: a `tesserax::ServerBuilder` served over an
//! owner-only Unix socket through the root's listener-driver hook.
#![cfg(all(unix, feature = "server"))]

use std::fs::{self, Permissions};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::routing::get;
use tesserax::{ServerBuilder, Tier};
use tesserax_transport::TransportExt;
use tesserax_transport::local::connect_local;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct PrivateDir(PathBuf);

impl PrivateDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "txi-{:x}-{:x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One HTTP/1.1 request over the local socket.
async fn http(path: &Path, method: &str, uri: &str) -> (u16, String) {
    let mut s = connect_local(path).await.expect("connect");
    let req = format!(
        "{method} {uri} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text[9..12].parse().unwrap();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

fn builder(socket: &Path) -> ServerBuilder {
    ServerBuilder::new("ipc-e2e")
        .with_ipc(socket)
        .get_tier("/ping", get(|| async { "pong" }), Tier::Public)
        .get_tier(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
            Tier::Public,
        )
        .get_tier(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                "done"
            }),
            Tier::Public,
        )
}

#[tokio::test]
async fn ipc_transport_serves_the_router_over_an_owner_only_socket() {
    let dir = PrivateDir::new();
    let socket = dir.0.join("app.sock");
    let running = builder(&socket)
        .build()
        .await
        .expect("Ipc builds once the driver is registered")
        .start()
        .await
        .expect("start");
    let bound = running.local_path().expect("path reported").to_path_buf();
    assert_eq!(bound, fs::canonicalize(&dir.0).unwrap().join("app.sock"));
    assert_eq!(
        fs::symlink_metadata(&bound).unwrap().permissions().mode() & 0o777,
        0o600
    );

    assert_eq!(http(&bound, "GET", "/ping").await, (200, "pong".into()));
    // Handlers and guards see a loopback peer.
    assert_eq!(
        http(&bound, "GET", "/peer").await,
        (200, "127.0.0.1:0".into())
    );
    let (status, body) = http(&bound, "GET", "/readyz").await;
    assert_eq!(status, 200, "{body}");
    // Ipc is local-only, so the ungated admin built-in is allowed and works.
    assert_eq!(http(&bound, "POST", "/admin/drain").await.0, 200);
    assert_eq!(http(&bound, "GET", "/readyz").await.0, 503);

    running.shutdown();
    running.wait().await.expect("wait");
    assert!(!bound.exists(), "socket removed after shutdown");
}

#[tokio::test]
async fn in_flight_requests_finish_during_shutdown() {
    let dir = PrivateDir::new();
    let socket = dir.0.join("app.sock");
    let running = builder(&socket)
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let bound = running.local_path().unwrap().to_path_buf();
    let slow = tokio::spawn({
        let bound = bound.clone();
        async move { http(&bound, "GET", "/slow").await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    running.shutdown();
    running.wait().await.unwrap();
    assert_eq!(
        slow.await.unwrap(),
        (200, "done".into()),
        "drain waited for the request"
    );
    // After shutdown nothing listens.
    assert!(tokio::net::UnixStream::connect(&bound).await.is_err());
}

#[tokio::test]
async fn a_second_server_on_the_same_socket_fails_to_start() {
    let dir = PrivateDir::new();
    let socket = dir.0.join("app.sock");
    let first = builder(&socket)
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let err = builder(&socket)
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap_err();
    assert!(
        matches!(err, tesserax::RunError::Io(ref e) if e.kind() == std::io::ErrorKind::AddrInUse),
        "{err}"
    );
    // The first one is untouched.
    assert_eq!(
        http(first.local_path().unwrap(), "GET", "/ping").await.0,
        200
    );
    first.shutdown();
    first.wait().await.unwrap();
}

#[tokio::test]
async fn an_insecure_socket_directory_fails_to_start() {
    let dir = PrivateDir::new();
    fs::set_permissions(&dir.0, Permissions::from_mode(0o755)).unwrap();
    let err = builder(&dir.0.join("app.sock"))
        .build()
        .await
        .unwrap()
        .start()
        .await
        .unwrap_err();
    assert!(
        matches!(err, tesserax::RunError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{err}"
    );
}
