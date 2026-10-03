//! Discover a service's identity (`daemon.name`, `daemon.pubkey_fingerprint`,
//! optionally `daemon.pubkey_b64`) so an operator can pin it on first use.
//!
//! Probes, in order:
//!
//! 1. `<base>/admin/identity` — the identity endpoint of `tesserax` services
//!    (`tesserax-http`, feature `signing`: `HttpExt::with_identity_endpoint`;
//!    tier Admin, so the client must carry an admin credential);
//! 2. `<base>/admin/mesh/status` — the path services built on the earlier
//!    toolkit expose (read-only compatibility; includes the raw public key);
//! 3. `<base>/manifest` — fingerprint only.
//!
//! All three answer the same shape:
//! `{"daemon":{"name":…,"pubkey_fingerprint":…,"pubkey_b64":…}}`. The first
//! one that answers 2xx with a complete `daemon` object wins; if none does,
//! the error of the last probe is returned.

use serde::Deserialize;

/// Discovery failure.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum DiscoverError {
    #[error("http: {0}")]
    Http(String),
    #[error("manifest missing 'daemon' object")]
    NoDaemon,
    #[error(
        "manifest 'daemon.pubkey_fingerprint' missing — daemon not running with_daemon_identity?"
    )]
    NoFingerprint,
    #[error("manifest 'daemon.name' missing")]
    NoName,
    #[error("non-2xx status: {0}")]
    Status(u16),
}

/// What discovery found.
#[derive(Debug, Clone)]
pub struct DaemonInfo {
    /// Service name.
    pub name: String,
    /// Identity fingerprint.
    pub pubkey_fingerprint: String,
    /// Raw 32-byte ed25519 pubkey, b64-url-no-pad.  Present when the
    /// discovery source includes it (mesh/status does; /manifest does
    /// only if the consumer extended the auto-built shape).
    pub pubkey_b64: Option<String>,
    /// URL that answered.
    pub source_url: String,
}

#[derive(Deserialize)]
struct DaemonField {
    name: Option<String>,
    pubkey_fingerprint: Option<String>,
    pubkey_b64: Option<String>,
}

#[derive(Deserialize)]
struct ManifestSlim {
    daemon: Option<DaemonField>,
}

/// Paths probed by [`discover_daemon`], in order.
pub const DISCOVERY_PATHS: [&str; 3] = ["/admin/identity", "/admin/mesh/status", "/manifest"];

/// Try `/admin/identity` first, then the older `/admin/mesh/status`
/// (read-only compatibility), then `/manifest` (only fingerprint).
///
/// `base_url` is `https://host[:port]` (no trailing slash, no path).
/// `/admin/identity` is an Admin route: build `http` with the operator's
/// credential as a default header, or it answers 401 and discovery falls
/// through to the older paths.
pub async fn discover_daemon(
    http: &reqwest::Client,
    base_url: &str,
) -> Result<DaemonInfo, DiscoverError> {
    let base = base_url.trim_end_matches('/');
    let mut last = DiscoverError::NoDaemon;
    for path in DISCOVERY_PATHS {
        match try_endpoint(http, &format!("{base}{path}")).await {
            Ok(info) => return Ok(info),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn try_endpoint(http: &reqwest::Client, url: &str) -> Result<DaemonInfo, DiscoverError> {
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| DiscoverError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(DiscoverError::Status(status.as_u16()));
    }
    let body: ManifestSlim = resp
        .json()
        .await
        .map_err(|e| DiscoverError::Http(format!("json: {e}")))?;
    let daemon = body.daemon.ok_or(DiscoverError::NoDaemon)?;
    let name = daemon.name.ok_or(DiscoverError::NoName)?;
    let fp = daemon
        .pubkey_fingerprint
        .ok_or(DiscoverError::NoFingerprint)?;
    Ok(DaemonInfo {
        name,
        pubkey_fingerprint: fp,
        pubkey_b64: daemon.pubkey_b64,
        source_url: url.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A one-thread HTTP/1.1 responder: 200 with a daemon object on the
    /// paths in `ok`, 404 elsewhere. Returns the base URL.
    async fn serve(ok: &'static [&'static str]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                let resp = if ok.contains(&path.as_str()) {
                    let body = format!(
                        r#"{{"daemon":{{"name":"svc","pubkey_fingerprint":"fp","pubkey_b64":"pk{}"}}}}"#,
                        path.len()
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn identity_endpoint_wins() {
        let base = serve(&["/admin/identity", "/admin/mesh/status"]).await;
        let info = discover_daemon(&client(), &base).await.unwrap();
        assert!(info.source_url.ends_with("/admin/identity"));
        assert_eq!(info.name, "svc");
        assert_eq!(info.pubkey_fingerprint, "fp");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn old_path_is_still_read() {
        let base = serve(&["/admin/mesh/status"]).await;
        let info = discover_daemon(&client(), &base).await.unwrap();
        assert!(info.source_url.ends_with("/admin/mesh/status"));
        assert!(info.pubkey_b64.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nothing_answers() {
        let base = serve(&[]).await;
        let err = discover_daemon(&client(), &base).await.unwrap_err();
        assert!(matches!(err, DiscoverError::Status(404)), "{err}");
    }
}
