//! Servers for the shell tests: a port served by `http_shell` on a
//! loopback listener, or by `local_shell` on an owner-only socket, each on
//! its own tokio runtime (the test thread stays a plain thread, as a
//! `RemoteHandle` caller must be).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tesserax::swc::Port;
use tesserax::{DoorName, KeyId, Tier};
use tesserax_auth::{AuthGate, Door, Grant, KeyHash, KeyRecord, KeyRing, Policy};
use tesserax_framework::shell::{
    HttpRemote, LinkContext, LinkKeys, LocalRemote, LocalShellOpts, RemoteHandle, ShellOpts,
    http_shell, local_shell,
};
use tokio::runtime::Runtime;

/// Key with grants on both doors.
pub const FULL_KEY: &str = "full-key-0123456789";
/// Key with a grant on the observe door only.
pub const OBSERVE_KEY: &str = "observe-key-0123456789";
/// Key with a grant on the control door only.
pub const CONTROL_KEY: &str = "control-key-0123456789";

pub const CONTROL_SECRET: &[u8] = b"control-secret-for-tests";
pub const OBSERVE_SECRET: &[u8] = b"observe-secret-for-tests";
pub const DOMAIN: &[u8] = b"tesserax-shell-test\0";

pub fn door(name: &str) -> DoorName {
    DoorName::new(name).unwrap()
}

/// Both doors admit every path, so only the door of each shell route
/// (not the path policy) separates the keys.
pub fn gate() -> AuthGate {
    let record = |id: &str, key: &str, doors: &[&str]| {
        KeyRecord::new(
            KeyId::new(id).unwrap(),
            KeyHash::of_raw(key),
            doors
                .iter()
                .map(|d| Grant::new(door(d), Tier::Authenticated))
                .collect(),
        )
    };
    let ring = KeyRing::from_records(vec![
        record("full", FULL_KEY, &["control", "observe"]),
        record("observer", OBSERVE_KEY, &["observe"]),
        record("controller", CONTROL_KEY, &["control"]),
    ])
    .unwrap();
    AuthGate::new(ring)
        .door(Door::new(door("control"), Policy::Any))
        .door(Door::new(door("observe"), Policy::Any))
}

pub fn shell_opts() -> ShellOpts {
    ShellOpts::standard()
        .unwrap()
        .keep_alive(Duration::from_millis(200))
        .feed_poll(Duration::from_millis(10))
}

pub fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Keeps a served port alive; stops it on drop.
pub struct Served {
    pub runtime: Option<Runtime>,
    pub addr: Option<SocketAddr>,
    pub endpoint: Option<PathBuf>,
    dir: Option<PathBuf>,
}

impl Drop for Served {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
        if let Some(dir) = self.dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

pub fn serve_http<P, C, V, S>(port: P) -> Served
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    let rt = runtime();
    let (router, _) = http_shell(port, gate(), shell_opts()).into_parts();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    rt.spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Served {
        runtime: Some(rt),
        addr: Some(addr),
        endpoint: None,
        dir: None,
    }
}

pub fn http_remote<C, V, S>(served: &Served, key: &str) -> RemoteHandle<C, V, S>
where
    C: Serialize + Send + 'static,
    V: DeserializeOwned + Send + 'static,
    S: DeserializeOwned + Send + Sync + 'static,
{
    RemoteHandle::http(HttpRemote::new(served.addr.unwrap()).bearer(key)).unwrap()
}

pub fn link_keys() -> LinkKeys {
    LinkKeys::new(LinkContext::new(DOMAIN, b"schema-1"))
}

pub fn server_keys() -> LinkKeys {
    link_keys()
        .control(CONTROL_SECRET.to_vec())
        .observe(OBSERVE_SECRET.to_vec())
}

fn private_dir() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tsx-shell-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&dir).unwrap();
    dir
}

pub fn serve_local<P, C, V, S>(port: P) -> Served
where
    P: Port<C, V, S> + 'static,
    C: DeserializeOwned + Send + 'static,
    V: Serialize + Clone + Send + Sync + 'static,
    S: Serialize + Send + Sync + 'static,
{
    let rt = runtime();
    let dir = private_dir();
    let endpoint = dir.join("shell.sock");
    let listener = rt
        .block_on(tesserax_transport::local::OwnerOnlyListener::bind(
            &endpoint,
        ))
        .unwrap();
    let opts = LocalShellOpts {
        feed_poll: Duration::from_millis(10),
        ..LocalShellOpts::default()
    };
    let entered = rt.enter();
    local_shell(port, listener, server_keys(), opts).unwrap();
    drop(entered);
    Served {
        runtime: Some(rt),
        addr: None,
        endpoint: Some(endpoint),
        dir: Some(dir),
    }
}

pub fn local_remote<C, V, S>(served: &Served, keys: LinkKeys) -> RemoteHandle<C, V, S>
where
    C: Serialize + Send + 'static,
    V: DeserializeOwned + Send + 'static,
    S: DeserializeOwned + Send + Sync + 'static,
{
    RemoteHandle::local(LocalRemote::new(served.endpoint.clone().unwrap(), keys)).unwrap()
}
