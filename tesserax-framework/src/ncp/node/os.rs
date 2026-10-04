//! `node-os`: spawn / kill / supervise of the node's services as OS
//! processes. This is the only module in `ncp` that may name
//! `std::process` — the middle tier "may route, mirror, resync, persist;
//! may NOT touch an OS process", and the grep gate in
//! `tests/ncp_gates.rs` keeps it that way.
//!
//! Scope note (design §5.4): adopting already-running processes, killing
//! a stale binary, and reconciling heartbeats moves here **last and only
//! with the owner's word**. What stands here now is the generic spine —
//! spawn spec, restart policy, kill, supervise loop — written from the
//! design's written rules; those adopt and stale-binary behaviours are
//! not ported.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// How running a service process fails.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProcessError {
    /// The process could not be spawned.
    #[error("spawn {service}: {source}")]
    Spawn {
        /// The service that failed to start.
        service: String,
        /// The OS error.
        source: std::io::Error,
    },
    /// A signal / wait failed.
    #[error("kill {service}: {source}")]
    Kill {
        /// The service that could not be signalled.
        service: String,
        /// The OS error.
        source: std::io::Error,
    },
    /// The service is not running (unknown name or already dead).
    #[error("not running: {0}")]
    NotRunning(String),
}

/// How one service becomes a process.
#[derive(Clone, Debug)]
pub struct SpawnSpec {
    /// The program (path or `PATH` lookup).
    pub program: String,
    /// Arguments, in order.
    pub args: Vec<String>,
    /// Extra environment (the service's token arrives here, by env name —
    /// never in the roster file).
    pub env: BTreeMap<String, String>,
    /// Working directory; `None` inherits.
    pub dir: Option<std::path::PathBuf>,
}

impl SpawnSpec {
    /// A spec for just a program.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            dir: None,
        }
    }

    /// Adds arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Adds one environment variable.
    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(name.into(), value.into());
        self
    }

    /// Sets the working directory.
    pub fn dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }
}

/// What the supervisor does when a supervised process exits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartPolicy {
    /// Leave it dead; the exit is reported, nothing restarts.
    Never,
    /// Restart with a capped exponential backoff (100 ms doubling to
    /// 30 s), reset after a full minute of uptime.
    Backoff,
}

/// One supervised process: the spec it runs from and its state.
struct Supervised {
    service: String,
    spec: SpawnSpec,
    policy: RestartPolicy,
    child: Option<Child>,
    started_at: Instant,
    restarts: u64,
    last_exit: Option<String>,
}

/// The node's process supervisor: owns the children it spawned, reaps
/// and — per policy — restarts them. Owns nothing it did not spawn
/// (adoption of foreign processes waits for the owner's word, see the
/// module docs).
pub struct ProcessSupervisor {
    inner: Arc<Mutex<BTreeMap<String, Supervised>>>,
}

impl std::fmt::Debug for ProcessSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessSupervisor").finish_non_exhaustive()
    }
}

impl Default for ProcessSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessSupervisor {
    /// A supervisor with nothing running.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Spawns `service` from `spec` and supervises it under `policy`.
    /// Spawning an already-supervised name is an error, not a restart —
    /// restart is the supervisor's word, not the caller's.
    pub async fn spawn(
        &self,
        service: impl Into<String>,
        spec: SpawnSpec,
        policy: RestartPolicy,
    ) -> Result<(), ProcessError> {
        let service = service.into();
        let mut guard = self.inner.lock().await;
        if guard.contains_key(&service) {
            return Err(ProcessError::Spawn {
                service,
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "already supervised",
                ),
            });
        }
        let child = spawn_child(&service, &spec)?;
        guard.insert(
            service.clone(),
            Supervised {
                service: service.clone(),
                spec,
                policy,
                child: Some(child),
                started_at: Instant::now(),
                restarts: 0,
                last_exit: None,
            },
        );
        drop(guard);
        Ok(())
    }

    /// Kills and forgets a supervised process.
    pub async fn kill(&self, service: &str) -> Result<(), ProcessError> {
        let mut guard = self.inner.lock().await;
        let Some(mut entry) = guard.remove(service) else {
            return Err(ProcessError::NotRunning(service.to_owned()));
        };
        if let Some(mut child) = entry.child.take() {
            child.kill().await.map_err(|source| ProcessError::Kill {
                service: service.to_owned(),
                source,
            })?;
        }
        Ok(())
    }

    /// One supervision pass: reaps exited children, restarts per policy
    /// (capped exponential backoff, reset after a minute of uptime),
    /// returns the names of the services it restarted. Drive it on a
    /// timer; it never blocks on a live child and never holds the lock
    /// across a backoff.
    pub async fn supervise_once(&self) -> Vec<String> {
        // Pass 1, under the lock: reap; collect what wants a restart.
        let mut to_restart = Vec::new();
        {
            let mut guard = self.inner.lock().await;
            for entry in guard.values_mut() {
                let Some(child) = entry.child.as_mut() else {
                    continue;
                };
                match child.try_wait() {
                    Ok(Some(status)) => {
                        entry.last_exit = Some(status.to_string());
                        entry.child = None;
                        if entry.policy == RestartPolicy::Backoff {
                            // A full minute of uptime resets the backoff.
                            if entry.started_at.elapsed() >= Duration::from_secs(60) {
                                entry.restarts = 0;
                            }
                            to_restart.push(entry.service.clone());
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        entry.last_exit = Some(e.to_string());
                    }
                }
            }
        }
        // Pass 2, lock-free across the backoff: restart one by one.
        let mut restarted = Vec::new();
        for service in to_restart {
            let (spec, restarts) = {
                let guard = self.inner.lock().await;
                match guard.get(&service) {
                    Some(e) if e.child.is_none() => (e.spec.clone(), e.restarts),
                    _ => continue, // killed or already restarted meanwhile
                }
            };
            let shift = restarts.min(8) as u32;
            let backoff = Duration::from_millis(100)
                .saturating_mul(1u32 << shift)
                .min(Duration::from_secs(30));
            tokio::time::sleep(backoff).await;
            let mut guard = self.inner.lock().await;
            let Some(entry) = guard.get_mut(&service) else {
                continue;
            };
            if entry.child.is_some() {
                continue;
            }
            match spawn_child(&entry.service, &spec) {
                Ok(child) => {
                    entry.child = Some(child);
                    entry.started_at = Instant::now();
                    entry.restarts += 1;
                    restarted.push(service.clone());
                }
                Err(e) => {
                    entry.last_exit = Some(e.to_string());
                }
            }
        }
        restarted
    }

    /// How many services are currently supervised (alive or between
    /// restarts).
    pub async fn supervised_count(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// The last exit status of a supervised service, if it exited.
    pub async fn last_exit(&self, service: &str) -> Option<String> {
        self.inner
            .lock()
            .await
            .get(service)
            .and_then(|e| e.last_exit.clone())
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        // Children the supervisor owns die with it: start_kill does not
        // wait, the OS reaps. No waiting in Drop.
        if let Ok(mut guard) = self.inner.try_lock() {
            for entry in guard.values_mut() {
                if let Some(child) = entry.child.as_mut() {
                    let _ = child.start_kill();
                }
            }
        }
    }
}

fn spawn_child(service: &str, spec: &SpawnSpec) -> Result<Child, ProcessError> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .envs(&spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = &spec.dir {
        command.current_dir(dir);
    }
    command.spawn().map_err(|source| ProcessError::Spawn {
        service: service.to_owned(),
        source,
    })
}
