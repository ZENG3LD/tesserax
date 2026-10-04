//! Process plugin host.
//!
//! A plugin here is an OS process the host starts, supervises, and stops.
//! Its capability token is passed only through the environment variable
//! named by the manifest (`token_env`). That name is the caller's; this
//! module has no built-in variable name.
//!
//! In-process shared libraries and WebAssembly are not hosted. A read of
//! the prior engine found both kinds written, and the inventory still
//! marks their behaviour unverified. Nothing in this crate proves them,
//! so they stay out until a check does.
//!
//! The child does not inherit the host process environment. `PATH` is
//! copied so a program name can be resolved; every other variable is one
//! the manifest lists, plus the capability token in `token_env` (the
//! token wins if the manifest also lists that name).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;

use thiserror::Error;
use zeroize::Zeroizing;

/// Why the plugin host refused or failed a call.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PluginError {
    /// The manifest cannot be started as given.
    #[error("invalid plugin manifest: {0}")]
    Config(&'static str),
    /// A plugin with this name is already started.
    #[error("plugin already started: {0}")]
    AlreadyStarted(String),
    /// No plugin with this name is in the host.
    #[error("plugin not running: {0}")]
    NotRunning(String),
    /// The operating system refused the spawn.
    #[error("spawn {name}: {source}")]
    Spawn {
        /// Plugin name.
        name: String,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
}

/// What the host does after a plugin process exits.
///
/// `max_restarts` counts restarts after the original start, not the
/// original start itself. Zero means the process is left dead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartPolicy {
    /// Leave it dead. The exit is recorded and nothing is spawned again.
    Never,
    /// Restart only when the exit status is a failure.
    OnFailure {
        /// Restarts allowed after the original start.
        max_restarts: u32,
    },
    /// Restart on any exit.
    Always {
        /// Restarts allowed after the original start.
        max_restarts: u32,
    },
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self::Never
    }
}

/// Declaration of one process plugin.
///
/// The capability token is not a field. The caller hands it to
/// [`PluginHost::start`] so a manifest can be logged or stored without
/// carrying the secret.
#[derive(Clone, Debug)]
pub struct PluginManifest {
    /// Host-local name. Unique among plugins this host has started.
    pub name: String,
    /// Program path, or a name resolved through `PATH`.
    pub program: String,
    /// Arguments, in order.
    pub args: Vec<String>,
    /// Extra environment. Does not include the capability token.
    pub env: BTreeMap<String, String>,
    /// Working directory. `None` inherits the host's.
    pub dir: Option<PathBuf>,
    /// What to do when the process exits.
    pub restart: RestartPolicy,
    /// Environment variable that receives the capability token.
    pub token_env: String,
}

impl PluginManifest {
    /// A manifest with no arguments, no extra environment, and
    /// [`RestartPolicy::Never`].
    pub fn new(
        name: impl Into<String>,
        program: impl Into<String>,
        token_env: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            dir: None,
            restart: RestartPolicy::Never,
            token_env: token_env.into(),
        }
    }

    /// Replaces the argument list.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Adds one non-secret environment variable.
    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(name.into(), value.into());
        self
    }

    /// Sets the working directory.
    pub fn dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }

    /// Sets the restart policy.
    pub fn restart(mut self, restart: RestartPolicy) -> Self {
        self.restart = restart;
        self
    }
}

struct Slot {
    manifest: PluginManifest,
    token: Zeroizing<String>,
    child: Option<Child>,
    restarts: u32,
    stop_requested: bool,
    last_exit: Option<ExitStatus>,
}

/// Starts process plugins, passes each one a capability token through
/// the manifest's environment name, and restarts them per policy.
///
/// [`Self::supervise_once`] does not sleep. The caller decides how often
/// to reap and restart.
pub struct PluginHost {
    slots: Mutex<BTreeMap<String, Slot>>,
}

impl std::fmt::Debug for PluginHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginHost").finish_non_exhaustive()
    }
}

impl Default for PluginHost {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginHost {
    /// A host with nothing running.
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(BTreeMap::new()),
        }
    }

    /// Spawns `manifest` and places `token` in the environment variable
    /// `manifest.token_env`. The rest of the host environment is not
    /// passed through, apart from `PATH`.
    pub fn start(
        &self,
        manifest: PluginManifest,
        token: impl Into<String>,
    ) -> Result<(), PluginError> {
        validate(&manifest)?;
        let name = manifest.name.clone();
        let token = Zeroizing::new(token.into());
        let child = spawn_child(&manifest, &token).map_err(|source| PluginError::Spawn {
            name: name.clone(),
            source,
        })?;
        let mut slots = lock(&self.slots);
        if slots.contains_key(&name) {
            // Dropping `child` does not kill it. Kill before returning.
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(PluginError::AlreadyStarted(name));
        }
        slots.insert(
            name,
            Slot {
                manifest,
                token,
                child: Some(child),
                restarts: 0,
                stop_requested: false,
                last_exit: None,
            },
        );
        Ok(())
    }

    /// Kills the named plugin and forgets it. A later exit is not a
    /// restart. The capability token is dropped with the slot.
    pub fn stop(&self, name: &str) -> Result<(), PluginError> {
        let mut slots = lock(&self.slots);
        let Some(mut slot) = slots.remove(name) else {
            return Err(PluginError::NotRunning(name.to_owned()));
        };
        slot.stop_requested = true;
        reap_kill(&mut slot);
        Ok(())
    }

    /// Reaps exited children and restarts those whose policy still
    /// allows it. Returns the names that were spawned again. Never
    /// blocks on a live child.
    pub fn supervise_once(&self) -> Vec<String> {
        let mut slots = lock(&self.slots);
        let mut restarted = Vec::new();
        for (name, slot) in slots.iter_mut() {
            let Some(child) = slot.child.as_mut() else {
                continue;
            };
            match child.try_wait() {
                Ok(Some(status)) => {
                    slot.last_exit = Some(status);
                    slot.child = None;
                    if slot.stop_requested || !should_restart(slot, status) {
                        continue;
                    }
                    match spawn_child(&slot.manifest, &slot.token) {
                        Ok(child) => {
                            slot.child = Some(child);
                            slot.restarts = slot.restarts.saturating_add(1);
                            restarted.push(name.clone());
                        }
                        Err(_) => {}
                    }
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }
        restarted
    }

    /// Whether the named plugin has a live child. A plugin between
    /// restarts is still known ([`Self::contains`]) but not alive.
    pub fn is_alive(&self, name: &str) -> bool {
        let mut slots = lock(&self.slots);
        let Some(slot) = slots.get_mut(name) else {
            return false;
        };
        let Some(child) = slot.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                slot.last_exit = Some(status);
                slot.child = None;
                false
            }
            Err(_) => false,
        }
    }

    /// Whether the host still tracks this name (alive or exited).
    pub fn contains(&self, name: &str) -> bool {
        lock(&self.slots).contains_key(name)
    }

    /// How many times this plugin has been restarted after the original
    /// start. `None` if the name is unknown.
    pub fn restarts(&self, name: &str) -> Option<u32> {
        lock(&self.slots).get(name).map(|s| s.restarts)
    }

    /// Names currently tracked, in order.
    pub fn names(&self) -> Vec<String> {
        lock(&self.slots).keys().cloned().collect()
    }
}

impl Drop for PluginHost {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.slots.lock() {
            for slot in slots.values_mut() {
                slot.stop_requested = true;
                if let Some(child) = slot.child.as_mut() {
                    let _ = child.kill();
                }
            }
        }
    }
}

fn lock(
    slots: &Mutex<BTreeMap<String, Slot>>,
) -> std::sync::MutexGuard<'_, BTreeMap<String, Slot>> {
    slots.lock().unwrap_or_else(|e| e.into_inner())
}

fn validate(manifest: &PluginManifest) -> Result<(), PluginError> {
    if manifest.name.is_empty() {
        return Err(PluginError::Config("name is empty"));
    }
    if manifest.program.is_empty() {
        return Err(PluginError::Config("program is empty"));
    }
    if !valid_env_name(&manifest.token_env) {
        return Err(PluginError::Config(
            "token_env must be a non-empty environment variable name",
        ));
    }
    for key in manifest.env.keys() {
        if !valid_env_name(key) {
            return Err(PluginError::Config(
                "env key must be an environment variable name",
            ));
        }
    }
    Ok(())
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn should_restart(slot: &Slot, status: ExitStatus) -> bool {
    match slot.manifest.restart {
        RestartPolicy::Never => false,
        RestartPolicy::OnFailure { max_restarts } => {
            !status.success() && slot.restarts < max_restarts
        }
        RestartPolicy::Always { max_restarts } => slot.restarts < max_restarts,
    }
}

fn spawn_child(manifest: &PluginManifest, token: &str) -> std::io::Result<Child> {
    let mut command = Command::new(&manifest.program);
    command
        .args(&manifest.args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = &manifest.dir {
        command.current_dir(dir);
    }
    if let Ok(path) = std::env::var("PATH") {
        command.env("PATH", path);
    }
    for (key, value) in &manifest.env {
        if key == &manifest.token_env {
            continue;
        }
        command.env(key, value);
    }
    command.env(&manifest.token_env, token);
    command.spawn()
}

fn reap_kill(slot: &mut Slot) {
    if let Some(mut child) = slot.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn shell() -> &'static str {
        if PathBuf::from("/bin/sh").exists() {
            "/bin/sh"
        } else {
            "sh"
        }
    }

    fn scratch() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tx-plugin-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wait_until(mut pred: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if pred() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out");
    }

    #[test]
    fn token_arrives_only_under_the_configured_name() {
        let dir = scratch();
        let out = dir.join("env.txt");
        let out_s = out.display().to_string();
        let host = PluginHost::new();
        let manifest = PluginManifest::new("probe", shell(), "TX_CAP_TOKEN")
            .args(["-c", &format!("env > {out_s}")])
            .env("TX_PLAIN", "visible");
        let token = "cap-token-value";
        host.start(manifest, token).unwrap();
        wait_until(|| out.exists());
        // Let the writer finish.
        thread::sleep(Duration::from_millis(50));
        let text = fs::read_to_string(&out).unwrap();
        let hits: Vec<_> = text.lines().filter(|l| l.contains(token)).collect();
        assert_eq!(hits, vec![format!("TX_CAP_TOKEN={token}")]);
        assert!(text.lines().any(|l| l == "TX_PLAIN=visible"));
        // The test process carries this variable; the child must not.
        assert!(!text.contains("CARGO_MANIFEST_DIR"));
        let _ = host.stop("probe");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn on_failure_restarts_until_the_cap_and_never_restarts_success() {
        let dir = scratch();
        let count = dir.join("n");
        let count_s = count.display().to_string();
        let script = format!(
            "n=0; if [ -f {count_s} ]; then n=$(cat {count_s}); fi; n=$((n+1)); printf %s \"$n\" > {count_s}; exit 1"
        );
        let host = PluginHost::new();
        host.start(
            PluginManifest::new("failing", shell(), "TX_CAP_TOKEN")
                .args(["-c", &script])
                .restart(RestartPolicy::OnFailure { max_restarts: 2 }),
            "t",
        )
        .unwrap();
        wait_until(|| {
            host.supervise_once();
            fs::read_to_string(&count).ok().as_deref() == Some("3")
        });
        // Cap is 2 restarts: one more supervise pass must not make a fourth run.
        thread::sleep(Duration::from_millis(80));
        host.supervise_once();
        thread::sleep(Duration::from_millis(80));
        host.supervise_once();
        assert_eq!(fs::read_to_string(&count).unwrap(), "3");
        assert_eq!(host.restarts("failing"), Some(2));

        let ok_count = dir.join("ok");
        let ok_s = ok_count.display().to_string();
        let ok_script = format!("printf %s 1 > {ok_s}; exit 0");
        host.start(
            PluginManifest::new("clean", shell(), "TX_CAP_TOKEN")
                .args(["-c", &ok_script])
                .restart(RestartPolicy::OnFailure { max_restarts: 5 }),
            "t",
        )
        .unwrap();
        wait_until(|| ok_count.exists());
        thread::sleep(Duration::from_millis(50));
        host.supervise_once();
        thread::sleep(Duration::from_millis(50));
        host.supervise_once();
        assert_eq!(fs::read_to_string(&ok_count).unwrap(), "1");
        assert_eq!(host.restarts("clean"), Some(0));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn never_does_not_restart_and_always_restarts_a_clean_exit() {
        let dir = scratch();
        let never_p = dir.join("never");
        let never_s = never_p.display().to_string();
        let always_p = dir.join("always");
        let always_s = always_p.display().to_string();
        let host = PluginHost::new();
        host.start(
            PluginManifest::new("once", shell(), "TX_CAP_TOKEN")
                .args(["-c", &format!("printf %s 1 > {never_s}; exit 1")])
                .restart(RestartPolicy::Never),
            "t",
        )
        .unwrap();
        host.start(
            PluginManifest::new("loop", shell(), "TX_CAP_TOKEN")
                .args([
                    "-c",
                    &format!(
                        "n=0; if [ -f {always_s} ]; then n=$(cat {always_s}); fi; n=$((n+1)); printf %s \"$n\" > {always_s}; exit 0"
                    ),
                ])
                .restart(RestartPolicy::Always { max_restarts: 1 }),
            "t",
        )
        .unwrap();
        wait_until(|| {
            host.supervise_once();
            fs::read_to_string(&always_p).ok().as_deref() == Some("2")
        });
        thread::sleep(Duration::from_millis(80));
        host.supervise_once();
        assert_eq!(fs::read_to_string(&never_p).unwrap(), "1");
        assert_eq!(host.restarts("once"), Some(0));
        assert_eq!(fs::read_to_string(&always_p).unwrap(), "2");
        assert_eq!(host.restarts("loop"), Some(1));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_manifest_and_duplicate_name_are_refused() {
        let host = PluginHost::new();
        let err = host
            .start(PluginManifest::new("a", shell(), ""), "t")
            .unwrap_err();
        assert!(matches!(err, PluginError::Config(_)));
        let err = host
            .start(PluginManifest::new("a", shell(), "1TOKEN"), "t")
            .unwrap_err();
        assert!(matches!(err, PluginError::Config(_)));
        host.start(
            PluginManifest::new("sleep", shell(), "TX_CAP_TOKEN").args(["-c", "sleep 30"]),
            "t",
        )
        .unwrap();
        let err = host
            .start(
                PluginManifest::new("sleep", shell(), "TX_CAP_TOKEN").args(["-c", "sleep 30"]),
                "t",
            )
            .unwrap_err();
        assert!(matches!(err, PluginError::AlreadyStarted(_)));
        assert!(matches!(
            host.stop("missing").unwrap_err(),
            PluginError::NotRunning(_)
        ));
        host.stop("sleep").unwrap();
        assert!(!host.contains("sleep"));
    }
}
