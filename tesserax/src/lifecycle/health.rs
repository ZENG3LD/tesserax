//! Detailed `/health`: dependency probes plus runtime information.
//!
//! Payload (stable JSON):
//!
//! ```json
//! {"ok": true, "service": "example", "version": "1.2.3",
//!  "started_at": "2026-01-01T00:00:00Z", "uptime_secs": 42,
//!  "dependencies": [{"name": "db", "status": "ok", "latency_ms": 2}],
//!  "background_tasks": ["sweep"]}
//! ```
//!
//! `ok` is true iff every dependency reports `"ok"`; the endpoint then
//! answers 200, otherwise 503.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;

type CheckFn = dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync;

/// Deadline of one probe.
const PROBE_DEADLINE: Duration = Duration::from_secs(2);

/// One dependency probe; runs on every `/health` request with a 2 s
/// deadline. `Err(reason)` marks the dependency unhealthy.
#[derive(Clone)]
pub struct DependencyCheck {
    name: Arc<str>,
    check: Arc<CheckFn>,
}

impl DependencyCheck {
    /// Wraps an async probe.
    pub fn new<F, Fut>(name: impl Into<String>, f: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let name: String = name.into();
        Self {
            name: Arc::from(name.as_str()),
            check: Arc::new(move || Box::pin(f())),
        }
    }

    /// Probe name.
    pub fn name(&self) -> &str {
        &self.name
    }

    async fn probe(name: Arc<str>, check: Arc<CheckFn>) -> DependencyStatus {
        let start = Instant::now();
        let res = tokio::time::timeout(PROBE_DEADLINE, check()).await;
        let latency_ms = Some(start.elapsed().as_millis() as u64);
        let (status, error) = match res {
            Ok(Ok(())) => ("ok", None),
            Ok(Err(reason)) => ("error", Some(reason)),
            Err(_) => ("timeout", Some("check exceeded 2s deadline".to_owned())),
        };
        DependencyStatus {
            name: name.to_string(),
            status: status.to_owned(),
            latency_ms,
            error,
        }
    }
}

impl std::fmt::Debug for DependencyCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DependencyCheck")
            .field("name", &self.name)
            .finish()
    }
}

/// Result of one probe.
#[derive(Clone, Debug, Serialize)]
pub struct DependencyStatus {
    /// Probe name.
    pub name: String,
    /// `"ok"`, `"error"` or `"timeout"`.
    pub status: String,
    /// How long the probe took.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Failure reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// State of the detailed `/health` handler; cheap to clone.
#[derive(Clone, Debug)]
pub struct HealthState {
    service: Arc<str>,
    version: Option<Arc<str>>,
    started_at: SystemTime,
    started_at_instant: Instant,
    checks: Arc<Vec<DependencyCheck>>,
    background_tasks: Arc<Vec<String>>,
}

impl HealthState {
    /// New state; the start time is now.
    pub fn new(
        service: impl Into<String>,
        version: Option<String>,
        checks: Vec<DependencyCheck>,
        background_tasks: Vec<String>,
    ) -> Self {
        let service: String = service.into();
        Self {
            service: Arc::from(service.as_str()),
            version: version.map(|v| Arc::from(v.as_str())),
            started_at: SystemTime::now(),
            started_at_instant: Instant::now(),
            checks: Arc::new(checks),
            background_tasks: Arc::new(background_tasks),
        }
    }

    /// Runs every probe concurrently and assembles the report.
    pub async fn report(&self) -> HealthReport {
        let handles: Vec<_> = self
            .checks
            .iter()
            .map(|c| {
                (
                    Arc::clone(&c.name),
                    tokio::spawn(DependencyCheck::probe(
                        Arc::clone(&c.name),
                        Arc::clone(&c.check),
                    )),
                )
            })
            .collect();
        let mut dependencies = Vec::with_capacity(handles.len());
        for (name, handle) in handles {
            dependencies.push(handle.await.unwrap_or_else(|_| DependencyStatus {
                name: name.to_string(),
                status: "error".to_owned(),
                latency_ms: None,
                error: Some("check panicked".to_owned()),
            }));
        }
        HealthReport {
            ok: dependencies.iter().all(|d| d.status == "ok"),
            service: self.service.to_string(),
            version: self.version.as_deref().map(str::to_owned),
            started_at: iso8601(self.started_at),
            uptime_secs: self.started_at_instant.elapsed().as_secs(),
            dependencies,
            background_tasks: self.background_tasks.as_ref().clone(),
        }
    }
}

/// JSON body of the detailed `/health`.
#[derive(Clone, Debug, Serialize)]
pub struct HealthReport {
    /// True iff every dependency is `"ok"`.
    pub ok: bool,
    /// Server name.
    pub service: String,
    /// Server version, if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Start time, `YYYY-MM-DDTHH:MM:SSZ`.
    pub started_at: String,
    /// Seconds since start.
    pub uptime_secs: u64,
    /// One entry per probe, in registration order.
    pub dependencies: Vec<DependencyStatus>,
    /// Names of registered background tasks.
    pub background_tasks: Vec<String>,
}

/// UTC `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days).
fn iso8601(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe as i64 + era * 400 + i64::from(m <= 2);
    let sod = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_state_reports_ok() {
        let r = HealthState::new("svc", Some("0.1.0".into()), vec![], vec![])
            .report()
            .await;
        assert!(r.ok);
        assert_eq!(r.service, "svc");
        assert_eq!(r.version.as_deref(), Some("0.1.0"));
        assert!(r.dependencies.is_empty());
    }

    #[tokio::test]
    async fn failing_check_flips_overall() {
        let st = HealthState::new(
            "svc",
            None,
            vec![
                DependencyCheck::new("db", || async { Ok(()) }),
                DependencyCheck::new("upstream", || async { Err("connection refused".into()) }),
            ],
            vec![],
        );
        let r = st.report().await;
        assert!(!r.ok);
        assert_eq!(r.dependencies[0].status, "ok");
        assert_eq!(r.dependencies[1].status, "error");
        assert_eq!(
            r.dependencies[1].error.as_deref(),
            Some("connection refused")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_check_times_out() {
        let st = HealthState::new(
            "svc",
            None,
            vec![DependencyCheck::new("hangs", || async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            })],
            vec![],
        );
        let r = st.report().await;
        assert!(!r.ok);
        assert_eq!(r.dependencies[0].status, "timeout");
    }

    #[test]
    fn iso8601_known_dates() {
        assert_eq!(iso8601(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_779_796_800);
        assert_eq!(iso8601(t), "2026-05-26T12:00:00Z");
        let leap = SystemTime::UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(iso8601(leap), "2000-02-29T00:00:00Z");
    }
}
