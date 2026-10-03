//! Prometheus request metrics (feature `metrics`).
//!
//! [`metrics_mw`] records `http_requests_total{method,path,status}` and
//! `http_request_duration_seconds{method,path}` through the `metrics`
//! facade, labelling by the matched route template (never the raw path,
//! so parameters do not explode the label set; unmatched requests are
//! labelled `unmatched`). [`PrometheusState`] renders the text exposition
//! for a scrape endpoint.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle, PrometheusRecorder};

use crate::error::HttpError;

/// Renders the installed recorder. Cheap to clone.
#[derive(Clone)]
pub struct PrometheusState {
    handle: Arc<PrometheusHandle>,
}

impl std::fmt::Debug for PrometheusState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrometheusState").finish_non_exhaustive()
    }
}

impl PrometheusState {
    /// Installs a Prometheus recorder as the process-global `metrics`
    /// recorder. Fails if one is already installed.
    pub fn install() -> Result<Self, HttpError> {
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .map_err(|e| HttpError::Config(format!("metrics recorder: {e}")))?;
        Ok(Self::from_handle(handle))
    }

    /// A recorder that is not installed (tests, fan-out recorders), and
    /// the state rendering it.
    pub fn unattached() -> (PrometheusRecorder, Self) {
        let rec = PrometheusBuilder::new().build_recorder();
        let st = Self::from_handle(rec.handle());
        (rec, st)
    }

    /// Wraps a handle obtained elsewhere.
    pub fn from_handle(handle: PrometheusHandle) -> Self {
        Self {
            handle: Arc::new(handle),
        }
    }

    /// Text exposition format.
    pub fn render(&self) -> String {
        self.handle.render()
    }
}

/// The middleware (`from_fn(metrics_mw)`).
pub async fn metrics_mw(req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_owned();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let start = Instant::now();
    let resp = next.run(req).await;
    let secs = start.elapsed().as_secs_f64();
    let status = resp.status().as_u16().to_string();
    metrics::counter!("http_requests_total", "method" => method.clone(), "path" => path.clone(), "status" => status)
        .increment(1);
    metrics::histogram!("http_request_duration_seconds", "method" => method, "path" => path)
        .record(secs);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_local_recorder() {
        let (rec, st) = PrometheusState::unattached();
        metrics::with_local_recorder(&rec, || {
            metrics::counter!("http_requests_total", "method" => "GET", "path" => "/x", "status" => "200")
                .increment(2);
        });
        let out = st.render();
        assert!(out.contains("http_requests_total"), "{out}");
        assert!(out.contains("path=\"/x\""), "{out}");
    }
}
