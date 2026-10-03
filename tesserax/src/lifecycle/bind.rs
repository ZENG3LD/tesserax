//! [`bind_with_retry`] — `TcpListener::bind` with exponential backoff.
//!
//! A restarted process can find its previous socket still in TIME_WAIT for
//! a while; a few retries with backoff usually win.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tracing::warn;

/// Retry schedule of [`bind_with_retry`].
#[derive(Clone, Debug)]
pub struct BindRetryPolicy {
    /// Total attempts (at least one is always made).
    pub attempts: u32,
    /// Delay after the first failure.
    pub initial_delay: Duration,
    /// Multiplier between consecutive delays; 1.0 keeps them constant.
    pub backoff_factor: f64,
    /// Upper bound of a delay.
    pub max_delay: Duration,
}

impl Default for BindRetryPolicy {
    /// 5 attempts, 200 ms first delay, doubling, at most 5 s.
    fn default() -> Self {
        Self {
            attempts: 5,
            initial_delay: Duration::from_millis(200),
            backoff_factor: 2.0,
            max_delay: Duration::from_secs(5),
        }
    }
}

/// Final bind failure.
#[derive(Debug, thiserror::Error)]
#[error("bind failed on {addr} after {attempts} attempts: {source}")]
pub struct BindError {
    /// Address that could not be bound.
    pub addr: SocketAddr,
    /// Attempts made.
    pub attempts: u32,
    /// Last OS error.
    #[source]
    pub source: std::io::Error,
}

/// Binds `addr`, retrying per `policy`.
pub async fn bind_with_retry(
    addr: SocketAddr,
    policy: &BindRetryPolicy,
) -> Result<TcpListener, BindError> {
    let attempts = policy.attempts.max(1);
    let mut delay = policy.initial_delay;
    let mut attempt = 1;
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => return Ok(listener),
            Err(source) if attempt >= attempts => {
                return Err(BindError {
                    addr,
                    attempts,
                    source,
                });
            }
            Err(e) => {
                warn!(%addr, attempt, "bind failed: {e}; retrying in {delay:?}");
                tokio::time::sleep(delay).await;
                delay = delay.mul_f64(policy.backoff_factor).min(policy.max_delay);
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn binds_on_first_try() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let listener = bind_with_retry(addr, &BindRetryPolicy::default())
            .await
            .unwrap();
        let bound = listener.local_addr().unwrap();
        assert_eq!(bound.ip(), addr.ip());
        assert_ne!(bound.port(), 0);
    }

    #[tokio::test]
    async fn fails_after_attempts_when_port_is_taken() {
        let holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken = holder.local_addr().unwrap();
        let policy = BindRetryPolicy {
            attempts: 2,
            initial_delay: Duration::from_millis(10),
            backoff_factor: 1.0,
            max_delay: Duration::from_millis(10),
        };
        let err = bind_with_retry(taken, &policy).await.unwrap_err();
        assert_eq!(err.attempts, 2);
        assert_eq!(err.addr, taken);
    }
}
