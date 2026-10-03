//! [`Webhook`]: outbound JSON POST with retry and an optional signature.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tesserax::ct::hmac_sha256;

use super::{USER_AGENT, clip};

/// Signature header (same name `tesserax-http`'s verifier reads).
pub const WEBHOOK_SIGNATURE: &str = "x-webhook-signature";
/// Timestamp header.
pub const WEBHOOK_TIMESTAMP: &str = "x-webhook-timestamp";

/// Why a delivery failed.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// The HTTP client could not be built.
    #[error("http: {0}")]
    Http(#[source] reqwest::Error),
    /// Every attempt failed at the transport level (the URL is never part
    /// of the message).
    #[error("retries exhausted: last error: {0}")]
    Exhausted(String),
    /// Every attempt got a retryable status (5xx, 408, 429); the last one.
    #[error("server error {status}: {body}")]
    ServerError {
        /// Last status.
        status: u16,
        /// Start of its body.
        body: String,
    },
    /// A final non-2xx answer (4xx other than 408 / 429, or a redirect,
    /// which is never followed).
    #[error("rejected {status}: {body}")]
    Rejected {
        /// Status.
        status: u16,
        /// Start of its body.
        body: String,
    },
}

/// Retry schedule.
#[derive(Debug, Clone)]
pub struct WebhookRetryPolicy {
    /// Total attempts (at least one is made).
    pub attempts: u32,
    /// Delay after the first failure.
    pub initial_delay: Duration,
    /// Multiplier between delays.
    pub backoff_factor: f64,
    /// Upper bound of a delay.
    pub max_delay: Duration,
}

impl Default for WebhookRetryPolicy {
    /// 3 attempts, 500 ms first delay, doubling, at most 10 s.
    fn default() -> Self {
        Self {
            attempts: 3,
            initial_delay: Duration::from_millis(500),
            backoff_factor: 2.0,
            max_delay: Duration::from_secs(10),
        }
    }
}

/// One webhook target.
pub struct Webhook {
    client: reqwest::Client,
    url: String,
    policy: WebhookRetryPolicy,
    secret: Option<Vec<u8>>,
}

impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook")
            .field("url", &self.url)
            .field("policy", &self.policy)
            .field("signed", &self.secret.is_some())
            .finish()
    }
}

impl Webhook {
    /// Target `url`, default retry policy, 15 s per attempt, no redirects.
    pub fn new(url: impl Into<String>) -> Result<Self, WebhookError> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(WebhookError::Http)?;
        Ok(Self {
            client,
            url: url.into(),
            policy: WebhookRetryPolicy::default(),
            secret: None,
        })
    }

    /// Replaces the retry policy.
    pub fn with_policy(mut self, p: WebhookRetryPolicy) -> Self {
        self.policy = p;
        self
    }

    /// Signs every delivery: `X-Webhook-Timestamp: <unix seconds>` and
    /// `X-Webhook-Signature: sha256=<hex HMAC-SHA256(secret, ts "." body)>`,
    /// recomputed per attempt.
    pub fn with_signing_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    /// POSTs `body` as JSON. Returns on the first 2xx, on the first final
    /// non-2xx, or when the attempts are used up.
    pub async fn post_json<T: serde::Serialize + ?Sized>(
        &self,
        body: &T,
    ) -> Result<(), WebhookError> {
        let payload = serde_json::to_vec(body)
            .map_err(|e| WebhookError::Exhausted(format!("serialize: {e}")))?;
        let attempts = self.policy.attempts.max(1);
        let mut delay = self.policy.initial_delay;
        for attempt in 1..=attempts {
            let mut req = self
                .client
                .post(&self.url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(payload.clone());
            if let Some(secret) = &self.secret {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    .to_string();
                req = req
                    .header(WEBHOOK_TIMESTAMP, &ts)
                    .header(WEBHOOK_SIGNATURE, signature(secret, &ts, &payload));
            }
            let last = attempt == attempts;
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(());
                    }
                    let code = status.as_u16();
                    let text = clip(resp.text().await.unwrap_or_default());
                    let retryable = status.is_server_error() || code == 408 || code == 429;
                    if !retryable {
                        return Err(WebhookError::Rejected {
                            status: code,
                            body: text,
                        });
                    }
                    if last {
                        return Err(WebhookError::ServerError {
                            status: code,
                            body: text,
                        });
                    }
                    tracing::debug!(attempt, status = code, "webhook attempt failed; retrying");
                }
                Err(e) => {
                    // Webhook URLs often embed a secret; never report them.
                    let e = e.without_url();
                    if last {
                        return Err(WebhookError::Exhausted(e.to_string()));
                    }
                    tracing::debug!(attempt, "webhook attempt failed: {e}; retrying");
                }
            }
            tokio::time::sleep(delay).await;
            delay = delay
                .mul_f64(self.policy.backoff_factor)
                .min(self.policy.max_delay);
        }
        Err(WebhookError::Exhausted("no attempt was made".into()))
    }
}

/// `sha256=<hex>` of `HMAC-SHA256(secret, ts "." body)`.
fn signature(secret: &[u8], ts: &str, body: &[u8]) -> String {
    let mut msg = Vec::with_capacity(ts.len() + 1 + body.len());
    msg.extend_from_slice(ts.as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(body);
    let mac = hmac_sha256(secret, &msg);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256=");
    for b in mac {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_three_attempts() {
        let p = WebhookRetryPolicy::default();
        assert_eq!(p.attempts, 3);
        assert_eq!(p.initial_delay, Duration::from_millis(500));
    }

    #[test]
    fn webhook_constructs_and_hides_the_secret() {
        let w = Webhook::new("http://example.com/hook")
            .unwrap()
            .with_signing_secret(b"topsecret".to_vec());
        let s = format!("{w:?}");
        assert!(s.contains("signed: true"));
        assert!(!s.contains("topsecret"));
    }

    #[test]
    fn signature_is_the_timestamped_hmac() {
        let sig = signature(b"k", "1700000000", b"{}");
        let mac = hmac_sha256(b"k", b"1700000000.{}");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(sig, format!("sha256={hex}"));
    }
}
