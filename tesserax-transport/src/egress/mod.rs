//! Outbound clients (feature `egress`).
//!
//! - [`Webhook`] — HTTP POST of a JSON body with exponential-backoff retry
//!   on transport errors, 5xx, 408 and 429; any other non-2xx answer is
//!   final. Redirects are not followed. With
//!   [`Webhook::with_signing_secret`] every delivery carries
//!   `X-Webhook-Timestamp` and `X-Webhook-Signature: sha256=<hex>` over
//!   `timestamp "." body`, the scheme `tesserax-http`'s `WebhookVerifier`
//!   checks.
//! - [`SmtpClient`] — hand-written ESMTP (RFC 5321) with STARTTLS (RFC 3207)
//!   or implicit TLS, AUTH PLAIN / LOGIN (RFC 4616 / 4954), behind the
//!   [`Mailer`] trait so a caller can swap in another backend.
//! - [`TelegramBot`] — the three Bot API calls a notifier needs (`getMe`,
//!   `sendMessage`, `sendPhoto`) over raw HTTPS.
//!
//! None of the clients panics on construction; each constructor that can
//! fail returns a `Result`.

mod message;
mod smtp;
mod telegram;
mod webhook;

pub use message::{EmailMessage, build_rfc2822};
pub use smtp::{
    MailError, MailFuture, Mailer, SmtpAuth, SmtpClient, SmtpConfig, SmtpError, SmtpExtensions,
    SmtpResponse, SmtpTls,
};
pub use telegram::{TelegramBot, TelegramError};
pub use webhook::{Webhook, WebhookError, WebhookRetryPolicy};

/// `User-Agent` of the HTTP clients.
pub(crate) const USER_AGENT: &str = concat!("tesserax-transport/", env!("CARGO_PKG_VERSION"));

/// Upper bound of a response body kept in an error.
pub(crate) const ERROR_BODY_LIMIT: usize = 1024;

/// Truncates `s` to at most [`ERROR_BODY_LIMIT`] bytes on a char boundary.
pub(crate) fn clip(mut s: String) -> String {
    if s.len() > ERROR_BODY_LIMIT {
        let mut cut = ERROR_BODY_LIMIT;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}
