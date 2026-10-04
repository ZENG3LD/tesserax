# tesserax-transport

Contract header. The crate docs mirror this block.

```text
Role:      shell (link IO between processes and to the outside)
Owns:      listeners it binds (owner-only socket / pipe and its lock file, TLS accept loop) and the
           connections they accept; no routing, no domain state.
Exports:   Endpoint, TransportError; local::{OwnerOnlyListener, LocalServerStream, LocalClientStream,
           connect_local, connect_loopback}; proof::{link_proof, proofs_match, random_nonce, domain_with_label,
           LinkContext, LinkRole}; call_home::{write_announce, read_announce, Announce, CallHomeError};
           tls::{SpkiPin, compute_spki_pin, spki_of_certificate}; feature tls: tls::{serve_tls,
           load_server_config, pinned_client_config, TlsDriver, TlsError};
           feature server: IpcDriver, serve_ipc, TransportExt;
           feature egress: egress::{Webhook, WebhookRetryPolicy, WebhookError, SmtpClient, SmtpConfig, SmtpAuth,
           SmtpTls, SmtpError, SmtpExtensions, SmtpResponse, EmailMessage, build_rfc2822, Mailer, MailError,
           TelegramBot, TelegramError}.
Imports:   tesserax (ct for every HMAC, digest and secret compare; feature server: ServerBuilder, the
           listener-driver hook, lifecycle), tokio, serde, serde_json, thiserror, getrandom; unix: rustix;
           windows: windows-sys; feature server: axum, hyper, hyper-util, tower-service, tracing;
           feature tls: rustls, tokio-rustls; feature egress: reqwest, rustls, tokio-rustls, webpki-roots,
           base64, tracing.
Forbidden: any product build-stamp or protocol vocabulary (the caller passes its own as LinkContext);
           axum routing; a second constant-time compare, HMAC or SHA-256 (use tesserax::ct);
           `unsafe` outside `local/windows_pipe.rs` (crate is deny(unsafe_code), that module allows it);
           open-by-default behaviour; any product, host or consumer name.
```
