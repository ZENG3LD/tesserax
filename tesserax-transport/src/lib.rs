//! `tesserax-transport` — link IO between the processes of a back office
//! and to the outside.
//!
//! - [`Endpoint`]: where a peer is reached. The locality rule: a peer on
//!   the same host is reached over an owner-only local socket or pipe
//!   ([`Endpoint::Local`]), anything else over HTTP / WebSocket.
//! - [`local`]: [`OwnerOnlyListener`](local::OwnerOnlyListener) and
//!   [`connect_local`](local::connect_local) — a Unix domain socket in a
//!   `0700` directory, mode `0600`, peer uid checked on both ends (Unix), or
//!   a named pipe whose DACL admits only the current user and LocalSystem
//!   (Windows); [`connect_loopback`](local::connect_loopback) refuses a
//!   non-loopback TCP address before any IO.
//! - [`proof`]: [`link_proof`](proof::link_proof), the HMAC-SHA256 both
//!   ends of a link compute over both nonces, bound to a caller-supplied
//!   [`LinkContext`](proof::LinkContext) (protocol domain + negotiated
//!   binding), so a proof of one protocol, direction, role or negotiation
//!   is worthless in another.
//! - [`call_home`]: the one-frame preface a peer that dialled out sends to
//!   name itself before the handshake.
//! - [`tls`]: [`SpkiPin`](tls::SpkiPin) always; with feature `tls` the
//!   HTTPS accept loop, certificate loading, client-certificate pins and a
//!   pinned client configuration.
//! - feature `server` (default): `IpcDriver` / `TransportExt` wire
//!   `tesserax::Transport::Ipc` (and, with `tls`, `Transport::Tls`) into a
//!   `tesserax::ServerBuilder` through the root's listener-driver hook.
//! - feature `egress`: outbound `egress::Webhook` (retry, optional
//!   signature), `egress::SmtpClient` behind `egress::Mailer`,
//!   `egress::TelegramBot`.
//!
//! # Contract
//!
//! ```text
//! Role:      shell (link IO between processes and to the outside)
//! Owns:      listeners it binds (owner-only socket / pipe and its lock file, TLS accept loop) and the
//!            connections they accept; no routing, no domain state.
//! Exports:   Endpoint, TransportError; local::{OwnerOnlyListener, LocalServerStream, LocalClientStream,
//!            connect_local, connect_loopback}; proof::{link_proof, proofs_match, random_nonce, domain_with_label,
//!            LinkContext, LinkRole}; call_home::{write_announce, read_announce, Announce, CallHomeError};
//!            tls::{SpkiPin, compute_spki_pin, spki_of_certificate}; feature tls: tls::{serve_tls,
//!            load_server_config, pinned_client_config, TlsDriver, TlsError};
//!            feature server: IpcDriver, serve_ipc, TransportExt;
//!            feature egress: egress::{Webhook, WebhookRetryPolicy, WebhookError, SmtpClient, SmtpConfig, SmtpAuth,
//!            SmtpTls, SmtpError, SmtpExtensions, SmtpResponse, EmailMessage, build_rfc2822, Mailer, MailError,
//!            TelegramBot, TelegramError}.
//! Imports:   tesserax (ct for every HMAC, digest and secret compare; feature server: ServerBuilder, the
//!            listener-driver hook, lifecycle), tokio, serde, serde_json, thiserror, getrandom; unix: rustix;
//!            windows: windows-sys; feature server: axum, hyper, hyper-util, tower-service, tracing;
//!            feature tls: rustls, tokio-rustls; feature egress: reqwest, rustls, tokio-rustls, webpki-roots,
//!            base64, tracing.
//! Forbidden: any product build-stamp or protocol vocabulary (the caller passes its own as LinkContext);
//!            axum routing; a second constant-time compare, HMAC or SHA-256 (use tesserax::ct);
//!            `unsafe` outside `local/windows_pipe.rs` (crate is deny(unsafe_code), that module allows it);
//!            open-by-default behaviour; any product, host or consumer name.
//! ```
//!
//! # Features
//!
//! - `server` (default) — `IpcDriver`, `serve_ipc`, `TransportExt::with_ipc`.
//! - `tls` — HTTPS accept loop and certificate handling; implies `server`.
//! - `egress` — webhook, SMTP and Telegram clients (reqwest, rustls).
//!
//! # Frozen wire labels
//!
//! The call-home preface keeps the JSON keys `build_stamp` and `node_id`
//! and its `u32` little-endian length prefix byte-identical, so peers
//! already deployed with that preface keep reading it.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod call_home;
mod endpoint;
mod error;
pub mod local;
pub mod proof;
pub mod tls;

#[cfg(feature = "egress")]
pub mod egress;
#[cfg(feature = "server")]
mod serve;

pub use endpoint::Endpoint;
pub use error::TransportError;

#[cfg(feature = "server")]
pub use serve::{IpcDriver, TransportExt, serve_ipc};
