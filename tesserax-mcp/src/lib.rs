//! `tesserax-mcp` — an MCP (Model Context Protocol) server: JSON-RPC 2.0
//! over HTTP, mounted on a `tesserax` server through [`McpExt`].
//!
//! # Wire contract
//!
//! JSON-RPC 2.0 over `POST <path>` (default `/mcp`): a single request
//! object or a batch array. A request with no `id` is a *notification* —
//! it gets no response at all; a batch that is entirely notifications
//! answers `204 No Content`, same as a single notification would. `DELETE
//! <path>` always answers `204` — this server is stateless (`initialize`
//! records nothing), so there is nothing a session-end could tear down.
//! `initialize` echoes the client's own `protocolVersion` when it is one of
//! [`SUPPORTED_PROTOCOL_VERSIONS`], else falls back to
//! [`DEFAULT_PROTOCOL_VERSION`]. `ping` answers `{}`. Errors: malformed
//! JSON is `-32700`, an unknown method is `-32601`, a malformed `tools/call`
//! (missing `name`, unknown tool) or an empty batch is `-32602`. A tool that
//! ran and refused is NOT a JSON-RPC error — it is a normal result with
//! `isError: true` (the MCP spec's own distinction between "could not be
//! invoked" and "ran and reported failure").
//!
//! # Output budget
//!
//! - A tool result is `{"content":[{"type":"text","text": ..}],"isError":
//!   bool}` — a [`ToolBody::Json`] body serialises compactly (never
//!   pretty-printed) into `text`; there is no `structuredContent` duplicate,
//!   so a result never doubles itself in the calling agent's context.
//! - A result is capped at [`McpServer::max_result_bytes`] (default
//!   [`DEFAULT_MAX_RESULT_BYTES`]); over the cap, `text` is cut on a UTF-8
//!   char boundary and ends with one line naming how many bytes were cut
//!   (`…[cut N bytes; narrow the request]`). A handler can still return
//!   less on its own.
//! - `initialize` sends no `instructions` unless [`McpServer::instructions`]
//!   was called, and that builder refuses anything over
//!   [`MAX_INSTRUCTIONS_BYTES`] outright (panics — an author-time config
//!   mistake, not a runtime condition).
//! - [`McpServer::check_budget`] serialises `tools/list` compactly and names
//!   every offender ([`BudgetOffender`]) against a [`Budget`] —
//!   [`Budget::LEAN`] is a conservative profile: at most 8 tools,
//!   `tools/list` at most 8 KB compact, no single tool over 1.5 KB,
//!   `instructions` at most 300 B. The one-line test a server adds:
//!
//! ```
//! use tesserax_mcp::{Budget, McpServer, Tool, ToolOutcome};
//! use serde_json::json;
//!
//! let server = McpServer::<()>::new("example", "0.1.0").tool(
//!     Tool::new("ping_tool", "Answers pong.", json!({"type": "object", "properties": {}})),
//!     |_state, _ctx, _args| async { ToolOutcome::ok(json!({"pong": true})) },
//! );
//! assert!(server.check_budget(Budget::LEAN).is_ok());
//! ```
//!
//! # Mounting and auth
//!
//! [`McpServer::into_doc_router`] records `POST` and `DELETE` at the
//! server's path in a `tesserax_http::DocRouter`, described and tiered
//! (default `Authenticated`; [`McpServer::tier`], [`McpServer::scope`]).
//! [`McpExt::with_mcp`] puts them in a `ServerBuilder`'s route table, so
//! the `tesserax-auth` gate refuses an unadmitted caller before any
//! JSON-RPC is parsed (no tool runs), and a tool sees the admitted caller
//! as [`CallContext::principal`] (`None` on a `Public` server):
//!
//! ```no_run
//! use tesserax::{ServerBuilder, Tier};
//! use tesserax_mcp::{CallContext, McpExt, McpServer, Tool, ToolOutcome};
//! use serde_json::{Value, json};
//!
//! # async fn run() {
//! let mcp = McpServer::<()>::new("example", "0.1.0").tier(Tier::Authenticated).tool(
//!     Tool::new("whoami", "Names the caller.", json!({"type": "object", "properties": {}})),
//!     |_state: (), ctx: CallContext, _args: Value| async move {
//!         let key = ctx.principal.map(|p| p.key_id.to_string());
//!         ToolOutcome::ok(json!({ "key_id": key }))
//!     },
//! );
//! let server = ServerBuilder::new("svc").with_mcp(mcp, ()) /* .with_auth(gate) */ .build().await;
//! # let _ = server;
//! # }
//! ```
//!
//! [`McpServer::into_router`] returns a plain `axum::Router<S>` for a host
//! that guards and mounts it itself; [`McpServer::route_docs`] returns the
//! same two `Endpoint`s the doc router records.
//!
//! One HTTP request is one gate decision: every call of a JSON-RPC batch
//! runs as the same principal, and per-request middleware (audit, rate
//! limits) sees the batch once. Per-call audit belongs to the agent
//! surface built on top of this crate, not to the protocol adapter.
//!
//! # Contract
//!
//! ```text
//! Role:      shell (MCP JSON-RPC adapter over tool handlers)
//! Owns:      the tool table of one server; no session state, no storage.
//! Exports:   McpServer<S>, Tool, CallContext, ToolOutcome, ToolBody, Budget, BudgetOffender, BudgetReport,
//!            McpExt, DEFAULT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, DEFAULT_MAX_RESULT_BYTES,
//!            MAX_INSTRUCTIONS_BYTES.
//! Imports:   tesserax (Principal, Tier, Scope, ServerBuilder), tesserax-http (DocRouter, RouteDoc, Endpoint,
//!            HttpExt), axum, serde, serde_json.
//! Forbidden: a tool catalogue of any product; control-plane registration; storage; tesserax-store,
//!            -framework; identity parsed from headers when the gate already admitted a Principal;
//!            any product, host or consumer name.
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod ext;
mod server;

pub use ext::McpExt;
pub use server::{
    Budget, BudgetOffender, BudgetReport, CallContext, DEFAULT_MAX_RESULT_BYTES,
    DEFAULT_PROTOCOL_VERSION, MAX_INSTRUCTIONS_BYTES, McpServer, SUPPORTED_PROTOCOL_VERSIONS, Tool,
    ToolBody, ToolOutcome,
};
