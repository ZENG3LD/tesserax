# tesserax

Back-office library family on a single-writer core.

| Crate | Role |
| --- | --- |
| `tesserax` | SWC contract (envelopes, port, snapshot edge, resync), shared types, and a satellite-agnostic axum `ServerBuilder` with lifecycle. |
| `tesserax-auth` | Doors, path policies, hashed key ring, constant-time compare, auth ban. |
| `tesserax-secrets` | Host-bound seals, daemon identity, signed operator commands, Shamir, tripwire. |
| `tesserax-store` | SQLite single writer, hash-chained audit, optional field cipher and time series. |
| `tesserax-http` | Self-describing routes, OpenAPI, SSE / WebSocket hubs, security guards. |
| `tesserax-transport` | Owner-only local IPC, link proof, call-home, TLS, outbound webhook / SMTP / Telegram. |
| `tesserax-mcp` | MCP JSON-RPC tool server with a byte budget over the HTTP route table. |
| `tesserax-framework` | Single-writer kernel and runtime, effect executors, HTTP and local shells, NCP tier scaffolding (`node` / `c2` / `hq`), a REST + MCP verb surface (`agent`), and a process plugin host (`plugins`). |
| `tesserax-wireguard` | Kernel WireGuard link, brought up with `ip` and `wg`. No userspace UDP stack. |

Licensed under either of MIT or Apache-2.0, at your option.
