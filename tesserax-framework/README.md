# tesserax-framework

Back-office framework on `tesserax`: a single-writer kernel (`Domain`, `Core::step` in a fixed phase order, generation-checked observations, counters that saturate into health flags and then reject commands), the `Runtime` that owns the kernel and drives it through the `tesserax::swc` port, and effect executors (std threads; tokio tasks behind feature `tokio`; durable writes acknowledged after a `tesserax-store` barrier behind feature `store`).

Transport shells over the same port: `http_shell` (four self-describing routes with a control / observe door split, snapshot ETag = revision, SSE events with `id` = sequence and `Last-Event-ID` resume, wire resync with `gap`) and `local_shell` (NDJSON over an owner-only socket / pipe, one proven door per link) behind feature `shell`, and `RemoteHandle`, the root `Port` over either wire, behind feature `client`.

NCP tier scaffolding is in this release behind features `node`, `c2`, and `hq`: a shared roster, down link, fleet oracle and attach listener, plus one builder per tier (`node-os` supervises the node's services as OS processes). The REST + MCP verb surface is in this release behind feature `agent`: one `Verb` is answered over REST (`POST /v1/verbs/{name}`) and MCP (`tools/call`) from a single registration, and every mutating call is audited inside that dispatch.

Feature `plugins` is a process host only: a manifest, a restart policy, and a capability token passed through an environment variable the manifest names. Shared-library and WebAssembly hosts are not in this release.

Licensed under either of MIT or Apache-2.0, at your option.
