# tesserax-mcp

Contract header. The crate docs mirror this block.

```text
Role:      shell (MCP JSON-RPC adapter over tool handlers)
Owns:      the tool table of one server; no session state, no storage.
Exports:   McpServer<S>, Tool, CallContext, ToolOutcome, ToolBody, Budget, BudgetOffender, BudgetReport,
           McpExt, DEFAULT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, DEFAULT_MAX_RESULT_BYTES,
           MAX_INSTRUCTIONS_BYTES.
Imports:   tesserax (Principal, Tier, Scope, ServerBuilder), tesserax-http (DocRouter, RouteDoc, Endpoint,
           HttpExt), axum, serde, serde_json.
Forbidden: a tool catalogue of any product; control-plane registration; storage; tesserax-store,
           -framework; identity parsed from headers when the gate already admitted a Principal;
           any product, host or consumer name.
```
