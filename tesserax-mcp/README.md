# tesserax-mcp

An MCP (Model Context Protocol) server for `tesserax`: JSON-RPC 2.0 over HTTP, single request or batch, stateless (`DELETE` answers 204, notifications get no answer). Tool results are compact — one text entry, a JSON body serialised without pretty-printing, no `structuredContent` duplicate — and capped at a byte limit, cut on a UTF-8 boundary with a one-line note naming the bytes cut. `check_budget` measures `tools/list` against a size budget (`Budget::LEAN`: 8 tools, 8 KB list, 1.5 KB per tool, 300 B instructions) and names every offender. The routes are recorded in a `tesserax-http` `DocRouter` with their description and tier, so `McpExt::with_mcp` puts them in a `ServerBuilder`'s route table: the `tesserax-auth` gate refuses an unadmitted caller before any tool runs, and each tool receives the admitted `Principal` in its `CallContext`.

Licensed under either of MIT or Apache-2.0, at your option.
