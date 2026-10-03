//! The MCP door of the agent surface: every verb becomes one tool of an
//! [`McpServer`], answered in the MCP envelope of the module doc.

use std::sync::Arc;

use serde_json::Value;
use tesserax_mcp::{CallContext, McpServer, Tool, ToolOutcome};

use super::{AgentDoor, AgentSurface, VerbCx};

impl AgentSurface {
    /// The MCP door: an [`McpServer`] with one tool per verb (tool name
    /// = `Verb::NAME`, description = `Verb::DOC`, input schema =
    /// [`Verb::schema`](super::Verb::schema)). The tool handlers close
    /// over the surface's shared dispatch, so the server needs no
    /// external state (`McpServer<()>`) and a batched `tools/call` runs
    /// every verb through the same scope check and audit as a REST
    /// call — per-request middleware never sees inside a batch, dispatch
    /// does.
    ///
    /// With [`AgentSurface::auth`](super::AgentSurface::auth) configured
    /// the server is marked with the surface tier for the route table;
    /// serve its routes behind the same gate (the admitted `Principal`
    /// in the request extensions is what the in-dispatch scope check
    /// reads — calls without one are refused).
    pub fn into_mcp(self, name: impl Into<String>, version: impl Into<String>) -> McpServer<()> {
        let tier = self.auth.as_ref().map(|a| a.tier);
        let shared = self.into_shared();
        let mut server = McpServer::new(name, version);
        if let Some(tier) = tier {
            server = server.tier(tier);
        }
        for verb in &shared.verbs {
            let tool = Tool::new(verb.name, verb.doc, verb.schema.clone());
            let verb_name = verb.name;
            let shared = Arc::clone(&shared);
            server = server.tool(tool, move |_: (), ctx: CallContext, args: Value| {
                let shared = Arc::clone(&shared);
                let cx = VerbCx {
                    principal: ctx.principal,
                    door: AgentDoor::Mcp,
                    headers: ctx.headers,
                };
                async move {
                    match shared.dispatch(verb_name, cx, args).await {
                        Ok(out) => ToolOutcome::ok(out),
                        Err(e) => ToolOutcome::error(e.to_string()),
                    }
                }
            });
        }
        server
    }
}
