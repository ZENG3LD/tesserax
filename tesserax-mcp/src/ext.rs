//! [`McpExt`]: mounts an [`McpServer`] on a `tesserax::ServerBuilder`.

use tesserax::ServerBuilder;
use tesserax_http::HttpExt;

use crate::server::McpServer;

/// Adds an MCP server to a server builder.
pub trait McpExt: Sized {
    /// Registers the routes of `mcp` (`POST` / `DELETE` at its path) in the
    /// route table with their description, tier and scope, handing every
    /// tool a clone of `state`. The auth gate (if installed) enforces the
    /// tier before any JSON-RPC is parsed and puts the admitted `Principal`
    /// in the request, which reaches each tool as
    /// [`CallContext::principal`](crate::CallContext::principal). OpenAPI
    /// (`HttpExt::with_openapi`) lists the routes.
    fn with_mcp<S>(self, mcp: McpServer<S>, state: S) -> Self
    where
        S: Clone + Send + Sync + 'static;
}

impl McpExt for ServerBuilder {
    fn with_mcp<S>(self, mcp: McpServer<S>, state: S) -> Self
    where
        S: Clone + Send + Sync + 'static,
    {
        self.with_routes(mcp.into_doc_router().with_state(state))
    }
}
