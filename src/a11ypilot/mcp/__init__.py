"""Pure-STDIO JSON-RPC 2.0 MCP server package for A11yPilot."""

from __future__ import annotations

from a11ypilot.mcp.server import (
    MCP_TOOLS,
    A11yMCPServer,
    configure_stderr_logging,
    run_mcp_server,
)

__all__ = [
    "MCP_TOOLS",
    "A11yMCPServer",
    "configure_stderr_logging",
    "run_mcp_server",
]
