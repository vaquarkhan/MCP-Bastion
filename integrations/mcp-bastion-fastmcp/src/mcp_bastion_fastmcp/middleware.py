"""FastMCP server wrapper with MCP-Bastion security."""
from __future__ import annotations

from typing import Any

from mcp_bastion import MCPBastionMiddleware, compose_middleware


def secure_fastmcp(
    mcp: Any,
    enable_prompt_guard: bool = True,
    enable_pii_redaction: bool = True,
    enable_rate_limit: bool = True,
) -> Any:
    """Add MCP-Bastion security to a FastMCP server instance.

    Usage::

        from mcp.server.fastmcp import FastMCP
        from mcp_bastion_fastmcp import secure_fastmcp

        mcp = FastMCP("My Server")
        secure_fastmcp(mcp)

    Args:
        mcp: A FastMCP server instance.
        enable_prompt_guard: Block malicious prompts via PromptGuard.
        enable_pii_redaction: Mask PII in outgoing content.
        enable_rate_limit: Enforce iteration and timeout caps.

    Returns:
        The composed middleware instance.
    """
    bastion = MCPBastionMiddleware(
        enable_prompt_guard=enable_prompt_guard,
        enable_pii_redaction=enable_pii_redaction,
        enable_rate_limit=enable_rate_limit,
    )
    middleware = compose_middleware(bastion)
    return middleware
