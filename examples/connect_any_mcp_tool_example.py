"""
Connect Bastion to *any* MCP tool surface (names your server defines).

MCP-Bastion does not ship a fixed tool catalog. You wrap your existing server so
that every JSON-RPC message (especially `tools/list` and `tools/call`) passes
through the same middleware chain before your handlers or upstream proxy.

Patterns (pick one):

1) **In-process (Python):** build `MCPBastionMiddleware` or `build_middleware_from_config()`,
   then `compose_middleware(bastion, your_handler)` so each `tools/call` runs checks first.

2) **FastMCP / stdio / HTTP:** see `examples/llm_server.py` and `examples/server_with_config.py`.

3) **Third-party MCP as downstream:** run Bastion in front of the other process and forward
   allowed JSON-RPC; see `docs/TUTORIALS.md` (proxy-style integration).

4) **TypeScript:** `npm install @mcp-bastion/core @modelcontextprotocol/sdk` and wrap the SDK
   handler (see `packages/core/README.md`).

This file only demonstrates (1) with synthetic tool names. Run:

  PYTHONPATH=src python examples/connect_any_mcp_tool_example.py
"""

from __future__ import annotations

import asyncio
import os
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(root, "src"))

from mcp_bastion import MCPBastionMiddleware
from mcp_bastion.base import MiddlewareContext
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


async def main() -> None:
    bastion = MCPBastionMiddleware(
        rate_limiter=TokenBucketRateLimiter(max_iterations=50, timeout_seconds=60, token_budget=50_000),
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=True,
    )

    async def downstream(ctx: MiddlewareContext):
        """Your MCP server handler: any tool name your product defines."""
        msg = ctx.message
        name = (msg.get("params") or {}).get("name", "unknown") if isinstance(msg, dict) else "unknown"
        return {"content": [{"type": "text", "text": f"executed:{name}"}]}

    for tool in ("crm_lookup_contact", "erp_post_invoice", "partner_webhook_send"):
        ctx = MiddlewareContext(
            message={"method": "tools/call", "params": {"name": tool, "arguments": {"id": "123"}}},
            request_id="req-1",
            session_id="session-any-tool",
        )
        out = await bastion(ctx, downstream)
        print(tool, "->", out)


if __name__ == "__main__":
    asyncio.run(main())
