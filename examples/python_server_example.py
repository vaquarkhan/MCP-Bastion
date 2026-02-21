"""
Example: MCP server with MCP-Bastion middleware.
Run: uv run python examples/python_server_example.py
"""

import logging

from mcp_bastion import MCPBastionMiddleware, compose_middleware
from mcp_bastion.base import Middleware, MiddlewareContext

logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


class LoggingMiddleware(Middleware):
    """Logs method and timing."""

    async def on_message(self, context, call_next):
        msg = context.message
        method = getattr(msg, "method", None) or (msg.get("method") if isinstance(msg, dict) else None)
        result = await call_next(context)
        logger.debug("method=%s done", method)
        return result


def create_guarded_server():
    """Create middleware chain with MCP-Bastion."""
    return compose_middleware(
        MCPBastionMiddleware(
            enable_prompt_guard=True,
            enable_pii_redaction=True,
            enable_rate_limit=True,
        ),
        LoggingMiddleware(),
    )


if __name__ == "__main__":
    logger.info("Creating MCP-Bastion middleware chain")
    mw = create_guarded_server()
    logger.info("Middleware ready. Wire compose_middleware output into your MCP server.")
