"""
MCP server with MCP-Bastion for OpenAI, Claude, Gemini, Mistral, Grok.

Run:
  cd MCP-Bastion
  $env:PYTHONPATH="src"; python examples/llm_server.py              # stdio
  $env:PYTHONPATH="src"; python examples/llm_server.py --http 8000  # HTTP

Config: docs/LLM_INTEGRATION.md
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = os.path.join(root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)

    parser = argparse.ArgumentParser(description="MCP server with MCP-Bastion")
    parser.add_argument("--http", type=int, metavar="PORT", help="HTTP port")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP host")
    args = parser.parse_args()

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        logger.error("Install: pip install mcp mcp-bastion-python")
        sys.exit(1)

    mcp = FastMCP("MCP-Bastion-Secure", dependencies=["mcp-bastion-python"])

    @mcp.tool()
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    @mcp.tool()
    def get_weather(city: str) -> str:
        """Get weather for a city."""
        return f"Weather in {city}: 22C, sunny"

    if args.http:
        logger.info("MCP server on http://%s:%s/mcp", args.host, args.http)
        mcp.run(transport="streamable-http", host=args.host, port=args.http)
    else:
        logger.info("MCP server (stdio)")
        mcp.run()


if __name__ == "__main__":
    main()
