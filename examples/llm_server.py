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
        try:
            from mcp_bastion.config import load_config
            from mcp_bastion.serve import run_streamable_http

            cfg = load_config(os.environ.get("BASTION_CONFIG", "bastion.yaml"))
            run_streamable_http(mcp, host=args.host, port=args.http, config=cfg)
        except ImportError:
            mcp.settings.host = args.host
            mcp.settings.port = args.http
            logger.info("MCP server on http://%s:%s/mcp", args.host, args.http)
            mcp.run(transport="streamable-http")
    else:
        try:
            from mcp_bastion.config import load_config
            from mcp_bastion.pillars.stdio_guard import install_stdio_guard

            cfg = load_config(os.environ.get("BASTION_CONFIG", "bastion.yaml"))
            if cfg.stdio_guard_enabled:
                install_stdio_guard()
        except ImportError:
            pass
        logger.info("MCP server (stdio)")
        mcp.run()


if __name__ == "__main__":
    main()
