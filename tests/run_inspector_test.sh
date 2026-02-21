#!/bin/bash
# Spins up MCP Inspector for stdio transport validation.
# Run from project root. Requires: npm, npx, and a wrapped MCP server command.
#
# Usage:
#   ./tests/run_inspector_test.sh "uv run python -m your_mcp_server"
#   ./tests/run_inspector_test.sh "node packages/core/dist/index.js"

set -e

SERVER_CMD="${1:-echo 'Provide server command as first argument'}"
echo "Starting MCP Inspector for stdio validation..."
echo "Server command: $SERVER_CMD"
echo ""
echo "In the Inspector UI, connect via stdio and use the command above."
echo "Run: npx -y @modelcontextprotocol/inspector"
echo ""

npx -y @modelcontextprotocol/inspector
