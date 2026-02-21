# Spins up MCP Inspector for stdio transport validation.
# Run from project root. Requires: npm, npx, and a wrapped MCP server command.
#
# Usage:
#   .\tests\run_inspector_test.ps1 "uv run python -m your_mcp_server"
#   .\tests\run_inspector_test.ps1 "node packages/core/dist/index.js"

param(
    [string]$ServerCmd = "echo 'Provide server command as first argument'"
)

Write-Host "Starting MCP Inspector for stdio validation..."
Write-Host "Server command: $ServerCmd"
Write-Host ""
Write-Host "In the Inspector UI, connect via stdio and use the command above."
Write-Host "Run: npx -y @modelcontextprotocol/inspector"
Write-Host ""

npx -y @modelcontextprotocol/inspector
