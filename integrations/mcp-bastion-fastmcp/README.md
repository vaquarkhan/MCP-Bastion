# mcp-bastion-fastmcp

Security middleware for FastMCP servers powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

Protect any FastMCP server from prompt injection, PII leakage, and resource exhaustion with a single import.

## Install

```bash
pip install mcp-bastion-fastmcp
```

## Usage

```python
from mcp.server.fastmcp import FastMCP
from mcp_bastion_fastmcp import secure_fastmcp

mcp = FastMCP("My Secure Server")

# Add MCP-Bastion security to your server
secure_fastmcp(mcp)

@mcp.tool()
def get_weather(city: str) -> str:
    return f"Weather in {city}: 22C, sunny"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
```

## What it protects

- Scans all tool arguments through the same `MCPBastionMiddleware` path as the core Python package (see defaults on the three toggles above)
- For **full** `bastion.yaml` features (semantic firewall, OPA/Cedar, allowlists, session limits, etc.), use `build_middleware_from_config()` with the low-level MCP `Server` — FastMCP does not expose a native hook for the entire policy surface

**Implementation note:** `secure_fastmcp` patches `FastMCP._tool_manager.call_tool` so every tool invocation flows through Bastion. Call it right after `FastMCP(...)` and before `run()`.

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Commercial deployment requires a separate agreement ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
