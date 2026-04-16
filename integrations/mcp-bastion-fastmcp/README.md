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

- Scans all tool inputs for prompt injection
- Rate limits per session (15 calls, 60s timeout)
- Content filtering on inputs and outputs

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Commercial deployment requires a separate agreement ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
