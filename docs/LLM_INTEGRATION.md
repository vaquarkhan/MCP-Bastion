# MCP-Bastion LLM Integration Guide

Configure MCP-Bastion with major LLM providers. Each example uses the same secure MCP server; only the client config differs. Each example uses the same secure MCP server; only the client config differs.

## LLM Example Files

All 5 LLM example files in `examples/`:

| File | LLM | Transport |
|------|-----|------------|
| `examples/llm_openai_example.py` | OpenAI | stdio, HTTP |
| `examples/llm_claude_example.py` | Claude | stdio, HTTP |
| `examples/llm_gemini_example.py` | Gemini | stdio, HTTP |
| `examples/llm_mistral_example.py` | Mistral | stdio, HTTP/SSE |
| `examples/llm_grok_example.py` | Grok (xAI) | HTTP only |

Shared server: `examples/llm_server.py`

---

## Quick Setup

```bash
pip install mcp mcp-bastion-python
python -m spacy download en_core_web_sm   # for PII redaction (optional)
```

---

## 1. OpenAI (ChatGPT, API, Agents SDK)

### Run the server

**stdio** (for desktop apps, ChatGPT):
```bash
cd MCP-Bastion
$env:PYTHONPATH="src"; python examples/llm_openai_example.py
```

**HTTP** (for remote, API):
```bash
$env:PYTHONPATH="src"; python examples/llm_openai_example.py --http 8000
```

### Config: OpenAI ChatGPT / Desktop

Add to your MCP config (e.g. `~/.config/openai/mcp.json` or ChatGPT MCP settings).
Replace `C:\path\to\MCP-Bastion` with your actual path.

**stdio:**
```json
{
  "mcpServers": {
    "mcp-bastion": {
      "command": "python",
      "args": ["examples/llm_openai_example.py"],
      "cwd": "C:\\path\\to\\MCP-Bastion",
      "env": {
        "PYTHONPATH": "src"
      }
    }
  }
}
```

**HTTP:**
```json
{
  "mcpServers": {
    "mcp-bastion": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

### Config: OpenAI Agents Python SDK

```python
from openai import MCPClient

# stdio
client = MCPClient.from_command(
    command="python",
    args=["examples/llm_openai_example.py"],
    cwd="/path/to/MCP-Bastion",
    env={"PYTHONPATH": "src"},
)

# HTTP (start server first: python examples/llm_openai_example.py --http 8000)
client = MCPClient.from_url("http://localhost:8000/mcp")
```

---

## 2. Claude (Claude Desktop, Claude Code, API)

### Run the server

```bash
cd MCP-Bastion
$env:PYTHONPATH="src"; python examples/llm_claude_example.py
# or: --http 8000 for HTTP
```

### Config: Claude Desktop

Edit `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows: `%APPDATA%\Claude\claude_desktop_config.json`).
Replace `C:\path\to\MCP-Bastion` with your actual path.

**stdio:**
```json
{
  "mcpServers": {
    "mcp-bastion": {
      "command": "python",
      "args": ["examples/llm_claude_example.py"],
      "cwd": "C:\\path\\to\\MCP-Bastion",
      "env": {
        "PYTHONPATH": "src"
      }
    }
  }
}
```

**Windows batch wrapper** (optional): create `run_claude_mcp.bat`:
```batch
@echo off
cd /d C:\path\to\MCP-Bastion
set PYTHONPATH=src
python examples/llm_claude_example.py
```
Then use `"command": "C:\\path\\to\\MCP-Bastion\\run_claude_mcp.bat"` with no args.

**HTTP:**
```json
{
  "mcpServers": {
    "mcp-bastion": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

### Config: Claude Code

Add to `.claude/mcp.json` or project config:
```json
{
  "mcpServers": {
    "mcp-bastion": {
      "command": "python",
      "args": ["examples/llm_claude_example.py"],
      "cwd": "/path/to/MCP-Bastion",
      "env": { "PYTHONPATH": "src" }
    }
  }
}
```
Replace `/path/to/MCP-Bastion` with your actual path.

---

## 3. Google Gemini (Gemini CLI, AI Studio)

### Run the server

```bash
cd MCP-Bastion
$env:PYTHONPATH="src"; python examples/llm_gemini_example.py
# or: --http 8000 for HTTP
```

### Config: Gemini CLI

Edit `~/.gemini/mcp.json` or your Gemini config:

**stdio:**
```json
{
  "mcpServers": {
    "mcp-bastion": {
      "command": "python",
      "args": ["examples/llm_gemini_example.py"],
      "cwd": "/path/to/MCP-Bastion",
      "env": { "PYTHONPATH": "src" }
    }
  }
}
```

**HTTP:**
```json
{
  "mcpServers": {
    "mcp-bastion": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

---

## 4. Mistral (Mistral Agents SDK)

### Run the server

**stdio** (for Mistral Agents with MCPClientSTDIO):
```bash
cd MCP-Bastion
$env:PYTHONPATH="src"; python examples/llm_mistral_example.py
```

**HTTP** (for Mistral Agents with MCPClientSSE):
```bash
$env:PYTHONPATH="src"; python examples/llm_mistral_example.py --http 8000
```

### Config: Mistral Agents Python SDK

```python
import asyncio
import logging
import os
from pathlib import Path
from mcp import StdioServerParameters
from mistralai.extra.mcp.stdio import MCPClientSTDIO
from mistralai import Mistral
from mistralai.extra.run.context import RunContext

logger = logging.getLogger(__name__)
cwd = Path("/path/to/MCP-Bastion")  # Replace with your path

async def main():
    client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])
    server_params = StdioServerParameters(
        command="python",
        args=[str((cwd / "examples" / "llm_mistral_example.py").resolve())],
        env={"PYTHONPATH": str(cwd / "src")},
    )
    mcp_client = MCPClientSTDIO(stdio_params=server_params)
    async with RunContext(model="mistral-medium-latest") as run_ctx:
        await run_ctx.register_mcp_client(mcp_client=mcp_client)
        result = await client.beta.conversations.run_async(
            run_ctx=run_ctx,
            inputs="Add 5 and 7, then get weather for Paris.",
        )
        logger.info("%s", result.output_as_text)

asyncio.run(main())
```

**Remote (SSE):** Start the HTTP server first, then use `MCPClientSSE` with `SSEServerParams(url="http://localhost:8000/mcp")`.

---

## 5. Grok (xAI)

Grok only supports **remote MCP** (HTTP/SSE). Start the HTTP server first.

### Run the server

```bash
cd MCP-Bastion
$env:PYTHONPATH="src"; python examples/llm_grok_example.py
# Serves at http://localhost:8000/mcp (default port 8000)
# Or: python examples/llm_grok_example.py --http 9000
```

### Config: xAI SDK

```python
import logging
import os
from xai_sdk import Client
from xai_sdk.chat import user
from xai_sdk.tools import mcp

logger = logging.getLogger(__name__)
client = Client(api_key=os.environ["XAI_API_KEY"])
chat = client.chat.create(
    model="grok-4-1-fast-reasoning",
    tools=[
        mcp(
            server_url="http://localhost:8000/mcp",
            server_label="mcp-bastion",
        ),
    ],
)
chat.append(user("Add 10 and 20, then get weather for Tokyo."))
response = chat.run()
logger.info("%s", response)
```

### Config: OpenAI-compatible API (xAI Responses API)

```python
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["XAI_API_KEY"],
    base_url="https://api.x.ai/v1",
)
response = client.responses.create(
    model="grok-4-1-fast-reasoning",
    input=[{"role": "user", "content": "Add 5 and 7."}],
    tools=[
        {
            "type": "mcp",
            "server_url": "http://localhost:8000/mcp",
            "server_label": "mcp-bastion",
        }
    ],
)
```

---

## Configuration Reference

| Option | Default | Description |
|--------|---------|-------------|
| `enable_prompt_guard` | `True` | Block malicious prompts |
| `enable_pii_redaction` | `True` | Redact PII in responses |
| `enable_rate_limit` | `True` | Cap tool calls per session |
| `max_iterations` | 30 | Max tool calls (override via `TokenBucketRateLimiter`) |
| `timeout_seconds` | 60 | Session timeout |

### Custom config (edit the example file)

```python
from mcp_bastion import MCPBastionMiddleware
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter

rate_limiter = TokenBucketRateLimiter(
    max_iterations=50,
    timeout_seconds=120,
    token_budget=100_000,
)
bastion = MCPBastionMiddleware(
    rate_limiter=rate_limiter,
    enable_prompt_guard=True,
    enable_pii_redaction=True,
    enable_rate_limit=True,
)
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: mcp` | `pip install mcp mcp-bastion-python` |
| `ModuleNotFoundError: fastmcp` | Use `pip install mcp` (FastMCP is in mcp package) |
| PII not redacted | `pip install presidio-analyzer presidio-anonymizer` and `python -m spacy download en_core_web_sm` |
| Prompt injection not blocked | `pip install torch transformers` (optional, heavy) |
| Wrong working directory | Set `cwd` in config to your MCP-Bastion folder |
| PYTHONPATH | Set `env.PYTHONPATH=src` or `cwd` so `mcp_bastion` is found |

---

## Paths by OS

| OS | Claude config | Typical MCP-Bastion path |
|----|---------------|--------------------------|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` | `C:\Users\<user>\...\MCP-Bastion` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.../MCP-Bastion` |
| Linux | `~/.config/claude/claude_desktop_config.json` | `~/.../MCP-Bastion` |

Replace `/path/to/MCP-Bastion` with your actual path.

## TypeScript

For TypeScript MCP servers using `@mcp-bastion/core`, set `MCP_BASTION_URL` to the Python sidecar URL (e.g. `http://localhost:8000`) to enable prompt guard and PII redaction. Omit it for rate limiting only. See `packages/core/README.md` and `docs/README.md`.
