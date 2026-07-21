# Quick start: protect an MCP server in minutes

Time-to-value matters. Pick **one** path; each keeps Bastion-specific code to **a couple of lines** before you wire transport (stdio or HTTP) the same way you already do for MCP.

---

## Path A  -  FastMCP (Python)

After `pip install mcp-bastion-fastmcp` and your usual `mcp` / FastMCP install:

```python
from mcp.server.fastmcp import FastMCP
from mcp_bastion_fastmcp import secure_fastmcp

mcp = FastMCP("My Server")
secure_fastmcp(mcp)  # must run right after FastMCP(); wires Bastion into tool dispatch
```

`secure_fastmcp` patches FastMCP’s internal tool dispatcher so each `tools/call` runs through `MCPBastionMiddleware` (defaults: prompt guard, PII redaction, rate limit). It does **not** load arbitrary `bastion.yaml` by itself. For **full** policy (semantic firewall, OPA/Cedar, allowlists, session limits, etc.) use **Path B** or compose middleware on the low-level MCP server.

Full runnable pattern: [integrations/mcp-bastion-fastmcp/README.md](../integrations/mcp-bastion-fastmcp/README.md).

---

## Path B  -  Policy-as-code (`bastion.yaml`)

After `pip install mcp-bastion-python[policy]` and copying `bastion.yaml.example` → `bastion.yaml`:

```python
from mcp_bastion import build_middleware_from_config

middleware = build_middleware_from_config()
```

Register `middleware` on your MCP server’s request path (see [TUTORIALS.md](TUTORIALS.md)). Adjust knobs only in YAML.

**HTTP proxy + stateless MCP:** see [HYBRID_TRANSPORT_TUTORIAL.md](HYBRID_TRANSPORT_TUTORIAL.md) (`serve --proxy`, discovery card, `mcp_transport` block).

---

## Path C  -  CI gate (machine-scale adoption)

Add **`mcp-bastion validate`** to every PR so policy stays valid in pipelines: [examples/ci/README.md](../examples/ci/README.md).

---

## Next steps

| Need | Doc |
|------|-----|
| Full walkthrough | [DETAILED_TUTORIAL.md](DETAILED_TUTORIAL.md) |
| Claude / OpenAI / Gemini configs | [LLM_INTEGRATION.md](LLM_INTEGRATION.md) |
| `bastion.yaml` reference | [POLICY_AS_CODE.md](POLICY_AS_CODE.md) |
| Production + SIEM | [SECURITY_OBSERVABILITY.md](SECURITY_OBSERVABILITY.md) |
| Local dashboard (demo) | [dashboard/README.md](../dashboard/README.md) - `mcp-bastion dashboard --demo` |
