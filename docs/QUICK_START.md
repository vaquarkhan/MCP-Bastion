# Quick start: protect an MCP server in minutes

Time-to-value matters. Pick **one** path; each keeps Bastion-specific code to **a couple of lines** before you wire transport (stdio or HTTP) the same way you already do for MCP.

---

## Path A — FastMCP (Python)

After `pip install mcp-bastion-fastmcp` and your usual `mcp` / FastMCP install:

```python
from mcp_bastion_fastmcp import secure_fastmcp

secure_fastmcp(mcp)  # add after you create your FastMCP() instance
```

Full runnable pattern: [integrations/mcp-bastion-fastmcp/README.md](../integrations/mcp-bastion-fastmcp/README.md).

---

## Path B — Policy-as-code (`bastion.yaml`)

After `pip install mcp-bastion-python[policy]` and copying `bastion.yaml.example` → `bastion.yaml`:

```python
from mcp_bastion import build_middleware_from_config

middleware = build_middleware_from_config()
```

Register `middleware` on your MCP server’s request path (see [TUTORIALS.md](TUTORIALS.md)). Adjust knobs only in YAML.

---

## Path C — CI gate (machine-scale adoption)

Add **`mcp-bastion validate`** to every PR so policy stays valid in pipelines: [examples/ci/README.md](../examples/ci/README.md).

---

## Next steps

| Need | Doc |
|------|-----|
| Full walkthrough | [DETAILED_TUTORIAL.md](DETAILED_TUTORIAL.md) |
| Claude / OpenAI / Gemini configs | [LLM_INTEGRATION.md](LLM_INTEGRATION.md) |
| `bastion.yaml` reference | [POLICY_AS_CODE.md](POLICY_AS_CODE.md) |
| Production + SIEM | [SECURITY_OBSERVABILITY.md](SECURITY_OBSERVABILITY.md) |
