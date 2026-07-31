# Tutorials: Integrating with Popular MCP Servers

This guide shows how to add MCP-Bastion to your MCP server so that tool calls are protected regardless of the client (GitHub Copilot, Cursor, Claude, custom apps). The same pattern applies to open-source MCP servers (e.g. filesystem, database, Slack, GitHub API).

For **how this differs from an LLM API “swap base URL” gateway** and how **each stack** (Python, TypeScript, Desktop, HTTP, integrations) gets Bastion in front of MCP, see [INTEGRATION_MODELS.md](INTEGRATION_MODELS.md).

For **Java, TypeScript, Go, .NET, Kotlin, Rust** connectors and shared `bastion.yaml`, see [MULTI_LANGUAGE_SUITE.md](MULTI_LANGUAGE_SUITE.md) and the suite repo: https://github.com/vaquarkhan/mcp-bastion-suite

For a full environment-to-production walkthrough, see [DETAILED_TUTORIAL.md](DETAILED_TUTORIAL.md).

For the end-to-end professional handbook (concepts through production checklist), see [USER_GUIDE.md](USER_GUIDE.md) or the published site: https://vaquarkhan.github.io/MCP-Bastion/guide/.

---

## Prerequisites

- Python 3.10+ and `pip install mcp mcp-bastion-python`, or Node 18+ and `npm install @modelcontextprotocol/sdk @mcp-bastion/core`
- An MCP server you run (your own or an open-source one you host)

---

## Tutorial 1: Wrap Your Own Python MCP Server (FastMCP)

If you already have an MCP server built with [FastMCP](https://github.com/jlowin/fastmcp) or the Python MCP SDK:

**Step 1.** Install dependencies.

```bash
pip install mcp mcp-bastion-python
```

**Step 2.** In your server code, create the Bastion middleware and pass it into your server if the framework supports middleware. If your server uses a lower-level API, wrap the handler that processes JSON-RPC:

```python
from mcp.server.fastmcp import FastMCP
from mcp_bastion import MCPBastionMiddleware, compose_middleware

mcp = FastMCP("My Server")

bastion = MCPBastionMiddleware(
    enable_prompt_guard=True,
    enable_pii_redaction=True,
    enable_rate_limit=True,
)
middleware = compose_middleware(bastion)

# If your framework accepts middleware, register it.
# Otherwise, wrap your request handler so every message goes through middleware(context, call_next).
```

**Step 3.** Run the server (stdio or HTTP). Clients (e.g. Cursor, Claude Desktop, GitHub Copilot when configured to use your server) connect to this process. All tool calls are then checked by MCP-Bastion before your tools run.

**Policy-as-code option:** Use `bastion.yaml` and `build_middleware_from_config()` so security limits and features are configurable without code changes. See [POLICY_AS_CODE.md](POLICY_AS_CODE.md).

**3.0 runtime governance:** Enable opt-in pillars (`canary_goallock`, `atr_rules`, `llm_scanner`, etc.) from `bastion.yaml.example` or `examples/bastion-runtime-governance-3.0.yaml`. See [ENTERPRISE_RUNTIME_CONTROLS.md](ENTERPRISE_RUNTIME_CONTROLS.md).

---

## Tutorial 1b: Enable 3.0 runtime governance (policy-as-code)

**Step 1.** Copy the sample policy:

```bash
cp examples/bastion-runtime-governance-3.0.yaml bastion.yaml
# Or merge sections into your existing bastion.yaml
```

**Step 2.** Add ATR sample rules (already in repo under `atr-rules/`).

**Step 3.** Validate and run:

```bash
mcp-bastion validate --config bastion.yaml
mcp-bastion serve --config bastion.yaml --http 8080
```

**Step 4.** Try observe mode before enforcing:

```yaml
mode: observe   # logs would_block in metadata without denying
```

**Step 5.** Export compliance evidence from audit JSONL:

```bash
mcp-bastion report --framework soc2 --audit .bastion/audit.jsonl -o report.md
```

---

## Tutorial 2: Wrap a TypeScript MCP Server

For a Node/TypeScript MCP server (e.g. using `@modelcontextprotocol/sdk`):

**Step 1.** Install dependencies.

```bash
npm install @modelcontextprotocol/sdk @mcp-bastion/core
```

**Step 2.** Wrap the server with MCP-Bastion before registering handlers:

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { wrapWithMcpBastion } from "@mcp-bastion/core";

const server = new Server({ name: "my-mcp-server", version: "1.0.0" });

wrapWithMcpBastion(server, {
  enableRateLimit: true,
  maxIterations: 15,
  timeoutMs: 60_000,
  sidecarUrl: process.env.MCP_BASTION_SIDECAR || "",  // optional: for prompt/PII
  enablePromptGuard: !!process.env.MCP_BASTION_SIDECAR,
  enablePiiRedaction: !!process.env.MCP_BASTION_SIDECAR,
});

// Register your tools as usual
server.setRequestHandler("tools/call" as any, async (request) => {
  // Your tool logic
  return { content: [{ type: "text", text: "OK" }], isError: false };
});

const transport = new StdioServerTransport();
await server.connect(transport);
```

**Step 3.** For full prompt injection and PII redaction, run the Python sidecar and set `MCP_BASTION_SIDECAR` to its URL. See [README](../README.md) and [SETUP_GUIDE.md](../SETUP_GUIDE.md).

---

## Tutorial 3: Securing a “GitHub-like” or Third-Party MCP Server

Many teams use or fork open-source MCP servers (e.g. GitHub API, filesystem, database, Slack). You usually cannot change their code. You can still protect them by running MCP-Bastion as a **proxy** in front of the server:

**Option A – Same process (if you run a wrapper script):**  
Write a small Python script that (1) starts or connects to the existing MCP server, (2) wraps every incoming JSON-RPC message with MCP-Bastion middleware, and (3) forwards allowed requests to the real server. This requires your wrapper to speak MCP (stdio or HTTP) and call the real server. The examples in this repo show middleware in-process; for a true proxy you would run the upstream server as a subprocess or HTTP client and pass messages through Bastion first.

**Option B – Use the existing “serve” pattern:**  
If your MCP server is the one in this repo (e.g. `examples/llm_server.py`), you already use `mcp-bastion serve` or the same middleware in-process. For a third-party server you run (e.g. a community GitHub MCP server), you can:

1. Run the third-party server as-is on a port (e.g. 8001).
2. Run an MCP-Bastion-wrapped server that proxies to 8001: it receives client connections, runs each request through Bastion, and forwards to 8001 only if allowed. Implement the proxy in Python or TypeScript using the same middleware pattern; the “downstream” is the third-party server.

**Conceptually:** Client → MCP-Bastion (in your process) → Third-party MCP server. All tool calls are inspected and optionally blocked or redacted before they reach the third-party server.

---

## Tutorial 4: Open-Source MCP Servers (Generic)

Examples of open-source MCP servers you might host yourself:

- **GitHub MCP Server** – [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) or GitHub’s official server: exposes repos, issues, PRs. When you run your own instance, wrap it with MCP-Bastion so that prompt injection and rate limits are enforced before any GitHub API call.
- **Filesystem / Database / Slack MCP** – Community servers that expose tools for file read, DB query, or Slack. Same idea: run the server in a process where Bastion middleware wraps the request handler so that path traversal, injection, and rate limits are enforced.

**Generic steps:**

1. Identify how the server receives MCP requests (stdio vs HTTP).
2. If you can run your own entrypoint (e.g. a Python script that imports the server’s app and adds middleware), add `MCPBastionMiddleware` + `compose_middleware` in front of the handler (see Tutorial 1).
3. If you cannot modify the server, run a proxy that accepts client connections, runs each message through Bastion, and forwards to the open-source server (Tutorial 3, Option B).
4. Configure `bastion.yaml` (or equivalent) for limits and alerts, and run the dashboard to monitor blocked and PII-redacted metrics.

---

## Tutorial 5: Local dashboard (posture, issue guides, FinOps)

Zero-infra: the dashboard reads **in-process metrics** plus optional files under `.bastion/scan/` - no cloud DB.

```bash
pip install "mcp-bastion-python[dashboard]"
mcp-bastion dashboard --port 7000 --demo
```

Open [http://localhost:7000/](http://localhost:7000/):

1. **Security posture** - letter grades from scan JSON; click a finding → **Why / how to fix** (PMD-style + OWASP).
2. **Static prevalidation** - Sonar-style issue list (`/api/prevalidate`) from the same files.
3. **Cost burn & reduction** - actual vs would-have-been tokens/$; blocked-issues table for what Bastion stopped.
4. Write real artifacts (instead of `--demo`):

```bash
mkdir -p .bastion/scan
mcp-bastion scan tools.json --format json -o .bastion/scan/catalog.json
mcp-bastion audit --format json -o .bastion/scan/risk-audit.json
```

Details: [dashboard/README.md](../dashboard/README.md) · [ZERO_INFRA_STRATEGY.md](ZERO_INFRA_STRATEGY.md).

---

## Tutorial 6: Hybrid stateful / stateless MCP transport

Prepare for **stateless MCP** (explicit state handles, per-request protocol version) while keeping **legacy session clients** working on the same proxy.

**Step 1.** Copy the sample config:

```bash
cp examples/bastion-hybrid-transport.yaml bastion.yaml
mcp-bastion validate --config bastion.yaml
```

**Step 2.** Run upstream MCP on loopback, then the Bastion proxy:

```bash
mcp-bastion serve --http 9000 --host 127.0.0.1
mcp-bastion serve --proxy http://127.0.0.1:9000/mcp --http 8080 --config bastion.yaml
```

**Step 3.** Discover capabilities without an initialize handshake:

```bash
curl -s http://127.0.0.1:8080/.well-known/mcp.json | jq .
```

**Step 4.** Send stateful (session header) and stateless (state handle) tool calls - both paths share the same `bastion.yaml` pillars.

Full walkthrough with curl examples, Redis scaling, and agent stability: **[HYBRID_TRANSPORT_TUTORIAL.md](HYBRID_TRANSPORT_TUTORIAL.md)** · architecture: [HYBRID_MCP_TRANSPORT.md](HYBRID_MCP_TRANSPORT.md).

---

## CRA / CycloneDX SBOM (supply chain, no runtime change)

Generate a CycloneDX SBOM for questionnaires and CRA Article 14 steward docs:

```bash
python scripts/generate_sbom.py --output bom.json
```

Tutorial: **[CRA_SBOM_TUTORIAL.md](CRA_SBOM_TUTORIAL.md)** · posture: [CRA_COMPLIANCE.md](CRA_COMPLIANCE.md) · VDP: [SECURITY.md](../SECURITY.md).

---

## Reversible PII vault (opt-in)

Keep tool calling working while the LLM never sees raw emails/SSNs:

```yaml
pii_vault:
  enabled: true
```

Tutorial: **[PII_VAULT_TUTORIAL.md](PII_VAULT_TUTORIAL.md)** · [PII_VAULT.md](PII_VAULT.md).

---

## Summary

| Scenario | Approach |
|----------|----------|
| Your own Python MCP server | Add `MCPBastionMiddleware` + `compose_middleware` (or `build_middleware_from_config()`). |
| Your own TypeScript MCP server | Use `wrapWithMcpBastion(server, options)`. |
| Third-party / GitHub / open-source MCP server | Run a Bastion-wrapped proxy that forwards to the upstream server, or run a wrapper process that injects middleware if the server supports it. |
| Stateless MCP + legacy sessions (same proxy) | Enable `mcp_transport` in `bastion.yaml`; use `serve --proxy` + discovery card. [HYBRID_TRANSPORT_TUTORIAL.md](HYBRID_TRANSPORT_TUTORIAL.md) |
| CRA / SBOM evidence | `python scripts/generate_sbom.py` - [CRA_SBOM_TUTORIAL.md](CRA_SBOM_TUTORIAL.md) |
| Reversible PII (LLM never sees raw) | `pii_vault.enabled: true` - [PII_VAULT_TUTORIAL.md](PII_VAULT_TUTORIAL.md) |
| Schema minimize + live catalog pin | `discovery_filter.minimize_schemas` / `tool_metadata_fingerprint.pin_on_first_seen` - [SCHEMA_MINIMIZE_LIVE_PIN.md](SCHEMA_MINIMIZE_LIVE_PIN.md) |

For more examples, see [examples/README.md](../examples/README.md), [SETUP_GUIDE.md](../SETUP_GUIDE.md), and [LLM_INTEGRATION.md](LLM_INTEGRATION.md) for client-side (OpenAI, Claude, etc.) setup.
