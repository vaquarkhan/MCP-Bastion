# @mcp-bastion/core

[npm](https://www.npmjs.com/package/@mcp-bastion/core)

Security middleware for MCP servers. Rate limiting and hash-chained audit in-process; prompt injection, PII, semantic egress, and result guard via optional sidecar.

## Nature (do not break)

- **Zero-infrastructure core** — no inline ML, no trust-root service required for default paths.
- **Fail-closed** when a heavy feature is enabled without its sidecar (prompt guard; semantic egress / result guard in quarantine|strict mode).
- **Mediation precondition:** controls apply only to MCP traffic that flows through these wrappers. Out-of-band shell or code-exec is **out of scope** — use capability reduction and an OS sandbox for that path.
- Heavy / semantic work is always a **sidecar** (`sidecarUrl` or `MCP_BASTION_URL`). Enabling a sidecar is opt-in infrastructure; do not claim zero-infra once it is on.

## Install

```bash
npm install @mcp-bastion/core @modelcontextprotocol/sdk
```

## Quick Start

Set `MCP_BASTION_URL` to the sidecar URL (e.g. `http://localhost:8000`) to enable sidecar features. Omit it for rate limiting / provenance tagging / audit only.

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { wrapWithMcpBastion } from "@mcp-bastion/core";

const server = new Server({ name: "my-mcp-server", version: "1.0.0" });

wrapWithMcpBastion(server, {
  enableRateLimit: true,
  enablePromptGuard: true,
  enablePiiRedaction: true,
  // Advisory by default — raises cost, does not prevent social engineering
  enableSemanticEgress: true,
  semanticEgressMode: "detect",
  semanticEgressTools: ["create_pull_request", "send_email"],
  // Reduces indirect-injection efficacy; not IFC isolation
  tagResultProvenance: true,
  enableAudit: true,
});

server.setRequestHandler("tools/call" as any, async (request) => {
  if (request.params?.name === "get_weather") {
    return { content: [{ type: "text", text: "Sunny, 22C" }], isError: false };
  }
  throw new Error("Unknown tool");
});

const transport = new StdioServerTransport();
await server.connect(transport);
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| enableRateLimit | true | Cap tool calls per session |
| maxIterations | 15 | Max tool calls before block |
| timeoutMs | 60000 | Session timeout |
| sidecarUrl | (none) | Sidecar URL; falls back to MCP_BASTION_URL |
| enablePromptGuard | false | Needs sidecar |
| enablePiiRedaction | false | Needs sidecar |
| enableSemanticEgress | false | Screen allowlisted outbound tools via `/semantic-egress` |
| semanticEgressMode | detect | `detect` = log; `quarantine` = block high scores (fail-closed) |
| semanticEgressTools | [] | Tool names to screen |
| semanticThreshold | 0.7 | Quarantine when score ≥ threshold |
| semanticTimeoutMs | 800 | Sidecar timeout |
| tagResultProvenance | false | Wrap result text in `<untrusted_tool_result>` markers (in-process) |
| enableResultGuard | false | Scan results via `/result-guard` |
| resultGuardMode | detect | `detect` = log; `strict` = block (fail-closed) |
| resultGuardTimeoutMs | 800 | Sidecar timeout |
| enableAudit | false | In-memory hash-chained audit (tamper-evident, not tamper-proof) |
| onAudit | (noop) | Optional sink per audit record (e.g. JSONL append) |

### Sidecar endpoints

| Path | Purpose |
|------|---------|
| `POST /prompt-guard` | `{ text }` → `{ malicious }` |
| `POST /pii-redact` | `{ content }` → `{ content }` |
| `POST /semantic-egress` | `{ text }` → `{ score, dimensions?, verdict? }` |
| `POST /result-guard` | `{ content }` → `{ malicious? }` |

### Honest claims

| Feature | Claim | Not a claim |
|---------|-------|-------------|
| Semantic egress | Raises cost; catches unsubtle manipulation on MCP-mediated outbound tools | Prevents social engineering; sees shell/git |
| Result provenance | Reduces indirect-injection efficacy | Isolates content (needs IFC in the agent) |
| Audit chain | Tamper-evident; offline verify detects mutation | Tamper-proof / immutable without external seal |

### Scope vs Python (`mcp-bastion-python`)

The **npm** package is **smaller by design**: in-process rate limit, provenance tags, and audit, plus optional sidecar for ML-ish checks. It does **not** implement the full Python control set. For those controls, use **`mcp-bastion-python`**. Compare explicitly — **npm** and **PyPI** are complementary, not interchangeable.

## Full docs

See [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) for Python package, examples, and documentation.

## License

Same terms as the monorepo: [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE) (source-available; free non‑commercial use with **citation/attribution**; **copyright** terms apply; **commercial** use may need a separate agreement per [COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
