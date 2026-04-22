# @mcp-bastion/core

[npm](https://www.npmjs.com/package/@mcp-bastion/core)

Security middleware for MCP servers. Rate limiting in-process; prompt injection and PII via optional sidecar.

## Install

```bash
npm install @mcp-bastion/core @modelcontextprotocol/sdk
```

## Quick Start

Set `MCP_BASTION_URL` to the sidecar URL (e.g. `http://localhost:8000`) to enable prompt guard and PII redaction. Omit it for rate limiting only.

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { wrapWithMcpBastion } from "@mcp-bastion/core";

const server = new Server({ name: "my-mcp-server", version: "1.0.0" });

wrapWithMcpBastion(server, {
  enableRateLimit: true,
  enablePromptGuard: true,
  enablePiiRedaction: true,
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
| enablePromptGuard | false | Needs sidecar (sidecarUrl or MCP_BASTION_URL) |
| enablePiiRedaction | false | Needs sidecar |

### Parity with Python (`mcp-bastion-python`)

The **npm** package is intentionally smaller: in-process **rate limiting** plus optional **sidecar** for prompt guard and PII. It does **not** embed the full Python pillar set (semantic firewall, tool-metadata guard, sensitive-term classifier, edge auth, tool allowlist, content filter, replay guard, schema validation, etc.). For those controls, use **`mcp-bastion-python`** middleware or a sidecar that runs the same checks. Version **1.0.15** on npm reflects this scope; feature parity is **Python-first**.

## Full docs

See [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) for Python package, examples, and documentation.

## License

Same terms as the monorepo: [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE) (source-available; commercial use requires a separate agreement per [COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
