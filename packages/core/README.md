# @mcp-bastion/core

[npm](https://www.npmjs.com/package/@mcp-bastion/core)

Security middleware for MCP (Model Context Protocol) servers. Rate limiting in-process; prompt injection and PII via Python sidecar.

Author: Viquar Khan

## Install

```bash
npm install @mcp-bastion/core @modelcontextprotocol/sdk
```

## Quick Start

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { wrapWithMcpBastion } from "@mcp-bastion/core";

const server = new Server({ name: "my-mcp-server", version: "1.0.0" });

wrapWithMcpBastion(server, {
  enableRateLimit: true,
  maxIterations: 15,
  timeoutMs: 60_000,
  sidecarUrl: process.env.MCP_BASTION_SIDECAR || "",
  enablePromptGuard: !!process.env.MCP_BASTION_SIDECAR,
  enablePiiRedaction: !!process.env.MCP_BASTION_SIDECAR,
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
| sidecarUrl | "" | Python sidecar URL for ML features |
| enablePromptGuard | false | Requires sidecarUrl |
| enablePiiRedaction | false | Requires sidecarUrl |

## Full Docs

See [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) for Python package, examples, and full documentation.
