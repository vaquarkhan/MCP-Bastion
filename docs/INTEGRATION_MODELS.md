# Integration models: middleware vs “change the URL”

**MCP-Bastion** ships as **security middleware and `bastion.yaml`** on the **Model Context Protocol** tool path: you embed it in (or in front of) the MCP server **you** run.

Many **LLM HTTP API** products adopt with a **single base-URL swap**—clients point at a proxy host. MCP-Bastion instead gives you **policy on the MCP tool path**: embed it in **your** stdio-based or **your** HTTPS **`/mcp`** server.

This page maps common stacks so **“drop-in middleware”** is easy to adopt on **your** infrastructure.

---

## LLM API gateway (URL swap) vs Bastion (OSS today)

| Aspect | LLM API gateway (swap base URL) | MCP-Bastion (typical OSS use) |
|--------|----------------------------------|-------------------------------|
| **Client change** | Often: new base URL / API host | Clients use **your** MCP server (stdio command or **your** HTTP `/mcp`) with Bastion wired in. |
| **Where policy runs** | On the proxy process | On **your** MCP server process (middleware) or on a **wrapper** you deploy in front of upstream MCP. |
| **Config** | Proxy env / config file | **`bastion.yaml`** + `load_config()` / `build_middleware_from_config()`, or code flags on `MCPBastionMiddleware`. |

---

## How each stack gets Bastion in front of MCP

Use the row that matches **who runs the MCP server** and **what you can change**.

| Stack | How Bastion sits “in front” | What you actually change |
|-------|-----------------------------|---------------------------|
| **Your Python MCP server** (MCP SDK, FastMCP) | **In-process:** `MCPBastionMiddleware` + `compose_middleware`, or **`build_middleware_from_config()`** for `bastion.yaml`. | Server **entrypoint code** (and policy file on disk). Same deployable; clients keep using your stdio command or HTTP URL. |
| **Your TypeScript MCP server** | **`wrapWithMcpBastion`** from `@mcp-bastion/core`; optional **sidecar** URL for prompt guard and PII (see `packages/core/README.md` for **exact** npm vs Python scope). | Server **startup code**. See [TUTORIALS.md](TUTORIALS.md) § Tutorial 2. |
| **Claude Desktop, Cursor, ChatGPT MCP, etc. (stdio)** | MCP config runs **a command**; point it at the entrypoint that **starts your server with Bastion** (e.g. your `python my_server.py` that builds middleware). | **MCP client JSON:** `command` / `args` / `cwd` / `env`. Examples: [LLM_INTEGRATION.md](LLM_INTEGRATION.md). |
| **HTTP MCP clients** | Your server listens on **your** host; middleware runs **inside** that server (or behind a reverse proxy you control that still terminates at your wrapped app). | Base URL is **your** deployed server (e.g. `https://your-org/mcp`), which you built with Bastion wired in. |
| **LangChain, LlamaIndex, OpenAI Agents, …** | Use the **`mcp-bastion-*` integration** packages where they wrap the provider path, **or** run an MCP server with Bastion and point the agent at that server. | Per **integration** `README` under `integrations/`; each stack has its own connection settings. |
| **Third-party / vendor MCP you cannot fork** | **Proxy boundary:** clients reach only the Bastion proxy; upstream MCP binds to loopback. See [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md). | [deploy/docker-compose.proxy.yml](../deploy/docker-compose.proxy.yml) + `edge_auth`; see [TUTORIALS.md](TUTORIALS.md) (Tutorial 3, Option B). |

**LangChain / LlamaIndex / Claude Desktop** are **clients or frameworks**; they connect to the MCP server **you** run—wire Bastion into that server, then point the client at it (stdio or **your** HTTPS URL).

---

## HTTPS and your own gateway

If clients use a **single MCP HTTPS URL**, that endpoint should be **your** deployment (reverse proxy + server) where Bastion middleware is already part of the process chain. That is the same pattern as any production API: **your** DNS, **your** TLS, **your** app with Bastion inside.

---

## See also

- [LLM_INTEGRATION.md](LLM_INTEGRATION.md) — concrete MCP client configs (OpenAI, Claude, Gemini, …)  
- [TUTORIALS.md](TUTORIALS.md) — FastMCP, TypeScript, third-party / proxy patterns  
- [POLICY_AS_CODE.md](POLICY_AS_CODE.md) — `bastion.yaml`  
- [PILLARS.md](PILLARS.md) — what the runtime implements  
- [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) — mandatory proxy hop vs in-process middleware  
