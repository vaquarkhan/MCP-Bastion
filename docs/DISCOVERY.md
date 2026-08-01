# Discovery and registries (MCP ecosystem)

Many installs come from **CI**, **mirrors**, and **transitive** dependencies - not only manual `pip install`. Listing MCP-Bastion where developers search for MCP tools increases legitimate machine and human traffic.

Use this as an **internal checklist** when promoting releases (URLs and forms change; verify on each site).

| Platform | Suggested action |
|----------|------------------|
| **Official MCP Registry** | Already wired in release automation when you publish tags; keep `mcp-name` in README aligned with registry metadata. |
| **[Smithery](https://smithery.ai/)** | Submit or refresh the server listing so `mcp install` / Smithery flows can resolve MCP-Bastion or your wrapped server. |
| **[Glama](https://glama.ai/)** | Claim or add the MCP server listing with accurate description and repo link. |
| **Docker MCP / partner catalogs** | If you publish an official image or Compose stack, submit to Docker’s MCP-related listings when available. |
| **Awesome lists** | Propose a one-line entry to curated **awesome-mcp-servers** / **awesome-mcp** lists with a stable doc link ([QUICK_START.md](QUICK_START.md)). |
| **Proof deck (social / sales)** | Share **[MCP-Security-Deck-v3.pdf](../MCP-Security-Deck-v3.pdf)** ([raw](https://github.com/vaquarkhan/MCP-Bastion/raw/main/MCP-Security-Deck-v3.pdf)) in LinkedIn, RFPs, and security reviews — pair with [BENCHMARKS.md](BENCHMARKS.md). |
| **GitHub Topics** | Ensure topics include `mcp`, `model-context-protocol`, `ai-security`, `prompt-injection`, `finops`, `owasp`. |

**PyPI / npm:** keep package metadata (`keywords`, `project.urls`) current so search and mirrors pick up the right description.
