# Publishing npm `@mcp-bastion/core` and the MCP Registry

## Why npm 404'd on 3.0.0 / 3.0.1

`@mcp-bastion/core` was **never created** on registry.npmjs.org. npm **Trusted Publishing (OIDC)** can only attach to an **existing** package name. First publish must use a granular **NPM_TOKEN**, then you configure Trusted Publisher for later tag releases.

### One-time bootstrap

1. Create a granular token at https://www.npmjs.com/settings/~/tokens (read and write; bypass 2FA for CI).
2. Add it as a GitHub Actions secret: `NPM_TOKEN` on `vaquarkhan/MCP-Bastion`.
3. Run **Actions → Build, Test, and Publish MCP-Bastion → Run workflow** with **publish = true** (from `main` after this fix), **or** push a new `v*` tag.
4. On success, open https://www.npmjs.com/package/@mcp-bastion/core/access and add a **Trusted Publisher**:
   - Owner: `vaquarkhan`
   - Repository: `MCP-Bastion`
   - Workflow: `publish-mcp.yml`
5. Optional: remove `NPM_TOKEN` after Trusted Publisher works (OIDC + `--provenance`).

## MCP Registry OIDC audience

Pinned `mcp-publisher` **v1.4.1** requested audience `mcp-registry`. Production registry now expects `https://registry.modelcontextprotocol.io`. The workflow pins **v1.7.9** (or newer) so `mcp-publisher login github-oidc` succeeds.

Requires `permissions: id-token: write` (already set).
