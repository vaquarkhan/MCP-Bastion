# Trusted Publishing Setup

Secure your release pipeline with OIDC—no long-lived tokens needed.

## npm Trusted Publishers

Required for publishing via `git push` tags. Configure once at [npmjs.com](https://www.npmjs.com/) → **Packages** → **@mcp-bastion/core** → **Settings** → **Trusted Publishers** → **GitHub Actions**:
- **Workflow filename:** `publish-mcp.yml`
- **Repository:** `vaquarkhan/MCP-Bastion`

## PyPI Trusted Publishers

1. Go to [pypi.org](https://pypi.org/) → Your project → **Publishing** → **Add a new pending publisher**
2. Choose **GitHub Actions**
3. Enter:
   - **Owner:** `vaquarkhan` (or your org)
   - **Repository:** `MCP-Bastion`
   - **Workflow:** `publish-mcp.yml`
4. Add. PyPI will verify on the next publish.
