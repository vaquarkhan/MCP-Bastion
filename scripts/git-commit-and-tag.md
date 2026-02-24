# Branch, commit, and tag commands for MCP-Bastion
# Run from repo root: c:\Users\Administrator\Downloads\MCP-Bastion

# 1. Create and switch to a new branch (or skip to use current branch)
git checkout -b feature/dashboard-docs-and-error-handling

# 2. Stage all changes
git add -A

# 3. Review what will be committed
git status

# 4. Commit (include version bump)
git commit -m "chore: bump version to 1.0.9 (PyPI, npm, server.json)

- pyproject.toml, src/mcp_bastion/__init__.py (Python/PyPI)
- package.json, packages/core/package.json (npm)
- server.json (MCP registry)"

# 5. Tag for release
git tag -a v1.0.9 -m "Release 1.0.9"

# Push branch and tag
# git push -u origin feature/dashboard-docs-and-error-handling
# git push origin v1.0.9
