# Branch, commit, and tag commands for MCP-Bastion
# Run from repo root: c:\Users\Administrator\Downloads\MCP-Bastion

# 1. Create and switch to a new branch
git checkout -b feature/tutorial-and-validation

# 2. Stage all changes
git add -A

# 3. Review what will be committed
git status

# 4. Commit (adjust message if needed)
git commit -m "docs: update tutorials, validation checklist, .gitignore; fix CLI tests for logging"

# 5. Tag the release (version 1.0.8 - match pyproject.toml / package.json)
git tag -a v1.0.8 -m "Release 1.0.8: tutorials, policy-as-code docs, validation checklist, .gitignore"

# Optional: push branch and tag
# git push -u origin feature/tutorial-and-validation
# git push origin v1.0.8
