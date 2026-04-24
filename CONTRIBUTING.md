# Contributing to MCP-Bastion

Thank you for helping improve docs, examples, tests, and integrations. Small PRs are easier to review and ship quickly.

## Good first contributions

These usually need **no deep security internals** knowledge:

- **Documentation:** typos, clearer steps, new links in [docs/README.md](docs/README.md), [QUICK_START.md](docs/QUICK_START.md), or [DISCOVERY.md](docs/DISCOVERY.md).
- **Examples:** another `llm_*` stub, a minimal `bastion.yaml` recipe, or CI snippet under [examples/ci/](examples/ci/).
- **Tests:** coverage for edge cases; see `pytest --cov=mcp_bastion` in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

When opening an issue, ask maintainers to apply the **`good first issue`** label if the task fits—volunteers filter on that tag.

## Before you send a PR

1. Run **`pytest --cov=mcp_bastion --cov-fail-under=92`** (with `[dev,policy,dashboard]` installed) and **`npm test`** at the repo root.
2. Run **`mcp-bastion validate --config bastion.yaml.example`** if you touch policy loading.
3. Keep changes focused on one concern per PR.

## Maintainer note (labels)

Repository owners can create a **`good first issue`** label and apply it to small docs/test tasks to signal a welcoming backlog.
