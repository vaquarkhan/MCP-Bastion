# CI examples for MCP-Bastion

## This repository

Pull requests and pushes to `main` run [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml): `mcp-bastion validate` on `bastion.yaml.example`, **`pytest` with ≥92% coverage** on `src/mcp_bastion`, and `npm test` for the monorepo.

## Your project — Bastion only

`mcp-bastion validate` confirms your **`bastion.yaml` loads cleanly** (syntax and known keys) — a fast gate to catch typos and invalid policy before deploy.

Add this to your repo to run validation on every pull request (install policy extras; use PyPI `mcp-bastion-python`):

```yaml
# .github/workflows/bastion-policy.yml (in your repo)
name: Bastion policy

on:
  pull_request:
  push:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install "mcp-bastion-python[policy]"
      - run: mcp-bastion validate --config bastion.yaml
```

Commit `bastion.yaml` at the repository root or pass `--config path/to/bastion.yaml`.

## Your project — MCP Test Harness + Bastion (recommended)

**[mcp-test-harness](https://github.com/vaquarkhan/mcp-test-harness)** is our sister product: it quality-gates your MCP *server* (tools, schemas, contract). Bastion quality-gates *policy* and *runtime* (validate, redteam, enforce, attest).

Use them together:

| Stage | Product | What it proves |
|-------|---------|----------------|
| 1 | mcp-test-harness | Server behavior / schema / regressions |
| 2 | Bastion `validate` + `redteam` | Policy loads; attack corpus vs your config |
| 3 | Bastion middleware / `serve` | Runtime enforcement in process |
| 4 | Bastion `attest` | Signed evidence for auditors |

Copy [`mcp-quality-and-bastion.yml`](./mcp-quality-and-bastion.yml) into `.github/workflows/`, or see the full walkthrough: [Bastion + MCP Test Harness](../../docs/BASTION_AND_TEST_HARNESS.md).
