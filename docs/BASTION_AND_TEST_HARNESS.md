# MCP-Bastion + MCP Test Harness (end-to-end)

You own **two complementary products**:

| Product | Role | Install |
|---------|------|---------|
| **[MCP Test Harness](https://github.com/vaquarkhan/mcp-test-harness)** (`mcp-test-harness`) | Deterministic **CI gate** for MCP servers — functional, performance, security payload packs, JUnit/SARIF | `pip install mcp-test-harness` · [docs site](https://vaquarkhan.github.io/mcp-test-harness/) |
| **[MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion)** (`mcp-bastion-python`) | **Runtime guardrail** — enforce `bastion.yaml` on every tool call; attest what fired | `pip install mcp-bastion-python` |

**Story no single competitor owns:** *test the MCP server in CI → red-team the Bastion policy → enforce the same policy at runtime → export attestation evidence.*

```text
┌─────────────────────────┐     ┌──────────────────────────┐
│  MCP Test Harness       │     │  MCP-Bastion             │
│  mcp-test (CI)          │     │  middleware + CLI        │
│  correctness / latency  │     │  bastion.yaml enforce    │
│  security payload packs │     │  redteam + attest        │
└───────────┬─────────────┘     └────────────┬─────────────┘
            │                                  │
            ▼                                  ▼
     Pass/fail + SARIF/JUnit            Blocks + session attest
            │                                  │
            └──────────► One PR evidence pack ◄─┘
```

## One-time setup

```bash
# Runtime guardrails
pip install "mcp-bastion-python[policy,dashboard]"

# CI test gate for your MCP server
pip install mcp-test-harness
```

Copy and edit policies:

```bash
cp bastion.yaml.example bastion.yaml
# Point Test Harness at your server (see harness quick start)
mcp-test init --server-command "python your_mcp_server.py"
```

## End-to-end pipeline (recommended CI)

### 1. Prove the MCP server still works (Test Harness)

```yaml
# .github/workflows/mcp-quality.yml (excerpt)
- name: MCP Test Harness
  uses: vaquarkhan/mcp-test-harness@v3
  with:
    config: mcp-test.yaml
    # uploads JUnit / SARIF per Action docs
```

Or CLI:

```bash
mcp-test --config mcp-test.yaml
```

Docs: [Harness CI & reports](https://github.com/vaquarkhan/mcp-test-harness/blob/main/docs/CI_AND_REPORTS.md) · Marketplace Action [`mcp-test-harness`](https://github.com/marketplace/actions/mcp-test-harness).

### 2. Prove Bastion policy blocks what it should (Bastion red-team)

Run the **integrated** OWASP/MCP-oriented pack against the **same** `bastion.yaml` you will deploy:

```bash
mcp-bastion validate --config bastion.yaml
mcp-bastion redteam --config bastion.yaml --output bastion-redteam.json
```

Interpret scores: [REDTEAM.md](REDTEAM.md).

### 3. Enforce at runtime (same policy)

Wrap your server (FastMCP example):

```python
from mcp_bastion.config import load_config, build_middleware_from_config
# or secure_fastmcp / serve --proxy — see QUICK_START.md
```

Or boundary mode without host cooperation:

```bash
mcp-bastion serve --proxy --config bastion.yaml
```

### 4. Export evidence (attestation)

After traffic (or a CI smoke session):

```bash
mcp-bastion attest export --session "$SESSION_ID" --output attest.json
# Optional HMAC: set BASTION_MANIFEST_SIGNING_KEY
```

Bundle for auditors: `bastion-redteam.json` + `attest.json` + Test Harness JUnit/SARIF + CycloneDX `bom.json` from release workflows ([SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)).

## Example GitHub Actions job (both products)

```yaml
name: MCP quality + Bastion policy
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install
        run: |
          pip install mcp-test-harness "mcp-bastion-python[policy]"
      - name: Test Harness (server correctness)
        run: mcp-test --config mcp-test.yaml
      - name: Bastion validate + redteam (policy)
        run: |
          mcp-bastion validate --config bastion.yaml
          mcp-bastion redteam --config bastion.yaml --output bastion-redteam.json
      - uses: actions/upload-artifact@v4
        with:
          name: bastion-policy-evidence
          path: bastion-redteam.json
```

## How responsibilities split

| Concern | Test Harness | Bastion |
|---------|--------------|---------|
| Tool schema / lifecycle / latency SLOs | ✅ | — |
| Deterministic security *payload* packs in CI | ✅ | Also `redteam` vs live middleware |
| Prompt injection / PII / rate / RBAC at runtime | — | ✅ |
| Session attestation / cost governance | — | ✅ |
| Multi-language MCP server tests | [mcp-test-suite](https://github.com/vaquarkhan/mcp-test-suite) | [mcp-bastion-suite](https://github.com/vaquarkhan/mcp-bastion-suite) adapters |

## Links

- Harness repo: https://github.com/vaquarkhan/mcp-test-harness  
- Harness site: https://vaquarkhan.github.io/mcp-test-harness/  
- Bastion red-team: [REDTEAM.md](REDTEAM.md) · CLI: [CLI.md](CLI.md)  
- Threat model: [THREAT_MODEL.md](THREAT_MODEL.md)
