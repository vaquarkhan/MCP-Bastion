# MCP-Bastion Examples

Python examples demonstrating MCP-Bastion middleware integration.

---

## Files in examples/

All Python files in this folder:

| File | Purpose |
|------|---------|
| `examples/dashboard_demo.py` | Web dashboard with **rich seeded metrics** (KPIs, time series, forensics, alerts, **Insights & anomalies**  -  run with or without `--no-live`) |
| `examples/python_server_example.py` | Minimal middleware chain |
| `examples/full_demo.py` | All features demo (11 scenarios) |
| `examples/llm_server.py` | Shared MCP server for LLM clients |
| `examples/llm_openai_example.py` | OpenAI (ChatGPT, API, Agents SDK) |
| `examples/llm_claude_example.py` | Claude (Desktop, Code, API) |
| `examples/llm_gemini_example.py` | Gemini (CLI, AI Studio) |
| `examples/llm_mistral_example.py` | Mistral (Agents SDK) |
| `examples/llm_grok_example.py` | Grok (xAI, HTTP only) |
| `examples/server_with_config.py` | Policy-as-code (bastion.yaml) |
| `examples/bastion-runtime-governance-3.0.yaml` | Sample config for 3.0 runtime governance pillars |
| `examples/bastion-filesystem-guards.yaml` | Path/credential denies (`.env`, `.git/config`, keys, shell patterns) + secret redaction |
| `examples/filesystem_env_deny_demo.py` | Proof: allow README, deny `.env` / `.git/config` with filesystem guards |
| `examples/fixtures/tools-clean.json` | Clean tool catalog for `mcp-bastion scan` demos |
| `examples/fixtures/tools-poisoned.json` | Poisoned catalog (injection, homoglyph, secrets) for scan demos |
| `examples/ci/README.md` | CI: copy-paste workflow to validate `bastion.yaml` in your repository |

---

## Prerequisites

```bash
cd MCP-Bastion
pip install mcp mcp-bastion-python
# For PII redaction: pip install presidio-analyzer presidio-anonymizer
# python -m spacy download en_core_web_sm
```

---

## Dashboard demo (dummy metrics)

Runs the FastAPI dashboard (`dashboard/app.py`) in-process and fills `MetricsStore` with realistic fake traffic so you can validate charts, KPIs, and tables without a live MCP server.

**Install:** `pip install fastapi uvicorn` (or `pip install mcp-bastion-python[dashboard]`).

**Run**  -  repo root:

```bash
# Windows PowerShell
$env:PYTHONPATH="src"; python examples/dashboard_demo.py

# Linux / macOS
PYTHONPATH=src python examples/dashboard_demo.py
```

**Or** from `examples/` (paths are bootstrapped; no `PYTHONPATH` needed):

```bash
cd examples
python dashboard_demo.py
```

Open **http://127.0.0.1:7000/** (prefer `127.0.0.1` over `localhost` if metrics fail  -  IPv6 vs IPv4). The demo binds **127.0.0.1** by default so Windows can open the port reliably; use `--host 0.0.0.0` for LAN. If **7000** is busy, the script **tries 7001…7007** automatically. Use `--no-live` for a static snapshot only.

---

## Example 1: python_server_example.py

Minimal middleware chain setup. Shows how to create `MCPBastionMiddleware` and compose with custom middleware.

**Run:**

```bash
$env:PYTHONPATH="src"; python examples/python_server_example.py   # Windows
PYTHONPATH=src python examples/python_server_example.py          # Linux/Mac
```

**Code snippet:**

```python
from mcp_bastion import MCPBastionMiddleware, compose_middleware

bastion = MCPBastionMiddleware(
    enable_prompt_guard=True,
    enable_pii_redaction=True,
    enable_rate_limit=True,
)
middleware = compose_middleware(bastion, LoggingMiddleware())
```

---

## Example 2: full_demo.py

End-to-end demo of all MCP-Bastion features. Runs 11 scenarios:

| # | Feature | What it demonstrates |
|---|---------|------------------------|
| 1 | Allowed tool call | add(2, 3) succeeds |
| 2 | PII redaction | get_profile returns masked SSN, email |
| 3 | Rate limit | 6th call blocked at 5-iteration limit |
| 4 | Prompt injection | Malicious prompt blocked (needs torch) |
| 5 | Content filter | /etc/passwd path blocked |
| 6 | Circuit breaker | 4th failure opens circuit |
| 7 | RBAC | Viewer cannot call write tool |
| 8 | Schema validation | Missing arg b blocked |
| 9 | Replay guard | Duplicate nonce blocked |
| 10 | Cost tracker | Over-budget session blocked |
| 11 | Semantic cache | Similar query returns cached result |

**Run:**

```bash
$env:PYTHONPATH="src"; python examples/full_demo.py   # Windows
PYTHONPATH=src python examples/full_demo.py          # Linux/Mac
```

**Full deps for PII and prompt injection:**

```bash
pip install mcp-bastion-python torch presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_sm
```

---

## Example 3: LLM Integration

Shared server: `llm_server.py`. Entry points per LLM:

| File | LLM | Transport | Run |
|------|-----|-----------|-----|
| `examples/llm_openai_example.py` | OpenAI | stdio, HTTP | `python examples/llm_openai_example.py` |
| `examples/llm_claude_example.py` | Claude | stdio, HTTP | `python examples/llm_claude_example.py` |
| `examples/llm_gemini_example.py` | Gemini | stdio, HTTP | `python examples/llm_gemini_example.py` |
| `examples/llm_mistral_example.py` | Mistral | stdio, HTTP | `python examples/llm_mistral_example.py` |
| `examples/llm_grok_example.py` | Grok (xAI) | HTTP only | `python examples/llm_grok_example.py` |

**HTTP mode:** Add `--http 8000` to any example (except Grok, which defaults to HTTP on port 8000).

**Config:** See [docs/LLM_INTEGRATION.md](../docs/LLM_INTEGRATION.md) for copy-paste config for each LLM.

**Quick run (Windows):**

```bash
cd MCP-Bastion
$env:PYTHONPATH="src"
python examples/llm_openai_example.py
python examples/llm_claude_example.py
python examples/llm_gemini_example.py
python examples/llm_mistral_example.py
python examples/llm_grok_example.py
```

**Quick run (Linux/Mac):**

```bash
cd MCP-Bastion
export PYTHONPATH=src
python examples/llm_openai_example.py
python examples/llm_claude_example.py
python examples/llm_gemini_example.py
python examples/llm_mistral_example.py
python examples/llm_grok_example.py
```

## Example 4: server_with_config.py (policy-as-code)

Load middleware from `bastion.yaml` (or `BASTION_CONFIG` env):

```python
from mcp_bastion import load_config, build_middleware_from_config

# Option A: load config then build
config = load_config()  # or load_config("path/to/bastion.yaml")
middleware = build_middleware_from_config(config)

# Option B: one-liner (loads bastion.yaml and builds)
middleware = build_middleware_from_config()
```

**Run:**

```bash
$env:PYTHONPATH="src"; python examples/server_with_config.py   # Windows
PYTHONPATH=src python examples/server_with_config.py           # Linux/Mac
```

---

## All Features (from full_demo.py)

| Feature | Module | Description |
|---------|--------|-------------|
| Prompt injection | prompt_guard | Block jailbreaks, adversarial prompts |
| PII redaction | pii_redaction | Mask SSN, email, phone, etc. |
| Rate limiting | rate_limit | Max iterations, timeout, token budget |
| Audit logging | audit_log | Log who, what, when, blocked/allowed |
| Content filter | content_filter | Block paths/code/URLs with allowlist and denylist tuning |
| Circuit breaker | circuit_breaker | Disable failing tools after N failures |
| RBAC | rbac | Tool-level permissions by role |
| Schema validation | schema_validation | Validate tool input types |
| Replay guard | replay_guard | Block duplicate nonces |
| Cost tracker | cost_tracker | Per-session cost budget |
| Semantic cache | semantic_cache | Cache similar queries |
| Exfiltration canary (3.0) | canary_goallock | Block tool args that echo session canary token |
| ATR rules (3.0) | atr_rules | YAML threat rules + content filter merge |
| Secret redaction (3.0) | secrets.redact_patterns | Mask/hash/remove secrets in tool outputs |

---

## Runtime governance (3.0)

Sample policy: `examples/bastion-runtime-governance-3.0.yaml`

```bash
mcp-bastion validate --config examples/bastion-runtime-governance-3.0.yaml
mcp-bastion report --framework soc2 --audit .bastion/audit.jsonl
```

Docs: [docs/ENTERPRISE_RUNTIME_CONTROLS.md](../docs/ENTERPRISE_RUNTIME_CONTROLS.md)

---

## Next Steps

- [docs/LLM_INTEGRATION.md](../docs/LLM_INTEGRATION.md) – Config for OpenAI, Claude, Gemini, Mistral, Grok
- [VALIDATION_CHECKLIST.md](../VALIDATION_CHECKLIST.md) – Run enterprise validation
- [SETUP_GUIDE.md](../SETUP_GUIDE.md) – Full config and customization
