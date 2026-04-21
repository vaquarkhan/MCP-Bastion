# MCP-Bastion Examples

Python examples demonstrating MCP-Bastion middleware integration.

**Also try:** `mcp-bastion dashboard` for the live command-center UI, and `mcp-bastion redteam` for a JSON security report against your `bastion.yaml`. See [dashboard/README.md](../dashboard/README.md) and [docs/CLI.md](../docs/CLI.md).

---

## Files in examples/

All Python files in this folder:

| File | Purpose |
|------|---------|
| `examples/python_server_example.py` | Minimal middleware chain |
| `examples/full_demo.py` | All features demo (11 scenarios) |
| `examples/advanced_features_demo.py` | Semantic firewall, sensitive classifier, session tool limits, tool metadata guard |
| `examples/owasp_security_showcase.py` | OWASP MCP Top 10–style controls: secrets, allowlist, edge auth, replay; optional embedded red team |
| `examples/connect_any_mcp_tool_example.py` | Same middleware stack for arbitrary downstream tool names (`await bastion(ctx, downstream)`) |
| `examples/policy_simulator_example.py` | Shadow `simulate_policy()` on sample events (FinOps / policy tuning) |
| `examples/bastion.advanced.example.yaml` | Sample `bastion.yaml` with newer pillars enabled (merge or set `BASTION_CONFIG`) |
| `examples/llm_server.py` | Shared MCP server for LLM clients |
| `examples/llm_openai_example.py` | OpenAI (ChatGPT, API, Agents SDK) |
| `examples/llm_claude_example.py` | Claude (Desktop, Code, API) |
| `examples/llm_gemini_example.py` | Gemini (CLI, AI Studio) |
| `examples/llm_mistral_example.py` | Mistral (Agents SDK) |
| `examples/llm_grok_example.py` | Grok (xAI, HTTP only) |
| `examples/server_with_config.py` | Policy-as-code (bastion.yaml) |

---

## Prerequisites

```bash
cd MCP-Bastion
pip install mcp mcp-bastion-python
# For PII redaction: pip install presidio-analyzer presidio-anonymizer
# python -m spacy download en_core_web_sm
```

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
| Semantic firewall | semantic_firewall | Tool intent and dangerous tool chains |
| Sensitive classifier | sensitive_classifier | Unstructured sensitive business text |
| Tool metadata guard | middleware | Strip or block poisoned `tools/list` metadata |
| Session tool scope | middleware | Cap distinct tool names per session |
| Policy simulator | policy_simulator | Shadow replay of events (`simulate_policy`) |

---

## Example 5: advanced_features_demo.py

Runnable checks for pillars that shipped after the original `full_demo.py` scenarios:

| Step | Pillar | What you should see |
|------|--------|----------------------|
| 1 | Semantic firewall | `get_weather` with SQL-like args blocked |
| 2 | Sensitive classifier | Business-sensitive narrative blocked at a low threshold |
| 3 | Session limits | Third distinct tool name in the same session blocked |
| 4 | Tool metadata guard | Poisoned `tools/list` entry removed; only safe tools remain |

**Run:**

```bash
$env:PYTHONPATH="src"; python examples/advanced_features_demo.py   # Windows
PYTHONPATH=src python examples/advanced_features_demo.py          # Linux/Mac
```

**Policy-as-code:** copy [bastion.advanced.example.yaml](bastion.advanced.example.yaml) or point `BASTION_CONFIG` at it, then run `server_with_config.py` to load the same toggles from YAML.

---

## Example 6: policy_simulator_example.py

Async sample calling `simulate_policy()` with two synthetic events and `content_filter` enabled in overrides. Use this pattern in CI or notebooks to compare candidate YAML against exported forensics.

**Run:**

```bash
$env:PYTHONPATH="src"; python examples/policy_simulator_example.py
```

---

## Example 7: owasp_security_showcase.py (OWASP MCP Top 10)

Runnable demos aligned with [docs/OWASP_MCP_TOP10.md](../docs/OWASP_MCP_TOP10.md). The script exercises the **same** `MCPBastionMiddleware` path your MCP host uses; tool names are arbitrary strings (`tools/call`), so “any tool” is just configuration plus your downstream handler.

| OWASP MCP tag | Risk (short) | What this example shows | Bastion knobs (see doc for full list) |
|---------------|--------------|-------------------------|----------------------------------------|
| MCP01 | Token / secret mishandling | Payload with AWS-like key blocked | `content_filter.block_secrets`, PII, audit |
| MCP03 | Tool poisoning / shadow tools | Disallowed tool name blocked | `tool_allowlist`, `tool_metadata_guard`, schema |
| MCP05 / MCP06 | Injection / confused deputy | Several allowed tool names on one stack | Content filter, schema, semantic firewall, prompt guard |
| MCP07 | Weak edge auth | Missing vs valid metadata token | `edge_auth` |
| — | Replay / duplicate requests | Duplicate `nonce` blocked | `replay_guard` (pairs with audit / hash chain for MCP08-style assurance in [OWASP doc](../docs/OWASP_MCP_TOP10.md)) |

**Run:**

```bash
$env:PYTHONPATH="src"; python examples/owasp_security_showcase.py
```

**Full JSON report (recommended for CI):** `mcp-bastion redteam -c bastion.yaml -o redteam-report.json` — includes `mcp_top10_summary`.

**Optional embedded red team** (uses your loadable `bastion.yaml` / `BASTION_CONFIG`; can be slow):

```bash
$env:MCP_BASTION_OWASP_RUN_REDTO_TEAM="1"
$env:PYTHONPATH="src"; python examples/owasp_security_showcase.py
```

---

## Example 8: connect_any_mcp_tool_example.py

Shows the integration pattern: build `MCPBastionMiddleware` once, then for each `tools/call` wrap your **downstream** tool executor in `async def downstream(): ...` and invoke **`await bastion(ctx, downstream)`**. Tool names can be CRM, ERP, webhooks, or vendor-specific; policy (allowlist, firewall, etc.) applies uniformly.

**Run:**

```bash
$env:PYTHONPATH="src"; python examples/connect_any_mcp_tool_example.py
```

---

## Next Steps

- [docs/LLM_INTEGRATION.md](../docs/LLM_INTEGRATION.md): config for OpenAI, Claude, Gemini, Mistral, Grok
- [VALIDATION_CHECKLIST.md](../VALIDATION_CHECKLIST.md): run enterprise validation
- [SETUP_GUIDE.md](../SETUP_GUIDE.md): full config and customization
