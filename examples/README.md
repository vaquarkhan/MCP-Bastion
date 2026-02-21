# MCP-Bastion Examples

Python examples demonstrating MCP-Bastion middleware integration.

## Prerequisites

```bash
cd MCP-Bastion
pip install mcp-bastion-python
# For full demo (PII, prompt injection): pip install torch presidio-analyzer presidio-anonymizer
# python -m spacy download en_core_web_sm
```

## Examples

### 1. python_server_example.py

**Purpose:** Minimal middleware chain setup.

Shows how to:
- Create `MCPBastionMiddleware` with all three pillars enabled
- Extend `Middleware` to add custom `LoggingMiddleware`
- Compose with `compose_middleware(bastion, LoggingMiddleware())`
- Wire the chain into your MCP server

**Run:**

```bash
$env:PYTHONPATH="src"; python examples/python_server_example.py   # Windows
PYTHONPATH=src python examples/python_server_example.py          # Linux/Mac
```

**Output:** Middleware chain created; ready to wire into your server.

---

### 2. full_demo.py

**Purpose:** End-to-end demo of all MCP-Bastion features.

Runs four scenarios:

| Demo | Description | Result |
|------|-------------|--------|
| 1 | Benign tool call `add(2, 3)` | Returns `5` |
| 2 | PII tool `get_profile` returns SSN, email | Redacted when Presidio installed |
| 3 | 6 rapid calls (limit 5) | 6th call blocked with `RateLimitExceededError` |
| 4 | Adversarial payload in tool args | Blocked with `PromptInjectionError` when torch installed |

**Run:**

```bash
$env:PYTHONPATH="src"; python examples/full_demo.py   # Windows
PYTHONPATH=src python examples/full_demo.py          # Linux/Mac
```

**Config:** Custom `TokenBucketRateLimiter(max_iterations=5, timeout_seconds=30)` for quick demo.

**Full deps for PII and prompt injection:**

```bash
pip install mcp-bastion-python torch presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_sm
```

---

## Next Steps

- [VALIDATION_CHECKLIST.md](../VALIDATION_CHECKLIST.md) – Run enterprise validation
- [SETUP_GUIDE.md](../SETUP_GUIDE.md) – Full config and LLM integration
