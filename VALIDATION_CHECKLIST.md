# MCP-Bastion Enterprise Validation Checklist

Validates build, security pillars (prompt injection, PII redaction, rate limiting), and latency. See `SETUP_GUIDE.md` for setup and `examples/README.md` for demos.

## Example Files

All Python files in `examples/`:

- `examples/python_server_example.py` - Minimal middleware
- `examples/full_demo.py` - All 11 features
- `examples/llm_server.py` - Shared LLM server
- `examples/llm_openai_example.py` - OpenAI
- `examples/llm_claude_example.py` - Claude
- `examples/llm_gemini_example.py` - Gemini
- `examples/llm_mistral_example.py` - Mistral
- `examples/llm_grok_example.py` - Grok (xAI)
- `examples/server_with_config.py` - Policy-as-code (bastion.yaml)

Run the automated validation:

```bash
cd MCP-Bastion
$env:PYTHONPATH="src"; python scripts/validate_checklist.py   # Windows
PYTHONPATH=src python scripts/validate_checklist.py          # Linux/Mac
```

## Checklist Results

| # | Item | Automated | Notes |
|---|------|-----------|-------|
| 1 | **Build and Installation** | Yes | `npm run build`, `pytest tests/` |
| 2 | **Protocol Interception (MCP Inspector)** | Manual | See below |
| 3 | **Security Pillar 1: Prompt Injection** | Yes | Benign passes; adversarial blocked (needs torch) |
| 4 | **Security Pillar 2: PII Redaction** | Yes | SSN, email, card masked (needs presidio) |
| 5 | **Security Pillar 3: Rate Limiting** | Yes | 16th call blocked at 15 limit |
| 6 | **Latency Benchmarking** | Yes | Proxy overhead < 5ms (excl. ML) |

## Test coverage

Python: run with coverage (fail_under set in pyproject.toml):

```bash
cd MCP-Bastion
$env:PYTHONPATH="src"; pytest tests/ -v --cov=src/mcp_bastion --cov-report=term-missing --cov-fail-under=92
```

Omitted from coverage: optional paths in pii_redaction and prompt_guard. TypeScript (from repo root, run `npm install` once so Vitest is available):

```bash
npm install
npm run test --workspace=@mcp-bastion/core
```

## 2. Protocol Interception (Manual)

Use the official MCP Inspector to validate JSON-RPC 2.0 and CallTool/ReadResource:

1. **Start a test server** (Python with FastMCP):

   ```bash
   pip install mcp mcp-bastion-python
   python examples/python_server_example.py   # Or a server that exposes HTTP/stdio
   ```

2. **Start MCP Inspector**:

   ```bash
   npx -y @modelcontextprotocol/inspector
   ```

3. **Connect** via stdio or HTTP (`http://localhost:8000/mcp` if using streamable-http).

4. **Verify**:
   - List tools – succeeds
   - Call tool with benign args (e.g. `add(2, 2)`) – succeeds
   - Call tool with "Ignore previous instructions" – blocked (Python + torch)
   - Response format is valid JSON-RPC 2.0

## Full Dependencies for All Tests

```bash
# Python
pip install mcp-bastion-python torch transformers presidio-analyzer presidio-anonymizer spacy
# Optional: pin latest tested release
pip install mcp-bastion-python==1.0.16
python -m spacy download en_core_web_sm

# Dev (for pytest async)
pip install pytest-asyncio
```

## Related Docs

- [SETUP_GUIDE.md](SETUP_GUIDE.md) – Full setup, config, and validation
- [examples/README.md](examples/README.md) – Example demos
- [NOTICE](NOTICE) – Third-party licenses
