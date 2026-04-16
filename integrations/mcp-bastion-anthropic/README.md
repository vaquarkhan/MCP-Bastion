# mcp-bastion-anthropic

Security middleware for Anthropic Claude powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

Protects your Claude API calls from prompt injection, PII leakage, and resource exhaustion.

## Install

```bash
pip install mcp-bastion-anthropic
```

## Usage

```python
from mcp_bastion_anthropic import SecureClaude

client = SecureClaude()  # uses ANTHROPIC_API_KEY from env
response = client.chat("What is MCP?")
print(response)
```

## Features

- Content filtering on all prompts
- Rate limiting per caller
- Prompt injection detection
- PII redaction

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Commercial deployment requires a separate agreement ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
