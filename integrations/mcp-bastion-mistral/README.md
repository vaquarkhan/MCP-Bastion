# mcp-bastion-mistral

Security middleware for Mistral AI powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-mistral
```

## Usage

```python
from mcp_bastion_mistral import SecureMistral

client = SecureMistral(api_key="YOUR_KEY")
print(client.chat("What is MCP?"))
```

## Features

- Content filtering and prompt injection detection
- Rate limiting per caller
- PII redaction

## License

MIT
