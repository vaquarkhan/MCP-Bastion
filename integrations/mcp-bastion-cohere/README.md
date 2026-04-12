# mcp-bastion-cohere

Security middleware for Cohere powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-cohere
```

## Usage

```python
from mcp_bastion_cohere import SecureCohere

client = SecureCohere(api_key="YOUR_KEY")
print(client.chat("What is MCP?"))
```

## Features

- Content filtering and prompt injection detection
- Rate limiting per caller
- PII redaction

## License

MIT
