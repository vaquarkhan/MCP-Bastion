# mcp-bastion-groq

Security middleware for Groq powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-groq
```

## Usage

```python
from mcp_bastion_groq import SecureGroq

client = SecureGroq()  # uses GROQ_API_KEY from env
print(client.chat("What is MCP?"))
```

## Features

- Content filtering and prompt injection detection
- Rate limiting per caller
- PII redaction

## License

MIT
