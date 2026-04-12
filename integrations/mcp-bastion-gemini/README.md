# mcp-bastion-gemini

Security middleware for Google Gemini powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-gemini
```

## Usage

```python
from mcp_bastion_gemini import SecureGemini

client = SecureGemini(api_key="YOUR_KEY")
print(client.chat("What is MCP?"))
```

## Features

- Content filtering and prompt injection detection
- Rate limiting per caller
- PII redaction

## License

MIT
