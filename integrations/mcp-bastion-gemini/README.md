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

Licensed under the [Apache License 2.0](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Commercial and non-commercial use are both permitted.
