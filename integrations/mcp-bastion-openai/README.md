# mcp-bastion-openai

Security middleware for OpenAI powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

Protects your OpenAI API calls from prompt injection, PII leakage, and resource exhaustion.

## Install

```bash
pip install mcp-bastion-openai
```

## Usage

```python
from mcp_bastion_openai import SecureOpenAI

client = SecureOpenAI()  # uses OPENAI_API_KEY from env
response = client.chat("What is MCP?")
print(response)
```

## Features

- Content filtering on all prompts
- Rate limiting per caller
- Prompt injection detection
- PII redaction

## License

MIT
