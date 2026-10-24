# mcp-bastion-bedrock

Security middleware for AWS Bedrock powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

Protects your Bedrock API calls from prompt injection, PII leakage, and resource exhaustion.

## Install

```bash
pip install mcp-bastion-bedrock
```

## Usage

```python
from mcp_bastion_bedrock import SecureBedrock

client = SecureBedrock(region_name="us-east-1")
response = client.chat("What is MCP?")
print(response)
```

## Features

- Content filtering on all prompts
- Rate limiting per caller
- Prompt injection detection
- PII redaction

## License

Licensed under the [Apache License 2.0](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Commercial and non-commercial use are both permitted.
