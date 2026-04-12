# mcp-bastion-llamaindex

Security middleware for LlamaIndex powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-llamaindex
```

## Usage

```python
from mcp_bastion_llamaindex import SecureLlamaIndex

guard = SecureLlamaIndex()
guard.scan_query("What is the revenue for Q4?")
```

## Features

- Content filtering on RAG queries and responses
- Rate limiting per caller
- Prompt injection detection

## License

MIT
