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

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
