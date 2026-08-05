# mcp-bastion-autogen

Security middleware for **Microsoft AutoGen** powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

MCP-Bastion security helpers for Microsoft AutoGen / Agent Framework tool messages.

## Install

```bash
pip install mcp-bastion-autogen
```

## Usage

```python
from mcp_bastion_autogen import SecureAutoGen

guard = SecureAutoGen()
guard.check_message("Summarize this ticket")  # raises on injection / rate limit
```

## Features

- Content filtering on prompts / messages
- Rate limiting per caller
- Prompt injection heuristics (via MCP-Bastion core)
- Pulls in `mcp-bastion-python` automatically

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).

