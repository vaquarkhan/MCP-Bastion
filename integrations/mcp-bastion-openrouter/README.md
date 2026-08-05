# mcp-bastion-openrouter

Security middleware for **OpenRouter** powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

MCP-Bastion security middleware for OpenRouter (multi-model gateway).

## Install

```bash
pip install mcp-bastion-openrouter
```

## Usage

```python
from mcp_bastion_openrouter import SecureOpenRouter

client = SecureOpenRouter()  # uses OPENROUTER_API_KEY
print(client.chat("What is MCP?"))
```

## Features

- Content filtering on prompts / messages
- Rate limiting per caller
- Prompt injection heuristics (via MCP-Bastion core)
- Pulls in `mcp-bastion-python` automatically

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).

