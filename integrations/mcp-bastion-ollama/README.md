# mcp-bastion-ollama

Security middleware for **Ollama** powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

MCP-Bastion security middleware for Ollama local models (OpenAI-compatible API).

## Install

```bash
pip install mcp-bastion-ollama
```

## Usage

```python
from mcp_bastion_ollama import SecureOllama

client = SecureOllama()  # default http://localhost:11434/v1
print(client.chat("What is MCP?", model="llama3.2"))
```

## Features

- Content filtering on prompts / messages
- Rate limiting per caller
- Prompt injection heuristics (via MCP-Bastion core)
- Pulls in `mcp-bastion-python` automatically

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).

