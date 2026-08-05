# mcp-bastion-openai-agents

Security helpers for **OpenAI Agents SDK** powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

MCP-Bastion security helpers for OpenAI Agents SDK tools and messages.

## Install

```bash
pip install mcp-bastion-openai-agents
```

## Usage

```python
from mcp_bastion_openai_agents import SecureOpenAIAgents, secure_tool

guard = SecureOpenAIAgents()
guard.check_message("user or tool text")

@secure_tool
def lookup(query: str) -> str:
    return query
```

## Features

- In-process content filter + injection heuristics
- Rate limiting per caller
- Thin adapter only — does not change MCP-Bastion's zero-infra nature
- Pulls in `mcp-bastion-python` automatically

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).

