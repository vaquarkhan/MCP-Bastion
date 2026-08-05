# mcp-bastion-langgraph

Security helpers for **LangGraph** powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

MCP-Bastion security helpers for LangGraph nodes and tool calls.

## Install

```bash
pip install mcp-bastion-langgraph
```

## Usage

```python
from mcp_bastion_langgraph import secure_node, BastionGraphGuard

@secure_node
def my_tool_node(state):
    return {"out": state["query"]}

guard = BastionGraphGuard()
guard.check_text(state.get("query", ""))
```

## Features

- In-process content filter + injection heuristics
- Rate limiting per caller
- Thin adapter only — does not change MCP-Bastion's zero-infra nature
- Pulls in `mcp-bastion-python` automatically

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).

