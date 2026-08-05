# mcp-bastion-pydantic-ai

Security helpers for **Pydantic AI** powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

MCP-Bastion security helpers for Pydantic AI agent prompts and tool args.

## Install

```bash
pip install mcp-bastion-pydantic-ai
```

## Usage

```python
from mcp_bastion_pydantic_ai import SecurePydanticAI

guard = SecurePydanticAI()
guard.check_prompt("Summarize this ticket")
guard.check_tool_args({"path": "README.md"})
```

## Features

- In-process content filter + injection heuristics
- Rate limiting per caller
- Thin adapter only — does not change MCP-Bastion's zero-infra nature
- Pulls in `mcp-bastion-python` automatically

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).

