# mcp-bastion-crewai

Security middleware for CrewAI powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-crewai
```

## Usage

```python
from mcp_bastion_crewai import SecureCrewAI

guard = SecureCrewAI()
guard.scan_task("Summarize the quarterly report")
```

## Features

- Content filtering on agent tasks and outputs
- Rate limiting per caller
- Prompt injection detection

## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Commercial deployment requires a separate agreement ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
