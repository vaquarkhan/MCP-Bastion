# mcp-bastion-together

Security middleware for Together AI powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-together
```

## Usage

```python
from mcp_bastion_together import SecureTogether

client = SecureTogether(api_key="YOUR_KEY")
print(client.chat("What is MCP?"))
```

## License

MIT
