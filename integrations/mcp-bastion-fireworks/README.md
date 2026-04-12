# mcp-bastion-fireworks

Security middleware for Fireworks AI powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-fireworks
```

## Usage

```python
from mcp_bastion_fireworks import SecureFireworks

client = SecureFireworks(api_key="YOUR_KEY")
print(client.chat("What is MCP?"))
```

## License

MIT
