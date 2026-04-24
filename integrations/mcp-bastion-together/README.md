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

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
