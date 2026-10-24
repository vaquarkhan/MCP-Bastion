# mcp-bastion-deepseek

Security middleware for DeepSeek AI powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-deepseek
```

## Usage

```python
from mcp_bastion_deepseek import SecureDeepSeek

client = SecureDeepSeek(api_key="YOUR_KEY")
print(client.chat("What is MCP?"))
```

## License

Licensed under the [Apache License 2.0](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Commercial and non-commercial use are both permitted.
