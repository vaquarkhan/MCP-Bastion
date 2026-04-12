# mcp-bastion-huggingface

Security middleware for Hugging Face powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-huggingface
```

## Usage

```python
from mcp_bastion_huggingface import SecureHuggingFace

client = SecureHuggingFace(api_key="YOUR_KEY")
print(client.chat("What is MCP?"))
```

## License

MIT
