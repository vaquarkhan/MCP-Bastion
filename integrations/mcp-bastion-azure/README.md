# mcp-bastion-azure

Security middleware for Azure OpenAI Service powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-azure
```

## Usage

```python
from mcp_bastion_azure import SecureAzureOpenAI

client = SecureAzureOpenAI(
    azure_endpoint="https://YOUR.openai.azure.com/",
    api_key="YOUR_KEY",
)
print(client.chat("What is MCP?"))
```

## License

MIT
