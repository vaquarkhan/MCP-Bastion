# mcp-bastion-vertexai

Security middleware for Google Cloud Vertex AI powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

## Install

```bash
pip install mcp-bastion-vertexai
```

## Usage

```python
from mcp_bastion_vertexai import SecureVertexAI

client = SecureVertexAI(project="my-gcp-project", location="us-central1")
print(client.chat("What is MCP?"))
```

## License

MIT
