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

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Commercial deployment requires a separate agreement ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
