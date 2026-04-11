# mcp-bastion-langchain

Security middleware for LangChain powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

Protects your LangChain agents from prompt injection, PII leakage, and resource exhaustion.

## Install

```bash
pip install mcp-bastion-langchain
```

## Usage

### Callback (automatic protection)

```python
from langchain_openai import ChatOpenAI
from mcp_bastion_langchain import BastionSecurityCallback

llm = ChatOpenAI(callbacks=[BastionSecurityCallback()])
llm.invoke("Hello, what is MCP?")
```

### Tool decorator

```python
from mcp_bastion_langchain import secure_tool

@secure_tool
def my_tool(query: str) -> str:
    return f"Result for {query}"
```

## Features

- Content filtering on all LLM prompts and tool inputs
- Rate limiting per caller
- Prompt injection detection
- PII redaction

## License

MIT
