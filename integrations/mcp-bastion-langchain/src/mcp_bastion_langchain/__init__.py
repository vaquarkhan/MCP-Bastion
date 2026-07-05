"""MCP-Bastion security integration for LangChain."""

__version__ = "2.0.1"

from mcp_bastion_langchain.callback import BastionSecurityCallback
from mcp_bastion_langchain.wrapper import secure_tool

__all__ = [
    "BastionSecurityCallback",
    "secure_tool",
]
