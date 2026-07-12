"""MCP-Bastion security integration for LangChain."""

__version__ = "3.1.1"

from mcp_bastion_langchain.callback import BastionSecurityCallback
from mcp_bastion_langchain.wrapper import secure_tool

__all__ = [
    "BastionSecurityCallback",
    "secure_tool",
]
