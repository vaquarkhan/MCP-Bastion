"""MCP-Bastion security integration for LangChain."""

__version__ = "4.0.0"

from mcp_bastion_langchain.callback import BastionSecurityCallback
from mcp_bastion_langchain.wrapper import secure_tool

__all__ = [
    "BastionSecurityCallback",
    "secure_tool",
]
