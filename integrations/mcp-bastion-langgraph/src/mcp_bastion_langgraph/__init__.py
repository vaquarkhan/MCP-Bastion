"""MCP-Bastion security integration for LangGraph."""
__version__ = "4.0.0"
from mcp_bastion_langgraph.middleware import BastionGraphGuard, secure_node
__all__ = ["secure_node", "BastionGraphGuard"]
