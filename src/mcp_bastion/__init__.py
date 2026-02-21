"""
MCP-Bastion: Security middleware for Model Context Protocol servers.
"""

from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.base import Middleware, MiddlewareContext, compose_middleware

__all__ = [
    "MCPBastionMiddleware",
    "Middleware",
    "MiddlewareContext",
    "compose_middleware",
]
__version__ = "1.0.0"
