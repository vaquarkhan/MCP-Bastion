"""
MCP-Bastion: Security middleware for Model Context Protocol servers.
Author: Viquar Khan
"""

from mcp_bastion.base import Middleware, MiddlewareContext, compose_middleware
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars import (
    AuditEntry,
    AuditLogMiddleware,
    CircuitBreaker,
    ContentFilter,
)

__all__ = [
    "AuditEntry",
    "AuditLogMiddleware",
    "CircuitBreaker",
    "ContentFilter",
    "MCPBastionMiddleware",
    "Middleware",
    "MiddlewareContext",
    "compose_middleware",
]
__version__ = "1.0.0"
