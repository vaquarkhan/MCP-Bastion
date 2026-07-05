"""
MCP-Bastion: Security middleware for Model Context Protocol servers.
"""

from mcp_bastion.base import Middleware, MiddlewareContext, compose_middleware
from mcp_bastion.config import BastionConfig, load_config, build_middleware_from_config
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
    "BastionConfig",
    "build_middleware_from_config",
    "CircuitBreaker",
    "ContentFilter",
    "load_config",
    "MCPBastionMiddleware",
    "Middleware",
    "MiddlewareContext",
    "compose_middleware",
]
__version__ = "2.0.1"
