"""
Tool-level RBAC for MCP-Bastion.

Block unauthorized tool access before execution.
Essential for multi-tenant MCP servers.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_bastion.errors import RBACError

logger = logging.getLogger(__name__)


class RBAC:
    """
    Role-based access control for tools.

    Maps role/agent to allowed tool names. Use "*" for all tools.
    """

    def __init__(self, permissions: dict[str, list[str]]) -> None:
        """
        permissions: { "role_name": ["tool1", "tool2", "*"] }
        """
        self.permissions = permissions
        self._default_role = "default"

    def _get_role(self, context: Any) -> str:
        """Extract role from context. Override for custom resolution."""
        if hasattr(context, "metadata") and isinstance(context.metadata, dict):
            return str(context.metadata.get("role", context.metadata.get("agent", self._default_role)))
        if hasattr(context, "role"):
            return str(context.role)
        return self._default_role

    def check(self, tool: str, context: Any) -> None:
        """
        Check if role can access tool. Raises RBACError if not allowed.
        """
        role = self._get_role(context)
        allowed = self.permissions.get(role, self.permissions.get(self._default_role, []))

        if not allowed:
            logger.warning("rbac blocked role=%s tool=%s no_permissions", role, tool)
            raise RBACError(f"Role '{role}' has no tool permissions")

        if "*" in allowed:
            return

        if tool not in allowed:
            logger.warning("rbac blocked role=%s tool=%s", role, tool)
            raise RBACError(f"Role '{role}' cannot access tool '{tool}'")
