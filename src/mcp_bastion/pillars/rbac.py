"""
Tool-level RBAC for MCP-Bastion.

Block unauthorized tool access before execution.
Supports exact names, ``*`` wildcard, and fnmatch globs (e.g. ``files_read_*``).
"""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from mcp_bastion.errors import RBACError

logger = logging.getLogger(__name__)

_WILDCARDS = frozenset("*?[]")


def _pattern_specificity(pattern: str) -> int:
    return sum(1 for char in pattern if char not in _WILDCARDS)


class RBAC:
    """
    Role-based access control for tools.

    Maps role/agent to allowed tool names. Use "*" for all tools, or fnmatch
    globs such as ``read_*`` / ``files_read_*``.
    """

    def __init__(self, permissions: dict[str, list[str]], *, require_authenticated_identity: bool = True) -> None:
        """
        permissions: { "role_name": ["tool1", "read_*", "*"] }
        """
        self.permissions = permissions
        self._default_role = "default"
        self.require_authenticated_identity = require_authenticated_identity

    def _get_role(self, context: Any) -> str:
        """Extract role from context. Only trusts server-verified identities by default."""
        from mcp_bastion.pillars.budget_principal import AUTHENTICATED_ROLE_KEY

        if hasattr(context, "metadata") and isinstance(context.metadata, dict):
            md = context.metadata
            if md.get(AUTHENTICATED_ROLE_KEY):
                return str(md.get("role", md.get("agent", self._default_role)))
            if self.require_authenticated_identity:
                raise RBACError(
                    "RBAC blocked: role is not from an authenticated identity. "
                    "Enable agent_iam or edge_auth, or set rbac.require_authenticated_identity: false for dev."
                )
            return str(md.get("role", md.get("agent", self._default_role)))
        if hasattr(context, "role"):
            if self.require_authenticated_identity:
                raise RBACError("RBAC blocked: no authenticated identity on context")
            return str(context.role)
        if self.require_authenticated_identity:
            raise RBACError("RBAC blocked: no authenticated identity on context")
        return self._default_role

    def _tool_allowed(self, tool: str, allowed: list[str]) -> bool:
        if not allowed:
            return False
        if "*" in allowed:
            return True
        matches = [
            pattern
            for pattern in allowed
            if pattern == tool or fnmatch.fnmatchcase(tool, pattern)
        ]
        if not matches:
            return False
        # Prefer the most specific matching pattern (longest literal run).
        best = max(matches, key=_pattern_specificity)
        return best is not None

    def check(self, tool: str, context: Any) -> None:
        """
        Check if role can access tool. Raises RBACError if not allowed.
        """
        role = self._get_role(context)
        allowed = self.permissions.get(role, self.permissions.get(self._default_role, []))

        if not allowed:
            logger.warning("rbac blocked role=%s tool=%s no_permissions", role, tool)
            raise RBACError(f"Role '{role}' has no tool permissions")

        if not self._tool_allowed(tool, allowed):
            logger.warning("rbac blocked role=%s tool=%s", role, tool)
            raise RBACError(f"Role '{role}' cannot access tool '{tool}'")
