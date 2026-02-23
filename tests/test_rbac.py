"""Tests for RBAC pillar."""

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import RBACError
from mcp_bastion.pillars.rbac import RBAC


def test_rbac_allows_tool_in_role():
    """Role with tool permission is allowed."""
    rbac = RBAC({"admin": ["read", "write"], "viewer": ["read"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "admin"})
    rbac.check("read", ctx)
    rbac.check("write", ctx)


def test_rbac_blocks_tool_not_in_role():
    """Role without tool permission is blocked."""
    rbac = RBAC({"admin": ["read", "write"], "viewer": ["read"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "viewer"})
    rbac.check("read", ctx)
    with pytest.raises(RBACError, match="cannot access tool 'write'"):
        rbac.check("write", ctx)


def test_rbac_wildcard_allows_all():
    """Wildcard allows all tools."""
    rbac = RBAC({"super": ["*"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "super"})
    rbac.check("any_tool", ctx)
    rbac.check("other", ctx)


def test_rbac_no_permissions_raises():
    """Role with no permissions raises."""
    rbac = RBAC({"admin": ["read"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "unknown"})
    with pytest.raises(RBACError, match="no tool permissions"):
        rbac.check("read", ctx)


def test_rbac_uses_agent_fallback():
    """Uses agent from metadata when role missing."""
    rbac = RBAC({"agent_a": ["read"]})
    ctx = MiddlewareContext(message={}, metadata={"agent": "agent_a"})
    rbac.check("read", ctx)


def test_rbac_context_no_metadata_no_role():
    """Uses default role when context has no metadata or role."""
    rbac = RBAC({"default": ["read"]})

    class Ctx:
        pass

    rbac.check("read", Ctx())


def test_rbac_context_role_attr():
    """Uses context.role when metadata missing."""
    rbac = RBAC({"admin": ["read"]})

    class Ctx:
        role = "admin"

    rbac.check("read", Ctx())


def test_rbac_default_role():
    """Default role used when metadata empty."""
    rbac = RBAC({"default": ["read"]})
    ctx = MiddlewareContext(message={}, metadata={})
    rbac.check("read", ctx)
