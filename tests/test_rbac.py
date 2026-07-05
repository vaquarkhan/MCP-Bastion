"""Tests for RBAC pillar."""

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import RBACError
from mcp_bastion.pillars.rbac import RBAC


def test_rbac_allows_tool_in_role():
    """Role with tool permission is allowed."""
    rbac = RBAC({"admin": ["read", "write"], "viewer": ["read"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "admin", "bastion_authenticated_role": True})
    rbac.check("read", ctx)
    rbac.check("write", ctx)


def test_rbac_blocks_tool_not_in_role():
    """Role without tool permission is blocked."""
    rbac = RBAC({"admin": ["read", "write"], "viewer": ["read"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "viewer", "bastion_authenticated_role": True})
    rbac.check("read", ctx)
    with pytest.raises(RBACError, match="cannot access tool 'write'"):
        rbac.check("write", ctx)


def test_rbac_wildcard_allows_all():
    """Wildcard allows all tools."""
    rbac = RBAC({"super": ["*"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "super", "bastion_authenticated_role": True})
    rbac.check("any_tool", ctx)
    rbac.check("other", ctx)


def test_rbac_no_permissions_raises():
    """Role with no permissions raises."""
    rbac = RBAC({"admin": ["read"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "unknown", "bastion_authenticated_role": True})
    with pytest.raises(RBACError, match="no tool permissions"):
        rbac.check("read", ctx)


def test_rbac_uses_agent_fallback():
    """Uses agent from metadata when role missing."""
    rbac = RBAC({"agent_a": ["read"]})
    ctx = MiddlewareContext(message={}, metadata={"agent": "agent_a", "bastion_authenticated_role": True})
    rbac.check("read", ctx)


def test_rbac_context_no_metadata_no_role():
    """Uses default role when context has no metadata or role (legacy dev mode)."""
    rbac = RBAC({"default": ["read"]}, require_authenticated_identity=False)

    class Ctx:
        pass

    rbac.check("read", Ctx())


def test_rbac_blocks_self_asserted_role():
    rbac = RBAC({"admin": ["*"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "admin"})
    with pytest.raises(RBACError, match="authenticated identity"):
        rbac.check("any_tool", ctx)


def test_rbac_context_role_attr():
    """Uses context.role when metadata missing (legacy dev mode)."""
    rbac = RBAC({"admin": ["read"]}, require_authenticated_identity=False)

    class Ctx:
        role = "admin"

    rbac.check("read", Ctx())


def test_rbac_default_role():
    """Default role used when metadata empty (legacy dev mode)."""
    rbac = RBAC({"default": ["read"]}, require_authenticated_identity=False)
    ctx = MiddlewareContext(message={}, metadata={})
    rbac.check("read", ctx)


def test_rbac_fnmatch_glob():
    """Fnmatch globs allow prefix patterns."""
    rbac = RBAC({"reader": ["read_*"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "reader", "bastion_authenticated_role": True})
    rbac.check("read_file", ctx)
    with pytest.raises(RBACError, match="cannot access tool"):
        rbac.check("write_file", ctx)


def test_rbac_prefers_specific_glob():
    """More specific glob wins over broader pattern in same role."""
    rbac = RBAC({"ops": ["*", "read_*"]})
    ctx = MiddlewareContext(message={}, metadata={"role": "ops", "bastion_authenticated_role": True})
    rbac.check("read_config", ctx)
    rbac.check("delete_all", ctx)
