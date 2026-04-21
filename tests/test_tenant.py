"""Tests for tenant resolution helper."""

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.tenant import resolve_tenant_id


def test_resolve_tenant_from_metadata():
    ctx = MiddlewareContext(message={"method": "tools/call"}, metadata={"tenant_id": "acme"})
    assert resolve_tenant_id(ctx) == "acme"


def test_resolve_tenant_from_session_prefix():
    ctx = MiddlewareContext(message={"method": "tools/call"}, session_id="tenant:blue|s1")
    assert resolve_tenant_id(ctx) == "blue"


def test_resolve_tenant_falls_back_default():
    ctx = MiddlewareContext(message={"method": "tools/call"})
    assert resolve_tenant_id(ctx, "zzz") == "zzz"


def test_resolve_tenant_from_params_tenant_id():
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"tenant_id": "  from_params  ", "name": "x"}},
    )
    assert resolve_tenant_id(ctx) == "from_params"


def test_resolve_tenant_from_params_metadata():
    ctx = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"metadata": {"tenant_id": "nested"}, "name": "x"},
        },
    )
    assert resolve_tenant_id(ctx) == "nested"


def test_resolve_tenant_session_prefix_empty_token_falls_back():
    ctx = MiddlewareContext(message={"method": "tools/call"}, session_id="tenant:|rest")
    assert resolve_tenant_id(ctx, "fallback") == "fallback"
