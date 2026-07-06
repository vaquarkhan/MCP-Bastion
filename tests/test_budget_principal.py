"""Coverage for FinOps principal resolution (budget_principal)."""

from __future__ import annotations

from types import SimpleNamespace

from mcp_bastion.pillars.budget_principal import (
    AUTHENTICATED_ROLE_KEY,
    mark_authenticated_role,
    resolve_budget_principal,
)


def test_mark_authenticated_role_no_metadata_is_noop():
    ctx = SimpleNamespace()
    mark_authenticated_role(ctx, role="admin")
    assert not hasattr(ctx, "metadata")


def test_mark_authenticated_role_non_dict_metadata_is_noop():
    ctx = SimpleNamespace(metadata="not-a-dict")
    mark_authenticated_role(ctx, role="admin")
    assert ctx.metadata == "not-a-dict"


def test_mark_authenticated_role_sets_flag_and_role():
    ctx = SimpleNamespace(metadata={})
    mark_authenticated_role(ctx, role="analyst")
    assert ctx.metadata[AUTHENTICATED_ROLE_KEY] is True
    assert ctx.metadata["role"] == "analyst"


def test_mark_authenticated_role_flag_only():
    ctx = SimpleNamespace(metadata={})
    mark_authenticated_role(ctx)
    assert ctx.metadata[AUTHENTICATED_ROLE_KEY] is True
    assert "role" not in ctx.metadata


def test_resolve_budget_principal_agent_id():
    ctx = SimpleNamespace(metadata={"agent_id": "support_bot", "tenant_id": "acme"})
    assert resolve_budget_principal(ctx) == ("agent:support_bot", "acme")


def test_resolve_budget_principal_authenticated_role():
    ctx = SimpleNamespace(
        metadata={
            AUTHENTICATED_ROLE_KEY: True,
            "role": "viewer",
            "tenant_id": "t1",
        }
    )
    assert resolve_budget_principal(ctx) == ("role:viewer", "t1")


def test_resolve_budget_principal_authenticated_agent_fallback():
    ctx = SimpleNamespace(
        metadata={
            AUTHENTICATED_ROLE_KEY: True,
            "agent": "ops",
        }
    )
    assert resolve_budget_principal(ctx) == ("role:ops", "default")


def test_resolve_budget_principal_anonymous_per_tenant():
    ctx = SimpleNamespace(metadata={"tenant_id": "tenant-x"})
    assert resolve_budget_principal(ctx) == ("anonymous:tenant-x", "tenant-x")


def test_resolve_budget_principal_no_metadata():
    ctx = SimpleNamespace()
    assert resolve_budget_principal(ctx, default_tenant_id="fallback") == (
        "anonymous:fallback",
        "fallback",
    )
