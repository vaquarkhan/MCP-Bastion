"""
Resolve FinOps budget principals for rate/cost caps.

Client-supplied session_id must not be the sole key for spend caps — otherwise
rotating session_id bypasses denial-of-wallet limits.
"""

from __future__ import annotations

from typing import Any

AUTHENTICATED_ROLE_KEY = "bastion_authenticated_role"


def mark_authenticated_role(context: Any, *, role: str | None = None) -> None:
    """Mark context metadata role as server-verified (Agent IAM / edge auth)."""
    if not hasattr(context, "metadata") or not isinstance(context.metadata, dict):
        return
    context.metadata[AUTHENTICATED_ROLE_KEY] = True
    if role:
        context.metadata["role"] = role


def resolve_budget_principal(context: Any, *, default_tenant_id: str = "default") -> tuple[str, str]:
    """
    Return (principal_id, tenant_id) for cost/rate aggregation.

    Unauthenticated traffic for a tenant shares one anonymous principal so
    session_id rotation cannot reset caps.
    """
    md = getattr(context, "metadata", None) or {}
    tenant = str(md.get("tenant_id") or default_tenant_id)

    agent_id = md.get("agent_id")
    if agent_id:
        return f"agent:{agent_id}", tenant

    if md.get(AUTHENTICATED_ROLE_KEY):
        role = str(md.get("role") or md.get("agent") or "authenticated")
        return f"role:{role}", tenant

    return f"anonymous:{tenant}", tenant
