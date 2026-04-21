"""Tenant resolution helpers for multi-tenant Bastion deployments."""

from __future__ import annotations

from typing import Any

from mcp_bastion.base import MiddlewareContext


def resolve_tenant_id(context: MiddlewareContext[Any], default_tenant: str = "default") -> str:
    """
    Resolve tenant ID from context metadata/message/session.

    Precedence:
    1) context.metadata["tenant_id"]
    2) message params metadata.tenant_id or params.tenant_id
    3) session_id prefix "tenant:<id>|..."
    4) default_tenant
    """
    md_tid = context.metadata.get("tenant_id")
    if isinstance(md_tid, str) and md_tid.strip():
        return md_tid.strip()

    msg = context.message.root if hasattr(context.message, "root") else context.message
    if isinstance(msg, dict):
        params = msg.get("params") or {}
        if isinstance(params, dict):
            p_tid = params.get("tenant_id")
            if isinstance(p_tid, str) and p_tid.strip():
                return p_tid.strip()
            meta = params.get("metadata")
            if isinstance(meta, dict):
                m_tid = meta.get("tenant_id")
                if isinstance(m_tid, str) and m_tid.strip():
                    return m_tid.strip()

    sid = context.session_id or ""
    if sid.startswith("tenant:"):
        rest = sid[len("tenant:") :]
        token = rest.split("|", 1)[0].strip()
        if token:
            return token

    return default_tenant
