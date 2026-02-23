"""Tests for audit log middleware."""

import pytest

from mcp_bastion.base import MiddlewareContext, compose_middleware
from mcp_bastion.pillars.audit_log import AuditEntry, AuditLogMiddleware


def test_audit_entry_to_dict():
    entry = AuditEntry(
        timestamp="2026-01-01T00:00:00Z",
        session_id="s1",
        request_id="r1",
        tool="add",
        action="ALLOWED",
        reason=None,
        latency_ms=10.5,
        tokens_used=100,
        error_code=None,
    )
    d = entry.to_dict()
    assert d["tool"] == "add"
    assert d["action"] == "ALLOWED"
    assert d["latency_ms"] == 10.5


def test_audit_entry_to_json():
    entry = AuditEntry(
        timestamp="2026-01-01T00:00:00Z",
        session_id=None,
        request_id=None,
        tool="test",
        action="BLOCKED",
        reason="rate limit",
    )
    s = entry.to_json()
    assert "test" in s
    assert "BLOCKED" in s


@pytest.mark.asyncio
async def test_audit_log_passthrough_non_tool_call():
    """Non-tool messages pass through without audit."""
    entries = []

    def capture(e):
        entries.append(e)

    audit = AuditLogMiddleware(export_callback=capture)
    ctx = MiddlewareContext(message={"method": "ping"}, request_id="r1")

    async def handler(c):
        return "ok"

    result = await audit(ctx, handler)
    assert result == "ok"
    assert len(entries) == 0


@pytest.mark.asyncio
async def test_audit_log_allowed_tool_call():
    """Tool call allowed logs ALLOWED."""
    entries = []

    def capture(e):
        entries.append(e)

    audit = AuditLogMiddleware(export_callback=capture)
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "add", "arguments": {}}},
        request_id="r1",
        session_id="s1",
    )

    async def handler(c):
        return {"result": 5}

    result = await audit(ctx, handler)
    assert result == {"result": 5}
    assert len(entries) == 1
    assert entries[0].tool == "add"
    assert entries[0].action == "ALLOWED"
    assert entries[0].reason is None


@pytest.mark.asyncio
async def test_audit_log_blocked_tool_call():
    """Tool call blocked logs BLOCKED with reason."""
    entries = []

    def capture(e):
        entries.append(e)

    audit = AuditLogMiddleware(export_callback=capture)
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "bad"}},
        request_id="r1",
    )

    async def handler(c):
        raise ValueError("blocked")

    with pytest.raises(ValueError):
        await audit(ctx, handler)

    assert len(entries) == 1
    assert entries[0].action == "BLOCKED"
    assert "blocked" in (entries[0].reason or "")


@pytest.mark.asyncio
async def test_audit_log_export_callback_failure():
    """Export callback failure does not raise."""
    audit = AuditLogMiddleware(export_callback=lambda e: (_ for _ in ()).throw(ValueError("export fail")))
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x"}},
    )

    async def handler(c):
        return "ok"

    result = await audit(ctx, handler)
    assert result == "ok"


@pytest.mark.asyncio
async def test_audit_log_captures_tokens_from_metadata():
    """Audit log reads tokens_used from context.metadata."""
    entries = []

    def capture(e):
        entries.append(e)

    audit = AuditLogMiddleware(export_callback=capture)
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x"}},
    )
    ctx.metadata["tokens_used"] = 500

    async def handler(c):
        return "ok"

    await audit(ctx, handler)
    assert entries[0].tokens_used == 500


@pytest.mark.asyncio
async def test_audit_log_include_tokens_false():
    """Audit log excludes tokens when include_tokens=False."""
    entries = []

    def capture(e):
        entries.append(e)

    audit = AuditLogMiddleware(export_callback=capture, include_tokens=False)
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x"}},
    )
    ctx.metadata["tokens_used"] = 500

    async def handler(c):
        return "ok"

    await audit(ctx, handler)
    assert entries[0].tokens_used == 0


@pytest.mark.asyncio
async def test_audit_log_message_with_root():
    """Audit log handles message with .root attribute."""
    from types import SimpleNamespace

    entries = []

    def capture(e):
        entries.append(e)

    audit = AuditLogMiddleware(export_callback=capture)
    msg = SimpleNamespace(root={"method": "tools/call", "params": {"name": "from_root"}})
    ctx = MiddlewareContext(message=msg)

    async def handler(c):
        return "ok"

    await audit(ctx, handler)
    assert entries[0].tool == "from_root"


@pytest.mark.asyncio
async def test_audit_log_message_with_method_attr():
    """Audit log handles message with .method attribute."""
    from types import SimpleNamespace

    entries = []

    def capture(e):
        entries.append(e)

    audit = AuditLogMiddleware(export_callback=capture)
    msg = SimpleNamespace(method="tools/call", params=SimpleNamespace(name="attr_tool"))
    ctx = MiddlewareContext(message=msg)

    async def handler(c):
        return "ok"

    await audit(ctx, handler)
    assert entries[0].tool == "attr_tool"


@pytest.mark.asyncio
async def test_audit_log_message_unknown_tool():
    """Audit log returns unknown when tool name cannot be extracted."""
    from types import SimpleNamespace

    entries = []

    def capture(e):
        entries.append(e)

    audit = AuditLogMiddleware(export_callback=capture)
    msg = SimpleNamespace(method="tools/call", params=SimpleNamespace())
    ctx = MiddlewareContext(message=msg)

    async def handler(c):
        return "ok"

    await audit(ctx, handler)
    assert entries[0].tool == "unknown"


@pytest.mark.asyncio
async def test_audit_log_blocked_captures_error_code():
    """Audit log captures error_code from MCPBastionError."""
    from mcp_bastion.errors import RateLimitExceededError

    entries = []

    def capture(e):
        entries.append(e)

    audit = AuditLogMiddleware(export_callback=capture)
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x"}},
    )

    async def handler(c):
        raise RateLimitExceededError("limit")

    with pytest.raises(RateLimitExceededError):
        await audit(ctx, handler)

    assert entries[0].error_code == -32002
