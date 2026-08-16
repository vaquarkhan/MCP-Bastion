import asyncio

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import ConcurrencyLimitError, LoadShedError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.concurrency import ConcurrencyLimiter


def test_o1_caller_and_tenant_admission_and_release():
    limiter = ConcurrencyLimiter(max_inflight_per_caller=1, max_inflight_per_tenant=2)
    assert limiter.try_acquire("alice", "t1") == "admit"
    assert limiter.try_acquire("alice", "t1") == "concurrency_limit"
    assert limiter.try_acquire("bob", "t1") == "admit"
    assert limiter.try_acquire("carol", "t1") == "concurrency_limit"
    limiter.release("alice", "t1")
    assert limiter.try_acquire("carol", "t1") == "admit"


def test_nonzero_queue_depth_sheds_without_unbounded_wait():
    limiter = ConcurrencyLimiter(
        max_inflight_per_caller=1,
        max_inflight_per_tenant=1,
        admission_queue_depth=1,
    )
    assert limiter.try_acquire("alice", "t1") == "admit"
    assert limiter.try_acquire("bob", "t1") == "load_shed"


@pytest.mark.asyncio
async def test_middleware_limits_and_releases_in_finally():
    limiter = ConcurrencyLimiter(max_inflight_per_caller=1, max_inflight_per_tenant=2)
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_concurrency=True,
        concurrency_limiter=limiter,
    )
    entered = asyncio.Event()
    unblock = asyncio.Event()

    async def handler(_ctx):
        entered.set()
        await unblock.wait()
        return {"ok": True}

    def context() -> MiddlewareContext:
        return MiddlewareContext(
            message={"method": "tools/call", "params": {"name": "read", "arguments": {}}},
            metadata={"principal_id": "alice", "tenant_id": "t1"},
        )

    first = asyncio.create_task(mw(context(), handler))
    await entered.wait()
    with pytest.raises(ConcurrencyLimitError) as exc:
        await mw(context(), handler)
    assert exc.value.code == -32044
    unblock.set()
    await first
    assert limiter.inflight("alice", "t1") == (0, 0)


@pytest.mark.asyncio
async def test_middleware_load_shed_error_code():
    limiter = ConcurrencyLimiter(
        max_inflight_per_caller=1,
        max_inflight_per_tenant=1,
        admission_queue_depth=1,
    )
    assert limiter.try_acquire("alice", "t1") == "admit"
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_concurrency=True,
        concurrency_limiter=limiter,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "read", "arguments": {}}},
        metadata={"principal_id": "bob", "tenant_id": "t1"},
    )
    with pytest.raises(LoadShedError) as exc:
        await mw(ctx, lambda _ctx: None)
    assert exc.value.code == -32045
    limiter.release("alice", "t1")
