"""Tests for pluggable shared state (memory + Redis backend wiring)."""

from unittest import mock

import pytest

from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter, SessionState
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.state_backend import MemoryStateBackend, RedisStateBackend, build_state_backend


def test_memory_backend_set_nx_rejects_duplicate():
    backend = MemoryStateBackend()
    assert backend.set_nx("nonce:abc", "1", ttl_seconds=30.0) is True
    assert backend.set_nx("nonce:abc", "1", ttl_seconds=30.0) is False


def test_memory_backend_set_add_respects_max_size():
    backend = MemoryStateBackend()
    assert backend.set_add("session_tools:s1", "tool_a", max_size=2) is True
    assert backend.set_add("session_tools:s1", "tool_a", max_size=2) is True
    assert backend.set_add("session_tools:s1", "tool_b", max_size=2) is True
    assert backend.set_add("session_tools:s1", "tool_c", max_size=2) is False


def test_memory_backend_json_roundtrip():
    backend = MemoryStateBackend()
    backend.set_json("key1", {"a": 1, "b": "two"})
    data = backend.get_json("key1")
    assert data == {"a": 1, "b": "two"}


def test_memory_backend_delete_clears_key():
    backend = MemoryStateBackend()
    backend.set("k", "v")
    assert backend.get("k") == "v"
    backend.delete("k")
    assert backend.get("k") is None


def test_memory_backend_ttl_expires(monkeypatch):
    backend = MemoryStateBackend()
    times = iter([0.0, 0.0, 100.0])
    monkeypatch.setattr("mcp_bastion.pillars.state_backend.time.monotonic", lambda: next(times))
    backend.set("k", "v", ttl_seconds=10.0)
    assert backend.get("k") == "v"
    assert backend.get("k") is None


def test_memory_backend_set_nx_after_expiry(monkeypatch):
    backend = MemoryStateBackend()
    times = iter([0.0, 100.0])
    monkeypatch.setattr("mcp_bastion.pillars.state_backend.time.monotonic", lambda: next(times))
    assert backend.set_nx("k", "v1", ttl_seconds=5.0) is True
    assert backend.set_nx("k", "v2", ttl_seconds=5.0) is True
    assert backend.get("k") == "v2"


def test_memory_backend_set_contains():
    backend = MemoryStateBackend()
    backend.set_add("set:k", "member")
    assert backend.set_contains("set:k", "member") is True
    assert backend.set_contains("set:k", "other") is False


def test_memory_backend_get_json_invalid():
    backend = MemoryStateBackend()
    backend.set("j", "not-json")
    assert backend.get_json("j") is None
    backend.set("d", '{"a": 1}')
    assert backend.get_json("d") == {"a": 1}


def test_shared_rate_limiter_across_instances():
    backend = MemoryStateBackend()
    a = TokenBucketRateLimiter(max_iterations=2, timeout_seconds=120, backend=backend)
    b = TokenBucketRateLimiter(max_iterations=2, timeout_seconds=120, backend=backend)
    a.consume_iteration(session_id="shared")
    check = b.check_iteration(session_id="shared")
    assert check.allowed
    a.consume_iteration(session_id="shared")
    check2 = b.check_iteration(session_id="shared")
    assert not check2.allowed


def test_rate_limit_session_state_serialization():
    state = SessionState(iterations=3, tokens_used=100, tool_iterations={"read": 2})
    restored = SessionState.from_dict(state.to_dict())
    assert restored.iterations == 3
    assert restored.tokens_used == 100
    assert restored.tool_iterations["read"] == 2


def test_shared_replay_guard_across_instances():
    backend = MemoryStateBackend()
    g1 = ReplayGuard(require_nonce=True, max_request_age_seconds=0, backend=backend)
    g2 = ReplayGuard(require_nonce=True, max_request_age_seconds=0, backend=backend)
    msg = {"params": {"nonce": "n-once"}}
    g1.check(msg)
    with pytest.raises(Exception):
        g2.check(msg)


def test_shared_cost_tracker_across_instances():
    backend = MemoryStateBackend()
    c1 = CostTracker(max_cost_per_session=1.0, max_cost_per_day=10.0, backend=backend)
    c2 = CostTracker(max_cost_per_session=1.0, max_cost_per_day=10.0, backend=backend)
    c1.record(1.0, session_id="s-cost")
    with pytest.raises(Exception):
        c2.check(session_id="s-cost")


def test_build_state_backend_memory():
    backend = build_state_backend(backend="memory")
    assert isinstance(backend, MemoryStateBackend)


def test_build_state_backend_invalid_raises():
    with pytest.raises(ValueError, match="Unknown state_backend"):
        build_state_backend(backend="dynamodb")


def test_build_state_backend_redis_requires_package():
    with mock.patch.dict("sys.modules", {"redis": None}):
        with pytest.raises(ImportError, match="redis"):
            build_state_backend(backend="redis")


def _fake_redis_module(client: mock.Mock | None = None) -> tuple[mock.Mock, mock.Mock]:
    """Build a stub ``redis`` module and client for tests without the redis package."""
    fake_client = client or mock.Mock()
    mod = mock.Mock()
    mod.Redis.from_url = mock.Mock(return_value=fake_client)
    return mod, fake_client


def test_redis_backend_ping():
    fake_client = mock.Mock()
    fake_client.ping.return_value = True
    fake_client.get.return_value = None
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        assert backend.ping() is True


def test_redis_backend_set_nx():
    fake_client = mock.Mock()
    fake_client.set.return_value = True
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        assert backend.set_nx("nonce:x", "1", ttl_seconds=60.0) is True
        fake_client.set.assert_called_once()


def test_redis_backend_get_set_delete():
    fake_client = mock.Mock()
    fake_client.get.return_value = "value"
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0", key_prefix="test")
        assert backend.get("k") == "value"
        backend.set("k2", "v2", ttl_seconds=30.0)
        fake_client.setex.assert_called()
        backend.delete("k")
        fake_client.delete.assert_called()


def test_redis_backend_set_add_with_max_size():
    fake_client = mock.Mock()
    fake_client.pipeline.return_value.execute.return_value = (False, 2)
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        assert backend.set_add("set:k", "m", max_size=2) is False


def test_redis_backend_set_contains_and_json():
    fake_client = mock.Mock()
    fake_client.sismember.return_value = True
    fake_client.get.return_value = '{"a": 1}'
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        assert backend.set_contains("set:k", "m") is True
        assert backend.get_json("j") == {"a": 1}


def test_redis_backend_ping_failure():
    fake_client = mock.Mock()
    fake_client.ping.side_effect = OSError("down")
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        assert backend.ping() is False


def test_redis_backend_set_add_existing_member():
    fake_client = mock.Mock()
    fake_client.pipeline.return_value.execute.return_value = (True, 5)
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        assert backend.set_add("set:k", "m", max_size=10) is True


def test_redis_backend_set_add_without_max_size():
    fake_client = mock.Mock()
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        assert backend.set_add("set:k", "m") is True
        fake_client.sadd.assert_called_once()


def test_redis_backend_set_nx_without_ttl():
    fake_client = mock.Mock()
    fake_client.set.return_value = True
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        assert backend.set_nx("nonce:y", "1") is True


def test_redis_backend_set_without_ttl():
    fake_client = mock.Mock()
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        backend.set("plain", "v")
        fake_client.set.assert_called_with("mcp-bastion:plain", "v")


def test_redis_backend_get_json_invalid():
    fake_client = mock.Mock()
    fake_client.get.return_value = "not-json"
    mod, _ = _fake_redis_module(fake_client)
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = RedisStateBackend("redis://localhost:6379/0")
        assert backend.get_json("j") is None


def test_build_state_backend_redis():
    mod, fake_client = _fake_redis_module()
    with mock.patch.dict("sys.modules", {"redis": mod}):
        backend = build_state_backend(backend="redis")
        assert isinstance(backend, RedisStateBackend)
