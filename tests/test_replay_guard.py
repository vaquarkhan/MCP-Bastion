"""Tests for replay guard pillar."""

import pytest

from mcp_bastion.errors import ReplayAttackError
from mcp_bastion.pillars.replay_guard import ReplayGuard


def test_replay_guard_require_nonce_false_passthrough():
    """With require_nonce=False, no nonce needed."""
    rg = ReplayGuard(require_nonce=False)
    rg.check({"params": {}})


def test_replay_guard_require_nonce_missing():
    """With require_nonce=True, missing nonce raises."""
    rg = ReplayGuard(require_nonce=True)
    with pytest.raises(ReplayAttackError, match="nonce"):
        rg.check({"params": {}})


def test_replay_guard_accepts_unique_nonce():
    """Unique nonce passes."""
    rg = ReplayGuard(require_nonce=True)
    rg.check({"params": {"nonce": "n1"}})
    rg.check({"params": {"nonce": "n2"}})


def test_replay_guard_blocks_duplicate_nonce():
    """Duplicate nonce raises."""
    rg = ReplayGuard(require_nonce=True)
    rg.check({"params": {"nonce": "dup"}})
    with pytest.raises(ReplayAttackError, match="Duplicate nonce"):
        rg.check({"params": {"nonce": "dup"}})


def test_replay_guard_stale_timestamp():
    """Stale timestamp raises."""
    import time
    rg = ReplayGuard(require_nonce=False, max_request_age_seconds=10.0)
    old_ts = time.time() - 100
    with pytest.raises(ReplayAttackError, match="too old"):
        rg.check({"params": {"timestamp": old_ts}})


def test_replay_guard_get_nonce_returns_none():
    """_get_nonce returns None when params not dict."""
    rg = ReplayGuard(require_nonce=True)
    with pytest.raises(Exception, match="nonce"):
        rg.check({"params": "not_a_dict"})


def test_replay_guard_message_with_root():
    """Extracts nonce from message with root."""
    rg = ReplayGuard(require_nonce=True)
    msg = type("Msg", (), {"root": {"params": {"nonce": "n-root"}}})()
    rg.check(msg)


def test_replay_guard_timestamp_type_error():
    """Invalid timestamp type is ignored."""
    rg = ReplayGuard(require_nonce=False, max_request_age_seconds=10.0)
    rg.check({"params": {"timestamp": "not_a_number"}})


def test_replay_guard_timestamp_value_error():
    """Invalid timestamp value is ignored."""
    rg = ReplayGuard(require_nonce=False, max_request_age_seconds=10.0)
    rg.check({"params": {"timestamp": "invalid"}})


def test_replay_guard_future_timestamp_blocked():
    """Timestamp too far in future is blocked."""
    import time
    rg = ReplayGuard(require_nonce=False, max_request_age_seconds=10.0)
    future = time.time() + 120
    with pytest.raises(Exception, match="too old"):
        rg.check({"params": {"timestamp": future}})


def test_replay_guard_nonce_cache_eviction():
    """Nonce cache evicts when full."""
    rg = ReplayGuard(require_nonce=True, max_nonce_cache=2)
    rg.check({"params": {"nonce": "n1"}})
    rg.check({"params": {"nonce": "n2"}})
    rg.check({"params": {"nonce": "n3"}})
    rg.check({"params": {"nonce": "n1"}})


def test_replay_guard_extracts_nonce_from_id():
    """Uses id as nonce fallback."""
    rg = ReplayGuard(require_nonce=True)
    rg.check({"params": {"id": "req-123"}})
