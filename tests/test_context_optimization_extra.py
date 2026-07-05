"""Additional coverage for context optimization pillars."""

import time
from unittest import mock

import pytest

from mcp_bastion.errors import GroundingViolationError
from mcp_bastion.pillars.grounding_guard import GroundingGuard
from mcp_bastion.pillars.output_budget import OutputBudget
from mcp_bastion.pillars.session_offload import SessionOffloadStore
from mcp_bastion.pillars import tokens as tokens_mod
from mcp_bastion.pillars.tokens import count_text_tokens, estimate_text_tokens


def test_session_offload_ttl_expiry():
    store = SessionOffloadStore(ttl_seconds=0.01)
    key = store.put("x", session_id="s1")
    time.sleep(0.02)
    assert store.get(key, session_id="s1") is None


def test_session_offload_evicts_oldest_at_capacity():
    store = SessionOffloadStore(max_entries_per_session=2, ttl_seconds=60)
    k1 = store.put("one", session_id="s1")
    time.sleep(0.001)
    store.put("two", session_id="s1")
    k3 = store.put("three", session_id="s1")
    assert store.get(k1, session_id="s1") is None
    assert store.get(k3, session_id="s1") == "three"


def test_session_offload_rejects_invalid_config():
    with pytest.raises(ValueError):
        SessionOffloadStore(ttl_seconds=0)
    with pytest.raises(ValueError):
        SessionOffloadStore(max_entries_per_session=0)


def test_output_budget_passes_non_text_items():
    ob = OutputBudget(max_output_tokens=10, min_tokens=1)
    content = [{"type": "image", "data": "abc"}, {"type": "text", "text": "ok"}]
    out, summary = ob.process_content_items(content)
    assert out[0]["type"] == "image"
    assert summary.applied is False


def test_output_budget_rejects_invalid_config():
    with pytest.raises(ValueError):
        OutputBudget(max_output_tokens=0)


def test_grounding_guard_extract_paths():
    guard = GroundingGuard(on_violation="warn")
    paths = guard.extract_paths("See src/auth/login.py and README.md")
    assert any("login.py" in p or "README.md" in p for p in paths)


def test_grounding_guard_invalid_action():
    with pytest.raises(ValueError):
        GroundingGuard(on_violation="invalid")  # type: ignore[arg-type]


def test_grounding_guard_empty_text():
    guard = GroundingGuard(on_violation="block")
    assert guard.check_text("").violations == []


def test_tokens_tiktoken_path_when_available():
    enc = mock.Mock()
    enc.encode.return_value = [1, 2, 3]
    with mock.patch.object(tokens_mod, "_get_tiktoken_encoder", return_value=enc):
        assert count_text_tokens("hello") == 3
        assert estimate_text_tokens("hello") == 3


def test_tokens_tiktoken_fallback_on_encode_error():
    enc = mock.Mock()
    enc.encode.side_effect = RuntimeError("boom")
    with mock.patch.object(tokens_mod, "_get_tiktoken_encoder", return_value=enc):
        assert count_text_tokens("abcd") == 1
