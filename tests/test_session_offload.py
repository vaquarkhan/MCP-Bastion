"""Tests for session offload store."""

from mcp_bastion.pillars.session_offload import SessionOffloadStore


def test_session_offload_put_get():
    store = SessionOffloadStore()
    key = store.put("hello world", session_id="s1")
    assert store.get(key, session_id="s1") == "hello world"
    assert store.get(key, session_id="other") is None


def test_session_offload_stats():
    store = SessionOffloadStore()
    store.put("a", session_id="s1")
    assert store.stats(session_id="s1")["entries"] == 1
