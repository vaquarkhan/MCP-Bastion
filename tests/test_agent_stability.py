"""Tests for agent stability monitor (repetitive loop detection)."""

from __future__ import annotations

import pytest

from mcp_bastion.errors import AgentLoopDetectedError
from mcp_bastion.pillars.agent_stability import AgentStabilityMonitor
from mcp_bastion.pillars.state_backend import MemoryStateBackend


def test_stability_no_repeat_on_varied_outputs():
    monitor = AgentStabilityMonitor(window_size=5, repeat_threshold=3, backend=MemoryStateBackend())
    for i in range(4):
        result = monitor.check_and_record("scope-1", f"unique output number {i}")
        assert result.repetitive is False


def test_stability_detects_identical_outputs():
    monitor = AgentStabilityMonitor(
        window_size=5,
        repeat_threshold=3,
        similarity_threshold=0.92,
        backend=MemoryStateBackend(),
    )
    text = "Error: connection refused to api.example.com port 443"
    for _ in range(2):
        assert monitor.check_and_record("scope-2", text).repetitive is False
    third = monitor.check_and_record("scope-2", text)
    assert third.repetitive is True
    assert third.similarity >= 0.92


def test_stability_shared_backend_across_instances():
    backend = MemoryStateBackend()
    a = AgentStabilityMonitor(repeat_threshold=2, backend=backend)
    b = AgentStabilityMonitor(repeat_threshold=2, backend=backend)
    msg = "same error again and again"
    a.check_and_record("shared-scope", msg)
    result = b.check_and_record("shared-scope", msg)
    assert result.repetitive is True


def test_inject_hint_into_result_appends_content():
    result = {"content": [{"type": "text", "text": "original"}]}
    updated = AgentStabilityMonitor.inject_hint_into_result(result, "change strategy")
    assert len(updated["content"]) == 2
    assert updated["content"][-1]["text"] == "change strategy"


def test_stability_invalid_config():
    with pytest.raises(ValueError):
        AgentStabilityMonitor(window_size=1)
    with pytest.raises(ValueError):
        AgentStabilityMonitor(repeat_threshold=1)


def test_agent_loop_error_code():
    err = AgentLoopDetectedError()
    assert err.code == -32030


def test_stability_blank_observation_skipped():
    monitor = AgentStabilityMonitor(repeat_threshold=2, backend=MemoryStateBackend())
    result = monitor.check_and_record("scope-blank", "   \n\t  ")
    assert result.repetitive is False
    assert result.window_size == 0


def test_stability_near_duplicate_jaccard():
    monitor = AgentStabilityMonitor(
        repeat_threshold=2,
        similarity_threshold=0.5,
        backend=MemoryStateBackend(),
    )
    a = "error connection refused api example com port 443 timeout"
    b = "error connection refused api example com port 443 timed out"
    monitor.check_and_record("scope-jaccard", a)
    result = monitor.check_and_record("scope-jaccard", b)
    assert result.similarity >= 0.5


def test_inject_hint_nested_result_wrapper():
    wrapped = {"result": {"content": [{"type": "text", "text": "inner"}]}}
    updated = AgentStabilityMonitor.inject_hint_into_result(wrapped, "hint")
    assert updated["result"]["content"][-1]["text"] == "hint"


def test_inject_hint_non_dict_passthrough():
    assert AgentStabilityMonitor.inject_hint_into_result("plain", "hint") == "plain"
