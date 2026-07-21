"""Tests for behavioral fingerprint monitor."""

from __future__ import annotations

import pytest

from mcp_bastion.errors import BehaviorAnomalyError
from mcp_bastion.pillars.behavior_fingerprint import BehaviorFingerprintMonitor
from mcp_bastion.pillars.state_backend import MemoryStateBackend


def test_learn_phase_no_anomaly():
    monitor = BehaviorFingerprintMonitor(learn_min_calls=5, freeze_after_calls=6, backend=MemoryStateBackend())
    for i in range(4):
        result = monitor.check_and_record("scope-a", f"tool_{i % 2}")
        assert result.anomalous is False


def test_tool_drift_detected_after_baseline():
    monitor = BehaviorFingerprintMonitor(
        learn_min_calls=4,
        freeze_after_calls=6,
        drift_window=3,
        tool_overlap_threshold=0.25,
        backend=MemoryStateBackend(),
    )
    for _ in range(10):
        monitor.check_and_record("scope-drift", "read_docs")
    for _ in range(2):
        monitor.check_and_record("scope-drift", "delete_user")
    result = monitor.check_and_record("scope-drift", "delete_user")
    assert result.anomalous is True
    assert result.kind == "tool_drift"


def test_rate_spike_detected():
    monitor = BehaviorFingerprintMonitor(
        learn_min_calls=2,
        freeze_after_calls=3,
        rate_spike_multiplier=3.0,
        backend=MemoryStateBackend(),
    )
    monitor.check_and_record("scope-rate", "api_call")
    monitor.check_and_record("scope-rate", "api_call")
    results = [monitor.check_and_record("scope-rate", "api_call") for _ in range(20)]
    assert any(r.anomalous and r.kind == "rate_spike" for r in results)


def test_shared_backend_across_monitors():
    backend = MemoryStateBackend()
    a = BehaviorFingerprintMonitor(learn_min_calls=2, freeze_after_calls=3, backend=backend)
    b = BehaviorFingerprintMonitor(learn_min_calls=2, freeze_after_calls=3, backend=backend)
    a.check_and_record("shared", "t1")
    a.check_and_record("shared", "t1")
    b.check_and_record("shared", "t1")
    assert b._load_state("shared").get("total_calls") == 3


def test_invalid_config():
    with pytest.raises(ValueError):
        BehaviorFingerprintMonitor(learn_min_calls=1)


def test_behavior_anomaly_error_code():
    assert BehaviorAnomalyError().code == -32031


def test_load_config_behavior_fingerprint_defaults_off(tmp_path):
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    from mcp_bastion.config import load_config

    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text("audit:\n  enabled: false\n", encoding="utf-8")
    cfg = load_config(str(yaml_path))
    assert cfg.behavior_fingerprint is False
    assert cfg.behavior_fingerprint_audit_metrics is True
