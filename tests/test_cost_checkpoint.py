"""Tests for cost tracker disk checkpoint."""

import json
from pathlib import Path

import pytest

from mcp_bastion.pillars.cost_tracker import CostTracker


def test_cost_checkpoint_persists_session_totals(tmp_path: Path):
    checkpoint = tmp_path / "cost.json"
    tracker = CostTracker(
        max_cost_per_session=10.0,
        max_cost_per_day=100.0,
        checkpoint_path=checkpoint,
    )
    tracker.record(1.25, session_id="sess-a")
    tracker2 = CostTracker(
        max_cost_per_session=10.0,
        max_cost_per_day=100.0,
        checkpoint_path=checkpoint,
    )
    tracker2.check(session_id="sess-a")
    data = json.loads(checkpoint.read_text(encoding="utf-8"))
    assert data["sessions"]["sess-a"]["cost"] == pytest.approx(1.25)


def test_cost_checkpoint_skipped_with_shared_backend(tmp_path: Path):
    from unittest.mock import MagicMock

    backend = MagicMock()
    checkpoint = tmp_path / "should-not-write.json"
    tracker = CostTracker(
        max_cost_per_session=1.0,
        checkpoint_path=checkpoint,
        backend=backend,
    )
    tracker.record(0.1, session_id="s")
    backend.set_json.assert_called()
    assert not checkpoint.exists()
