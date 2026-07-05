"""Tests for grounding guard pillar."""

from pathlib import Path

import pytest

from mcp_bastion.errors import GroundingViolationError
from mcp_bastion.pillars.grounding_guard import GroundingGuard


def test_grounding_guard_allows_existing_file(tmp_path):
    real = tmp_path / "src" / "app.py"
    real.parent.mkdir(parents=True)
    real.write_text("print('ok')", encoding="utf-8")
    guard = GroundingGuard(workspace_root=tmp_path, on_violation="block")
    guard.check_text("Edit src/app.py for the change")


def test_grounding_guard_blocks_fake_path(tmp_path):
    guard = GroundingGuard(workspace_root=tmp_path, on_violation="block")
    with pytest.raises(GroundingViolationError):
        guard.check_text("See src/nonexistent_fake_file.py for details")


def test_grounding_guard_strip_redacts(tmp_path):
    guard = GroundingGuard(workspace_root=tmp_path, on_violation="strip")
    out, result = guard.process_content_items(
        [{"type": "text", "text": "Open src/missing.py now"}]
    )
    assert result.violations
    assert "[ungrounded-path-removed]" in out[0]["text"]


def test_grounding_guard_warn_does_not_raise(tmp_path):
    guard = GroundingGuard(workspace_root=tmp_path, on_violation="warn")
    result = guard.check_text("src/ghost.py")
    assert result.violations
