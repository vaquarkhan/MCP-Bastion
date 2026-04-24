"""Tests for integrated red-team harness."""

import pytest
from unittest import mock

import mcp_bastion.redteam as redteam_mod
from mcp_bastion.config import BastionConfig
from mcp_bastion.redteam import RedTeamCase, run_redteam_sync


@pytest.fixture(autouse=True)
def _redteam_light_config() -> None:
    """Avoid lazy-loading Presidio/torch (PII) and Prompt Guard models during the harness run."""
    cfg = BastionConfig(
        prompt_guard=False,
        pii=False,
    )
    with mock.patch("mcp_bastion.redteam.load_config", return_value=cfg):
        yield


def test_run_redteam_sync_returns_report():
    report = run_redteam_sync(None)
    assert "score_blocked_pct" in report
    assert "results" in report
    assert report["totals"]["attempts"] >= 1
    assert "mcp_top10_summary" in report
    assert isinstance(report["mcp_top10_summary"], dict)


def test_run_redteam_skips_empty_mcp_top10_in_summary():
    extra = (
        RedTeamCase(
            id="no_tag_case",
            owasp_tag="LLM99",
            mcp_top10="",
            tool="search",
            arguments={"q": "x"},
        ),
    )
    with mock.patch.object(redteam_mod, "_CASES", redteam_mod._CASES + extra):
        report = run_redteam_sync(None)
    assert isinstance(report["mcp_top10_summary"], dict)
