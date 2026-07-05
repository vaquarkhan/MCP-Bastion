"""Tests for integrated red-team harness."""

import pytest
from unittest import mock

import mcp_bastion.redteam as redteam_mod
from mcp_bastion.config import BastionConfig
from mcp_bastion.errors import PromptGuardUnavailableError
from mcp_bastion.redteam import RedTeamCase, _is_guard_unavailable_block, run_redteam_sync


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
    assert "score_intended_blocked_pct" in report
    assert "score_guard_unavailable_pct" in report
    assert "results" in report
    assert report["totals"]["attempts"] >= 1
    assert "blocked_intended" in report["totals"]
    assert "mcp_top10_summary" in report
    assert isinstance(report["mcp_top10_summary"], dict)


def test_is_guard_unavailable_block():
    assert _is_guard_unavailable_block(PromptGuardUnavailableError()) is True
    assert _is_guard_unavailable_block(Exception("PromptGuard ML model unavailable")) is True
    assert _is_guard_unavailable_block(Exception("rate limit exceeded")) is False


def test_run_redteam_classifies_guard_unavailable(monkeypatch):
    cfg = BastionConfig(prompt_guard=False, pii=False)

    async def fake_middleware(ctx, handler):
        raise PromptGuardUnavailableError()

    with mock.patch("mcp_bastion.redteam.load_config", return_value=cfg):
        with mock.patch("mcp_bastion.redteam.build_middleware_from_config", return_value=fake_middleware):
            with mock.patch.object(redteam_mod, "_CASES", redteam_mod._CASES[:1]):
                report = run_redteam_sync(None)
    assert report["totals"]["blocked_guard_unavailable"] == 1
    assert report["totals"]["blocked_intended"] == 0
    assert report["score_intended_blocked_pct"] == 0.0
    assert report["interpretation"]


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
