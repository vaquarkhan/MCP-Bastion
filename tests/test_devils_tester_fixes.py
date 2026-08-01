"""Compat shims, alert placeholders, and red-team attribution fixes."""

from __future__ import annotations

import pytest

from mcp_bastion.config import _resolve_optional_url, load_config
from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter
from mcp_bastion.redteam import _blocking_pillar, _CASES


def test_resolve_optional_url_skips_unresolved_placeholder(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    assert _resolve_optional_url("${SLACK_WEBHOOK_URL}") is None


def test_resolve_optional_url_expands_env(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
    assert _resolve_optional_url("${SLACK_WEBHOOK_URL}") == "https://hooks.slack.com/services/T/B/X"


def test_load_config_skips_placeholder_alert_sinks(tmp_path, monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("BASTION_WEBHOOK_URL", raising=False)
    cfg_path = tmp_path / "bastion.yaml"
    cfg_path.write_text(
        "alerts:\n  slack_webhook: ${SLACK_WEBHOOK_URL}\n  webhook_url: ${BASTION_WEBHOOK_URL}\n",
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    assert cfg.alerts_slack_webhook is None
    assert cfg.alerts_webhook_url is None


def test_rate_limiter_compat_api():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    limiter.check()
    limiter.check()
    with pytest.raises(RateLimitExceededError):
        limiter.check()


def test_content_filter_scan_alias():
    cf = ContentFilter(block_code_execution=False, block_file_paths=False, block_secrets=False)
    cf.scan("please summarize this document")


def test_redteam_rate_limit_case_avoids_repeat_fp():
    case = next(c for c in _CASES if c.id == "rate_limit_bypass_01")
    assert case.arguments.get("q") != "repeat"
    assert "catalog" in str(case.arguments.get("q", "")).lower() or case.arguments.get("q")


def test_blocking_pillar_attribution():
    assert _blocking_pillar(PromptInjectionError()) == "prompt_guard"
    assert _blocking_pillar(RateLimitExceededError()) == "rate_limit"
