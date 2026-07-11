"""Tests for 3.0 runtime governance pillars."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock
import urllib.error

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.cli import cmd_report
from mcp_bastion.config import BastionConfig, build_middleware_from_config, load_config
from mcp_bastion.errors import (
    ATRRuleMatchError,
    CanaryExfiltrationError,
    ContentFilterError,
    LLMScannerBlockedError,
)
from mcp_bastion.middleware import MCPBastionMiddleware, _inject_canary_snippet_into_result
from mcp_bastion.pillars.atr_rules import ATRRuleLoader, _severity_rank
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.auto_repave import AutoRepaveEngine
from mcp_bastion.pillars.canary_goallock import CanaryGoalLock, generate_canary
from mcp_bastion.pillars.compliance_report import (
    FRAMEWORK_CONTROLS,
    generate_report_markdown,
    summarize_audit_log,
)
from mcp_bastion.pillars.llm_scanner import LLMScanner
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.secret_redaction import SecretPatternRedactor, apply_redaction_strategy
from mcp_bastion.pillars.state_backend import MemoryStateBackend
from mcp_bastion.pillars.threat_feeds import ThreatFeedManager


def test_generate_canary_prefix():
    token = generate_canary(prefix="TEST-")
    assert token.startswith("TEST-")


def test_canary_blocks_exfiltration():
    canary = CanaryGoalLock(token_prefix="CANARY-", rotate_on_detection=False)
    token = canary.active_token()
    with pytest.raises(CanaryExfiltrationError):
        canary.check_outbound_arguments({"message": f"leak {token} now"})


def test_canary_rotates_on_detection():
    canary = CanaryGoalLock(token_prefix="CANARY-", rotate_on_detection=True)
    old = canary.active_token()
    with pytest.raises(CanaryExfiltrationError):
        canary.check_outbound_arguments(old)
    assert canary.active_token() != old


def test_canary_backend_token_and_on_detection_event():
    backend = MemoryStateBackend()
    canary = CanaryGoalLock(token_prefix="CANARY-", backend=backend, rotate_on_detection=False)
    canary.set_active_token("CANARY-fixed-token")
    assert "CANARY-fixed-token" in canary.context_snippet()
    canary.check_outbound_arguments({"safe": "payload"})
    new_token = canary.on_detection_event()
    assert new_token.startswith("CANARY-")
    assert canary.active_token() == new_token


def test_canary_check_accepts_string_and_non_json_args():
    canary = CanaryGoalLock(rotate_on_detection=False)
    token = canary.active_token()
    canary.check_outbound_arguments("plain string without token")
    with pytest.raises(CanaryExfiltrationError):
        canary.check_outbound_arguments(f"leak {token}")

    class _Bad:
        def __str__(self) -> str:
            return token

    with pytest.raises(CanaryExfiltrationError):
        canary.check_outbound_arguments(_Bad())


def test_canary_empty_token_short_circuits(monkeypatch):
    canary = CanaryGoalLock(rotate_on_detection=False)
    monkeypatch.setattr(canary, "active_token", lambda: "")
    canary.check_outbound_arguments("anything")


def test_atr_rules_load_and_match(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r.yaml").write_text(
        """
- id: T1
  title: Bad phrase
  severity: high
  pattern: "(?i)evil_phrase_here"
""",
        encoding="utf-8",
    )
    loader = ATRRuleLoader(rules_dir, min_severity="medium")
    matched = loader.match("please evil_phrase_here now")
    assert matched is not None
    assert matched.rule_id == "T1"
    assert "evil_phrase_here" in loader.denylist_patterns()[0]


def test_atr_severity_rank_unknown_defaults_medium():
    assert _severity_rank("not-a-real-level") == 2


def test_atr_rules_skips_low_severity_and_bad_patterns(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "mixed.yaml").write_text(
        """
- id: LOW
  severity: informational
  pattern: "low_only"
- id: OK
  severity: high
  detection:
    pattern: "(?i)detection_hit"
- id: NODET
  severity: high
  title: no pattern field
- just-a-string
""",
        encoding="utf-8",
    )
    (rules_dir / "bad.yaml").write_text(
        """
- id: BAD
  severity: high
  pattern: "[unclosed"
""",
        encoding="utf-8",
    )
    (rules_dir / "single.yml").write_text(
        """
id: SINGLE
severity: critical
pattern: "(?i)single_rule"
category: test
""",
        encoding="utf-8",
    )
    loader = ATRRuleLoader(rules_dir, min_severity="high")
    rules = loader.load()
    assert len(rules) == 2
    assert loader.match("") is None
    assert loader.match("detection_hit") is not None
    assert loader.match("single_rule") is not None
    assert loader.match("no_match_here") is None
    # cached load path
    assert loader.load() is rules


def test_atr_rules_missing_dir_and_corrupt_file(tmp_path):
    missing = ATRRuleLoader(tmp_path / "nope")
    assert missing.load() == []
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "broken.yaml").write_text("::: not yaml", encoding="utf-8")
    loader = ATRRuleLoader(rules_dir)
    assert loader.load() == []


def test_atr_rules_skips_oversized_pattern(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    huge = "a" * 600
    (rules_dir / "big.yaml").write_text(
        f'- id: BIG\n  severity: high\n  pattern: "{huge}"\n',
        encoding="utf-8",
    )
    loader = ATRRuleLoader(rules_dir)
    assert loader.load() == []
    assert loader.match("a" * 700) is None


def test_atr_rules_without_pyyaml_returns_empty(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r.yaml").write_text('- id: X\n  pattern: "a"\n', encoding="utf-8")

    import builtins

    real_import = builtins.__import__

    def _import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _import)
    loader = ATRRuleLoader(rules_dir)
    assert loader.load() == []


def test_llm_scanner_fail_open_on_network_error():
    scanner = LLMScanner(url="http://127.0.0.1:1", timeout_ms=100, only_when_heuristics_uncertain=False)
    scanner.scan("some benign text", heuristics_uncertain=True)


def test_llm_scanner_blocks_high_confidence():
    scanner = LLMScanner(confidence_threshold=0.5, only_when_heuristics_uncertain=False)
    payload = {"response": '{"injection": true, "confidence": 0.99}'}
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode()
        with pytest.raises(LLMScannerBlockedError):
            scanner.scan("sneaky payload", heuristics_uncertain=True)


def test_llm_scanner_skips_when_heuristics_certain():
    scanner = LLMScanner(only_when_heuristics_uncertain=True)
    with mock.patch("urllib.request.urlopen") as urlopen:
        scanner.scan("text", heuristics_uncertain=False)
        urlopen.assert_not_called()


def test_llm_scanner_ignores_empty_and_low_confidence():
    scanner = LLMScanner(confidence_threshold=0.99, only_when_heuristics_uncertain=False)
    scanner.scan("", heuristics_uncertain=True)
    scanner.scan(None, heuristics_uncertain=True)  # type: ignore[arg-type]
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"response": '{"injection": true, "confidence": 0.1}'}
        ).encode()
        scanner.scan("maybe", heuristics_uncertain=True)
        urlopen.return_value.__enter__.return_value.read.return_value = b'{"response": "not json"}'
        scanner.scan("maybe", heuristics_uncertain=True)
        urlopen.return_value.__enter__.return_value.read.return_value = b'{"response": "{broken"}'
        scanner.scan("maybe", heuristics_uncertain=True)


def test_threat_feeds_refresh_and_patterns():
    feed_data = json.dumps({"patterns": [r"(?i)feed_pattern_xyz"]}).encode()
    manager = ThreatFeedManager(
        [{"url": "http://example.test/rules.json", "scanner": "content_filter", "interval_minutes": 60}]
    )
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = feed_data
        manager.refresh_all()
    assert manager.patterns_for("content_filter") == [r"(?i)feed_pattern_xyz"]


def test_threat_feed_background_loop_sets_last_key():
    feed_data = json.dumps({"patterns": [r"(?i)bg_pattern"]}).encode()
    manager = ThreatFeedManager(
        [{"url": "http://example.test/bg.json", "scanner": "prompt_guard", "interval_minutes": 1}]
    )
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = feed_data
        with mock.patch.object(manager._stop, "wait", side_effect=[False, True]):
            with mock.patch("time.time", return_value=1_700_000_000.0):
                manager.start_background()
                manager._thread.join(timeout=2)
    feed = manager._feeds[0]
    assert feed._last_key
    assert manager.patterns_for("prompt_guard") == [r"(?i)bg_pattern"]
    manager.stop()


def test_threat_feeds_parses_list_and_skips_invalid_patterns():
    feed_data = json.dumps(
        [
            r"(?i)ok_pattern",
            {"pattern": "(?i)dict_pattern"},
            {"pattern": "[unclosed"},
            "also_ok",
        ]
    ).encode()
    manager = ThreatFeedManager([{"url": "http://example.test/list.json", "scanner": "x"}])
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = feed_data
        manager.refresh_all()
    patterns = manager.patterns_for("x")
    assert r"(?i)ok_pattern" in patterns
    assert "(?i)dict_pattern" in patterns
    assert len(patterns) == 3


def test_threat_feeds_refresh_failure_keeps_last_good():
    manager = ThreatFeedManager([{"url": "http://example.test/fail.json", "scanner": "x"}])
    good = json.dumps({"patterns": [r"(?i)cached"]}).encode()
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = good
        manager.refresh_all()
        urlopen.side_effect = urllib.error.URLError("down")
        manager.refresh_feed(manager._feeds[0])
    assert manager.patterns_for("x") == [r"(?i)cached"]


def test_threat_feeds_start_background_is_idempotent():
    manager = ThreatFeedManager([{"url": "http://example.test/idempotent.json", "scanner": "x"}])
    with mock.patch.object(manager, "refresh_all") as refresh_all:
        manager.start_background()
        first = manager._thread
        manager.start_background()
        refresh_all.assert_called_once()
        assert manager._thread is first


def test_auto_repave_fires_at_threshold():
    fired: list[str] = []

    def _rotate() -> None:
        fired.append("rotated")

    engine = AutoRepaveEngine(
        triggers={"window_minutes": 5, "canary_detections": 2},
        actions={"rotate_canary": True},
        on_rotate_canary=_rotate,
    )
    assert engine.record_detection("canary_detections") == []
    actions = engine.record_detection("canary_detections")
    assert actions == ["rotate_canary"]
    assert "rotated" in fired


def test_auto_repave_zero_threshold_is_noop():
    engine = AutoRepaveEngine(triggers={"canary_detections": 0}, actions={"rotate_canary": True})
    assert engine.record_detection() == []


def test_auto_repave_backend_fires_all_actions():
    backend = MemoryStateBackend()
    fired: list[str] = []

    engine = AutoRepaveEngine(
        triggers={"window_minutes": 10, "canary_detections": 1},
        actions={
            "rotate_canary": True,
            "reset_session_scope": True,
            "kill_sessions": True,
        },
        backend=backend,
        on_rotate_canary=lambda: fired.append("rotate"),
        on_reset_session_scope=lambda: fired.append("scope"),
        on_kill_sessions=lambda: fired.append("kill"),
    )
    actions = engine.record_detection("canary_detections")
    assert actions == ["rotate_canary", "reset_session_scope", "kill_sessions"]
    assert fired == ["rotate", "scope", "kill"]


def test_auto_repave_concurrent_record_detection_counts_under_lock():
    import threading

    engine = AutoRepaveEngine(
        triggers={"window_minutes": 10, "canary_detections": 10},
        actions={"rotate_canary": True},
        on_rotate_canary=lambda: None,
    )
    results: list[list[str]] = []
    barrier = threading.Barrier(10)

    def _record() -> None:
        barrier.wait(timeout=2)
        results.append(engine.record_detection("canary_detections"))

    threads = [threading.Thread(target=_record) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert sum(1 for r in results if r) == 1


def test_threat_feeds_on_refresh_updates_content_filter():
    feed_data = json.dumps({"patterns": [r"(?i)hot_reload_pattern"]}).encode()
    content_filter = ContentFilter(denylist_patterns=[])
    manager = ThreatFeedManager(
        [{"url": "http://example.test/hot.json", "scanner": "content_filter", "interval_minutes": 60}]
    )

    def _sync() -> None:
        content_filter.update_denylist_patterns(manager.patterns_for("content_filter"))

    manager._on_refresh = _sync
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = feed_data
        manager.refresh_all()
    with pytest.raises(ContentFilterError):
        content_filter.check("please hot_reload_pattern now")


def test_threat_feeds_on_refresh_callback_errors_are_swallowed():
    manager = ThreatFeedManager([{"url": "http://example.test/x.json", "scanner": "x"}])

    def _boom() -> None:
        raise RuntimeError("sync failed")

    manager._on_refresh = _boom
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"patterns": [r"(?i)ok"]}
        ).encode()
        manager.refresh_feed(manager._feeds[0])


def test_threat_feeds_skips_oversized_remote_patterns():
    huge = "a" * 600
    manager = ThreatFeedManager([{"url": "http://example.test/big.json", "scanner": "x"}])
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"patterns": [huge, r"(?i)small_ok"]}
        ).encode()
        manager.refresh_all()
    assert manager.patterns_for("x") == [r"(?i)small_ok"]


def test_inject_canary_snippet_appends_prompt_message_without_mutating_existing():
    result = {
        "result": {
            "messages": [
                {"role": "user", "content": '{"api_key":"secret"}'},
            ]
        }
    }
    out = _inject_canary_snippet_into_result(result, "[Bastion runtime canary: TOKEN]")
    messages = out["result"]["messages"]
    assert messages[0]["content"] == '{"api_key":"secret"}'
    assert "TOKEN" in messages[-1]["content"]


def test_build_middleware_threat_feed_wires_hot_reload(tmp_path):
    cfg = BastionConfig(
        audit=False,
        prompt_guard=False,
        pii=False,
        rate_limit=False,
        content_filter=True,
        threat_feeds_enabled=True,
        threat_feeds=[{"url": "http://127.0.0.1:9/rules.json", "scanner": "content_filter"}],
    )
    feed = json.dumps({"patterns": [r"(?i)wired_hot_reload"]}).encode()
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = feed
        mw = build_middleware_from_config(cfg)
    assert mw is not None
    with pytest.raises(ContentFilterError):
        mw.content_filter.check("wired_hot_reload please")


def test_secret_redaction_strategies():
    assert apply_redaction_strategy("secret", strategy="remove") == ""
    assert apply_redaction_strategy("secret", strategy="replace") == "<REDACTED>"
    assert apply_redaction_strategy("abcdefghij", strategy="mask", mask_prefix=2, mask_suffix=2) == "ab******ij"
    assert apply_redaction_strategy("abc", strategy="mask", mask_prefix=2, mask_suffix=2) == "***"
    hashed = apply_redaction_strategy("secret", strategy="hash")
    assert hashed.startswith("<HASH:")


def test_secret_redactor_skips_bad_rules_and_custom_placeholder():
    redactor = SecretPatternRedactor(
        [
            {"pattern": "[bad"},
            {"rule": ""},
            {"rule": r"TOKEN-\w+", "strategy": "replace", "placeholder": "<SECRET>"},
        ]
    )
    assert redactor.redact_text("") == ""
    assert redactor.redact_text("no secrets") == "no secrets"
    assert redactor.redact_text("TOKEN-ABCDEF") == "<SECRET>"


def test_secret_redactor_on_text():
    redactor = SecretPatternRedactor([{"rule": r"sk-[A-Za-z0-9]{4,}", "strategy": "mask"}])
    out = redactor.redact_text("key=sk-ABCDEFGH12")
    assert "sk-A" in out
    assert "GH12" in out
    assert "BCDEF" not in out


def test_compliance_report_markdown(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps(
            {
                "timestamp": "2026-01-01T00:00:00",
                "action": "BLOCKED",
                "forensic_trace": [{"pillar": "rbac", "status": "blocked"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    summary = summarize_audit_log(audit)
    assert summary["total_events"] == 1
    assert summary["blocked_events"] == 1
    assert summary["pillars"]["rbac"] == 1
    md = generate_report_markdown(framework="soc2", audit_path=audit, version="3.0.0")
    assert "CC6.1" in md
    assert "**rbac**: 1 related audit events" in md
    assert "does not constitute certification" in md


def test_compliance_date_filter_handles_z_timestamps(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps({"timestamp": "2026-06-15T12:00:00Z", "action": "ALLOW"}) + "\n"
        + json.dumps({"timestamp": "2026-07-01T00:00:00Z", "action": "ALLOW"}) + "\n",
        encoding="utf-8",
    )
    summary = summarize_audit_log(audit, date_from="2026-06-01", date_to="2026-06-30")
    assert summary["total_events"] == 1


def test_compliance_report_counts_total_events_control(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps({"timestamp": "2026-01-01", "action": "ALLOW"}) + "\n", encoding="utf-8")
    md = generate_report_markdown(framework="soc2", audit_path=audit, version="3.0.0")
    assert "**all audit events**: 1 related audit events" in md


def test_compliance_summarize_skips_blank_and_invalid_lines(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        "\n"
        + "not-json\n"
        + json.dumps({"timestamp": "2026-01-15T00:00:00Z", "action": "ALLOW", "reason": "ok"}) + "\n"
        + json.dumps({"timestamp": "2026-01-02", "action": "BLOCKED", "pillar": "legacy_pillar"}) + "\n"
        + json.dumps(
            {
                "timestamp": "2026-12-31T00:00:00Z",
                "action": "ALLOW",
                "forensic_trace": [{"pillar": "edge_auth"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    summary = summarize_audit_log(audit, date_from="not-a-date", date_to="also-bad")
    assert summary["total_events"] == 3
    assert summary["blocked_events"] == 1
    assert summary["pillars"]["legacy_pillar"] == 1
    assert summary["kinds"]["ok"] == 1
    filtered = summarize_audit_log(audit, date_from="2026-03-01", date_to="2026-03-31")
    assert filtered["total_events"] == 0


def test_compliance_unknown_framework_has_empty_controls(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps({"timestamp": "2026-01-01", "action": "ALLOW"}) + "\n", encoding="utf-8")
    md = generate_report_markdown(framework="custom-framework", audit_path=audit)
    assert "CUSTOM-FRAMEWORK" in md
    assert "Control mapping" in md
    assert FRAMEWORK_CONTROLS.get("custom_framework") is None


def test_compliance_missing_audit_file_returns_zeros(tmp_path):
    summary = summarize_audit_log(tmp_path / "missing.jsonl")
    assert summary["total_events"] == 0


def test_cmd_report_writes_file(tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps({"timestamp": "2026-01-01", "action": "ALLOW", "pillar": "audit"}) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.md"
    rc = cmd_report(framework="gdpr", audit_path=str(audit), output=str(out))
    assert rc == 0
    assert out.is_file()
    assert "GDPR" in out.read_text(encoding="utf-8")


def test_cmd_report_missing_audit_returns_one():
    assert cmd_report(framework="soc2", audit_path="/nonexistent/audit.jsonl") == 1


def test_load_config_parses_30_fields(tmp_path):
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
mode: observe
canary_goallock:
  enabled: true
atr_rules:
  enabled: true
  rules_dir: ./custom-atr
llm_scanner:
  enabled: true
threat_feeds:
  enabled: true
  feeds:
    - url: http://x/rules
auto_repave:
  enabled: true
  triggers:
    canary_detections: 2
secrets:
  redact_patterns:
    - rule: "token=.+"
""",
        encoding="utf-8",
    )
    cfg = load_config(yaml_path)
    assert cfg.bastion_mode == "observe"
    assert cfg.canary_goallock_enabled is True
    assert cfg.atr_rules_dir == "./custom-atr"
    assert cfg.llm_scanner_enabled is True
    assert cfg.threat_feeds_enabled is True
    assert len(cfg.threat_feeds) == 1
    assert cfg.auto_repave_enabled is True
    assert len(cfg.secrets_redact_patterns) == 1


def test_inject_canary_snippet_into_resource_contents():
    result = {"result": {"contents": [{"type": "text", "text": '{"key":"value"}'}]}}
    out = _inject_canary_snippet_into_result(result, "[canary: TOKEN]")
    payload = out["result"]["contents"]
    assert payload[0]["text"] == '{"key":"value"}'
    assert "TOKEN" in payload[-1]["text"]


@pytest.mark.asyncio
async def test_middleware_injects_canary_into_prompts_get_and_blocks_echo():
    canary = CanaryGoalLock(rotate_on_detection=False)
    token = canary.active_token()
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(fail_open=True),
        canary_goallock=canary,
        enable_canary_goallock=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    prompt_ctx = MiddlewareContext(
        message={"method": "prompts/get", "params": {"name": "demo"}},
        request_id="r-prompt",
        session_id="s1",
        metadata={},
    )

    async def prompt_handler(c):
        return {"result": {"messages": [{"role": "user", "content": "system context"}]}}

    prompt_result = await mw(prompt_ctx, prompt_handler)
    injected = json.dumps(prompt_result)
    assert token in injected
    assert token in str(prompt_ctx.metadata.get("bastion_canary_snippet", ""))

    tool_ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "t", "arguments": {"q": token}}},
        request_id="r-tool",
        session_id="s1",
        metadata={},
    )

    async def tool_handler(c):
        return {"ok": True}

    with pytest.raises(CanaryExfiltrationError):
        await mw(tool_ctx, tool_handler)


@pytest.mark.asyncio
async def test_middleware_llm_scanner_reuses_prompt_guard_scan():
    scanner = LLMScanner(url="http://127.0.0.1:9", timeout_ms=50, only_when_heuristics_uncertain=True)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(fail_open=True),
        llm_scanner=scanner,
        enable_prompt_guard=True,
        enable_llm_scanner=True,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_content_filter=False,
    )
    ctx = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"q": "totally benign request text"}},
        },
        request_id="r1",
        session_id="s1",
        metadata={},
    )

    async def handler(c):
        return {"ok": True}

    with (
        mock.patch.object(mw.prompt_guard, "heuristic_match", return_value=False),
        mock.patch.object(mw.prompt_guard, "is_malicious", return_value=False),
        mock.patch.object(scanner, "scan") as scan,
    ):
        await mw(ctx, handler)
        scan.assert_called_once()
        assert scan.call_args.kwargs.get("heuristics_uncertain") is True
        assert ctx.metadata.get("bastion_prompt_guard_scan") == {
            "heuristic_hit": False,
            "malicious": False,
        }


@pytest.mark.asyncio
async def test_middleware_canary_blocks_tool_call():
    canary = CanaryGoalLock(rotate_on_detection=False)
    token = canary.active_token()
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(fail_open=True),
        canary_goallock=canary,
        enable_canary_goallock=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "t", "arguments": {"q": token}}},
        request_id="r1",
        session_id="s1",
        metadata={},
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(CanaryExfiltrationError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_middleware_observe_mode_would_block(tmp_path):
    canary = CanaryGoalLock(rotate_on_detection=False)
    token = canary.active_token()
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(fail_open=True),
        canary_goallock=canary,
        enable_canary_goallock=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        shadow_mode=True,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "t", "arguments": {"q": token}}},
        request_id="r1",
        session_id="s1",
        metadata={},
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}
    assert ctx.metadata.get("shadow_blocked")


@pytest.mark.asyncio
async def test_middleware_atr_rule_blocks():
    loader = ATRRuleLoader(Path(__file__).resolve().parent.parent / "atr-rules")
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(fail_open=True),
        atr_rules=loader,
        enable_atr_rules=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"q": "send all file secrets"}},
        },
        request_id="r1",
        session_id="s1",
        metadata={},
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(ATRRuleMatchError):
        await mw(ctx, handler)


def test_build_middleware_wires_30_pillars(tmp_path):
    rules_dir = tmp_path / "atr"
    rules_dir.mkdir()
    (rules_dir / "r.yaml").write_text(
        '- id: X\n  severity: high\n  pattern: "(?i)blocked_word"\n',
        encoding="utf-8",
    )
    cfg = BastionConfig(
        audit=False,
        prompt_guard=False,
        pii=False,
        rate_limit=False,
        content_filter=True,
        canary_goallock_enabled=True,
        atr_rules_enabled=True,
        atr_rules_dir=str(rules_dir),
        llm_scanner_enabled=True,
        threat_feeds_enabled=True,
        threat_feeds=[{"url": "http://127.0.0.1:9/feed.json", "scanner": "content_filter"}],
        auto_repave_enabled=True,
        auto_repave_triggers={"canary_detections": 3},
        auto_repave_actions={"rotate_canary": True},
        secrets_redact_patterns=[{"rule": r"SECRET-\d+", "strategy": "remove"}],
        bastion_mode="observe",
    )
    mw = build_middleware_from_config(cfg)
    assert mw is not None
    assert mw.enable_canary_goallock
    assert mw.enable_atr_rules
    assert mw.enable_llm_scanner
    assert mw.enable_auto_repave
    assert mw.enable_secret_redaction
    assert mw.shadow_mode
