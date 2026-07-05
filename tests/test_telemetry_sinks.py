"""Telemetry sink formatting and config wiring."""

import json

import pytest

from mcp_bastion.config import BastionConfig, build_middleware_from_config, load_config
from mcp_bastion.pillars.audit_log import AuditEntry
from mcp_bastion.pillars.telemetry_sinks import (
    audit_entry_to_event_dict,
    build_telemetry_sinks_from_config,
    format_telemetry_body,
)


def _sample_entry() -> AuditEntry:
    return AuditEntry(
        timestamp="2026-01-01T00:00:00Z",
        session_id="s1",
        request_id="r1",
        tool="search",
        action="BLOCKED",
        tenant_id="default",
        reason="test",
        latency_ms=1.0,
        forensic_event_id="e1",
    )


def test_format_http_json_wraps_audit():
    evt = {"tool": "x", "action": "ALLOWED"}
    raw = format_telemetry_body("http_json", evt, service="mcp-bastion", ddtags="")
    data = json.loads(raw.decode())
    assert data["source"] == "mcp-bastion"
    assert data["audit"]["tool"] == "x"


def test_format_datadog_logs_is_array():
    evt = {"tool": "t", "action": "BLOCKED"}
    raw = format_telemetry_body("datadog_logs", evt, service="mcp-bastion", ddtags="env:test")
    rows = json.loads(raw.decode())
    assert isinstance(rows, list) and len(rows) == 1
    assert rows[0]["service"] == "mcp-bastion"
    assert "message" in rows[0]


def test_format_splunk_hec_envelope():
    evt = {"tool": "t", "action": "ALLOWED"}
    raw = format_telemetry_body("splunk_hec", evt, service="mcp-bastion", ddtags="")
    data = json.loads(raw.decode())
    assert data.get("source") == "mcp-bastion"
    assert data.get("event") == evt


def test_format_unknown_falls_back_to_http_json():
    evt = {"x": 1}
    raw = format_telemetry_body("unknown_vendor", evt, service="s", ddtags="")
    data = json.loads(raw.decode())
    assert data["source"] == "mcp-bastion"


def test_format_new_relic_logs_is_array():
    evt = {"tool": "t", "action": "ALLOWED"}
    raw = format_telemetry_body("new_relic_logs", evt, service="mcp-bastion", ddtags="")
    rows = json.loads(raw.decode())
    assert isinstance(rows, list) and rows[0].get("attributes", {}).get("tool") == "t"


def test_audit_entry_to_event_dict_roundtrip():
    e = _sample_entry()
    d = audit_entry_to_event_dict(e)
    assert d["tool"] == "search"
    assert d["action"] == "BLOCKED"


def test_build_telemetry_sinks_from_config_skips_empty_url():
    cfg = BastionConfig(
        telemetry_sinks=[
            {"format": "http_json", "url": ""},
            "not-a-dict",
            {"format": "http_json", "url": "https://example.invalid/ingest", "headers": {"X-Test": "1"}},
        ]
    )
    sinks = build_telemetry_sinks_from_config(cfg)
    assert len(sinks) == 1


def test_expand_none_returns_empty_string():
    from mcp_bastion.pillars.telemetry_sinks import _expand

    assert _expand(None) == ""


def test_format_aws_alias_uses_generic_wrapper():
    evt = {"tool": "t"}
    raw = format_telemetry_body("aws", evt, service="s", ddtags="d")
    data = json.loads(raw.decode())
    assert data["source"] == "mcp-bastion"


def test_build_telemetry_sinks_non_list_specs_returns_empty():
    cfg = BastionConfig(telemetry_sinks="bad")
    assert build_telemetry_sinks_from_config(cfg) == []


def test_make_http_telemetry_sink_warns_on_4xx(caplog):
    from unittest import mock

    from mcp_bastion.pillars.telemetry_sinks import make_http_telemetry_sink

    entry = _sample_entry()
    sink = make_http_telemetry_sink(
        "https://example.test/ingest",
        {},
        "http_json",
        retry_attempts=1,
        retry_backoff_seconds=0.01,
        retry_backoff_max_seconds=0.02,
        timeout_seconds=1.0,
    )
    with caplog.at_level("WARNING"):
        with mock.patch("mcp_bastion.pillars.telemetry_sinks._post_with_retry", return_value=500):
            sink(entry)
    assert "telemetry sink returned" in caplog.text


def test_make_http_telemetry_sink_swallows_post_exception(caplog):
    from unittest import mock

    from mcp_bastion.pillars.telemetry_sinks import make_http_telemetry_sink

    entry = _sample_entry()
    sink = make_http_telemetry_sink(
        "https://example.test/ingest",
        {},
        "http_json",
        retry_attempts=1,
    )
    with caplog.at_level("DEBUG"):
        with mock.patch(
            "mcp_bastion.pillars.telemetry_sinks._post_with_retry",
            side_effect=OSError("network"),
        ):
            sink(entry)


def test_build_middleware_with_telemetry_does_not_raise(tmp_path):
    """Smoke: chain builds when telemetry sinks are declared."""
    p = tmp_path / "bastion.yaml"
    p.write_text(
        """
audit:
  enabled: true
telemetry:
  export_mode: blocked_only
  sinks:
    - format: http_json
      url: https://example.com/mcp-bastion-audit-intake
      headers: {}
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    cfg = load_config(str(p))
    mw = build_middleware_from_config(cfg)
    assert mw is not None


def test_format_syslog_rfc5424():
    evt = {"tool": "t", "action": "ALLOWED"}
    raw = format_telemetry_body("syslog_rfc5424", evt, service="mcp-bastion", ddtags="")
    text = raw.decode()
    assert "mcp-bastion" in text
    assert "ALLOWED" in text


def test_build_telemetry_sinks_syslog():
    from unittest import mock

    cfg = BastionConfig(telemetry_sinks=[{"format": "syslog", "host": "127.0.0.1", "port": 514}])
    sinks = build_telemetry_sinks_from_config(cfg)
    assert len(sinks) == 1
    with mock.patch("socket.socket") as sock_cls:
        inst = sock_cls.return_value.__enter__.return_value
        sinks[0](_sample_entry())
        inst.sendto.assert_called_once()
