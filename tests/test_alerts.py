"""Tests for alert sinks and audit export callback."""

import pytest
from unittest import mock

from mcp_bastion.pillars.audit_log import AuditEntry
from mcp_bastion.pillars.alerts import (
    AlertSink,
    LoggingAlertSink,
    SlackAlertSink,
    WebhookAlertSink,
    check_cost_anomaly,
    make_audit_export_callback,
    notify_audit_entry,
)
from mcp_bastion.pillars.metrics import MetricsStore


def test_alert_sink_base_raises():
    with pytest.raises(NotImplementedError):
        AlertSink().send("kind", "msg")


def test_concrete_alert_sink_works():
    class Concrete(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            return None

    Concrete().send("x", "msg")


def test_logging_alert_sink_send(caplog):
    sink = LoggingAlertSink()
    sink.send("injection", "Blocked", "warning", {"tool": "add"})
    assert "injection" in caplog.text or "alert" in caplog.text


def test_webhook_alert_sink_headers():
    sink = WebhookAlertSink("http://example.com/hook")
    assert sink.url == "http://example.com/hook"
    assert sink.headers.get("Content-Type") == "application/json"


def test_webhook_alert_sink_send_no_network(caplog):
    import urllib.request
    with mock.patch.object(urllib.request, "urlopen", side_effect=OSError("connection refused")):
        sink = WebhookAlertSink("http://localhost:99999/invalid")
        sink.send("test", "message", "warning", {"a": 1})
    assert "Webhook alert failed" in caplog.text or "alert" in caplog.text.lower() or "fail" in caplog.text.lower()


def test_webhook_alert_sink_send_exception_logs_warning(caplog):
    """Explicitly cover except branch (logger.warning) in WebhookAlertSink.send."""
    import logging
    caplog.set_level(logging.WARNING)
    import urllib.request
    with mock.patch.object(urllib.request, "urlopen", side_effect=ValueError("bad request")):
        sink = WebhookAlertSink("http://example.com/hook")
        sink.send("kind", "msg")
    assert "Webhook alert failed" in caplog.text


def test_notify_audit_entry_blocked_adds_alert():
    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "add", "rate limit exceeded", [], set())
    m = store.get_metrics()
    assert len(m["alerts"]) >= 1
    assert m["blocked_total"] == 0
    store.record_blocked("rate limit", "add")
    m2 = store.get_metrics()
    assert m2["blocked_total"] == 1


def test_notify_audit_entry_blocked_calls_sink():
    seen = []

    class CaptureSink(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append((kind, message, details))

    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "add", "injection", [CaptureSink()], {"injection"})
    assert len(seen) == 1
    assert seen[0][0] == "injection"
    assert "add" in seen[0][1]


def test_notify_audit_entry_allowed_no_sink_call():
    seen = []

    class CaptureSink(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append(1)

    notify_audit_entry("ALLOWED", "add", None, [CaptureSink()], {"injection"})
    assert len(seen) == 0


def test_make_audit_export_callback_allowed():
    store = MetricsStore.get()
    store.reset()
    cb = make_audit_export_callback(alert_sinks=[], alert_on=set())
    entry = AuditEntry(
        timestamp="2026-01-01T00:00:00Z",
        session_id="s1",
        request_id="r1",
        tool="add",
        action="ALLOWED",
        reason=None,
        latency_ms=10.0,
    )
    cb(entry)
    m = store.get_metrics()
    assert m["requests_total"] == 1
    assert m["top_tools"]["add"] == 1
    assert m["latency_ms"]["samples"] == 1
    forensic = store.list_forensic_events(limit=5, blocked_only=False, include_full=True)
    assert forensic[0]["tool"] == "add"
    assert forensic[0].get("audit_entry_hash")
    assert forensic[0].get("audit_prev_hash")


def test_make_audit_export_callback_non_numeric_latency():
    store = MetricsStore.get()
    store.reset()
    cb = make_audit_export_callback(alert_sinks=[], alert_on=set())

    class BadLat:
        tool = "x"
        session_id = None
        action = "ALLOWED"
        reason = None
        latency_ms = "not-a-number"

    cb(BadLat())
    assert store.get_metrics()["latency_ms"]["samples"] == 0


def test_make_audit_export_callback_blocked():
    store = MetricsStore.get()
    store.reset()
    cb = make_audit_export_callback(alert_sinks=[], alert_on=set())
    entry = AuditEntry(
        timestamp="2026-01-01T00:00:00Z",
        session_id="s1",
        request_id="r1",
        tool="add",
        action="BLOCKED",
        reason="rate limit",
        latency_ms=5.0,
    )
    cb(entry)
    m = store.get_metrics()
    assert m["blocked_total"] == 1
    assert m["latency_ms"]["samples"] == 1
    assert "rate limit" in m["blocked_by_reason"]
    forensic = store.list_forensic_events(limit=5, blocked_only=True, include_full=True)
    assert forensic[0]["action"] == "BLOCKED"


def test_check_cost_anomaly_below_threshold():
    store = MetricsStore.get()
    store.reset()
    store.record_cost(5.0)
    check_cost_anomaly(store, threshold_pct=80.0, budget=10.0)
    m = store.get_metrics()
    assert len(m["alerts"]) == 0


def test_check_cost_anomaly_above_threshold():
    store = MetricsStore.get()
    store.reset()
    store.record_cost(9.0)
    check_cost_anomaly(store, threshold_pct=80.0, budget=10.0)
    m = store.get_metrics()
    assert any(a["kind"] == "cost_threshold" for a in m["alerts"])


def test_check_cost_anomaly_zero_budget_no_alert():
    store = MetricsStore.get()
    store.reset()
    store.record_cost(100.0)
    check_cost_anomaly(store, threshold_pct=80.0, budget=0.0)
    m = store.get_metrics()
    assert not any(a["kind"] == "cost_threshold" for a in m["alerts"])


def test_slack_alert_sink_send_http_400(caplog):
    import urllib.request

    class Resp:
        status = 400
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass

    with mock.patch.object(urllib.request, "urlopen", return_value=Resp()):
        sink = SlackAlertSink("https://hooks.slack.com/fake")
        sink.send("test", "msg")
    assert "400" in caplog.text or "Slack" in caplog.text or "webhook" in caplog.text.lower()


def test_slack_alert_sink_send_raises(caplog):
    import urllib.request
    with mock.patch.object(urllib.request, "urlopen", side_effect=Exception("net error")):
        sink = SlackAlertSink("https://hooks.slack.com/fake")
        sink.send("test", "msg")
    assert "alert" in caplog.text.lower() or "fail" in caplog.text.lower()


def test_webhook_alert_sink_send_http_400(caplog):
    import urllib.request

    class Resp:
        status = 400
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass

    with mock.patch.object(urllib.request, "urlopen", return_value=Resp()):
        sink = WebhookAlertSink("http://example.com/hook")
        sink.send("test", "msg")
    assert "400" in caplog.text or "Webhook" in caplog.text


def test_webhook_alert_sink_retries_then_succeeds():
    import urllib.request

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    with mock.patch.object(
        urllib.request,
        "urlopen",
        side_effect=[OSError("net"), Resp()],
    ) as mocked:
        with mock.patch("mcp_bastion.pillars.alerts.time.sleep") as sleep_mock:
            sink = WebhookAlertSink(
                "http://example.com/hook",
                retry_attempts=2,
                retry_backoff_seconds=0.01,
            )
            sink.send("test", "msg")
    assert mocked.call_count == 2
    sleep_mock.assert_called_once()


def test_slack_alert_sink_retries_then_succeeds():
    import urllib.request

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    with mock.patch.object(
        urllib.request,
        "urlopen",
        side_effect=[OSError("net"), Resp()],
    ) as mocked:
        with mock.patch("mcp_bastion.pillars.alerts.time.sleep") as sleep_mock:
            sink = SlackAlertSink(
                "https://hooks.slack.com/fake",
                retry_attempts=2,
                retry_backoff_seconds=0.01,
            )
            sink.send("test", "msg")
    assert mocked.call_count == 2
    sleep_mock.assert_called_once()


def test_notify_audit_entry_alert_on_all():
    seen = []
    class S(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append(kind)
    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "t", "something else", [S()], {"all"})
    assert len(seen) == 1
    assert seen[0] == "other"


def test_notify_reason_injection():
    seen = []
    class S(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append(kind)
    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "t", "prompt injection", [S()], {"injection"})
    assert seen == ["injection"]


def test_notify_reason_rbac():
    seen = []
    class S(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append(kind)
    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "t", "rbac cannot access", [S()], {"rbac"})
    assert seen == ["rbac"]


def test_notify_reason_cost():
    seen = []
    class S(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append(kind)
    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "t", "cost budget", [S()], {"cost"})
    assert seen == ["cost"]


def test_notify_reason_content_filter():
    seen = []
    class S(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append(kind)
    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "t", "content blocked", [S()], {"content_filter"})
    assert seen == ["content_filter"]


def test_notify_reason_circuit_breaker():
    seen = []
    class S(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append(kind)
    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "t", "circuit open", [S()], {"circuit_breaker"})
    assert seen == ["circuit_breaker"]


def test_notify_reason_replay():
    seen = []
    class S(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append(kind)
    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "t", "replay nonce", [S()], {"replay"})
    assert seen == ["replay"]


def test_notify_reason_schema_validation():
    seen = []
    class S(AlertSink):
        def send(self, kind, message, severity="warning", details=None):
            seen.append(kind)
    store = MetricsStore.get()
    store.reset()
    notify_audit_entry("BLOCKED", "t", "schema validation failed", [S()], {"schema_validation"})
    assert seen == ["schema_validation"]


def test_make_audit_export_callback_otel_raises():
    store = MetricsStore.get()
    store.reset()
    with mock.patch("mcp_bastion.otel.record_tool_span", side_effect=RuntimeError("otel down")):
        cb = make_audit_export_callback(alert_sinks=[], alert_on=set())
        entry = AuditEntry(
            timestamp="2026-01-01T00:00:00Z", session_id="s1", request_id="r1",
            tool="add", action="ALLOWED", reason=None, latency_ms=1.0,
        )
        cb(entry)
    m = store.get_metrics()
    assert m["requests_total"] == 1
