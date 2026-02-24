"""
Alert sinks: Slack, PagerDuty, and cost anomaly detection.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any

from mcp_bastion.pillars.metrics import MetricsStore

logger = logging.getLogger(__name__)


class AlertSink:
    """Base alert sink."""

    def send(self, kind: str, message: str, severity: str = "warning", details: dict[str, Any] | None = None) -> None:
        raise NotImplementedError


class SlackAlertSink(AlertSink):
    """Send alerts to Slack via webhook."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def send(
        self,
        kind: str,
        message: str,
        severity: str = "warning",
        details: dict[str, Any] | None = None,
    ) -> None:
        color = "#ff0000" if severity == "critical" else "#ffa500" if severity == "warning" else "#36a64f"
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"MCP-Bastion: {kind}",
                    "text": message,
                    "fields": [{"title": k, "value": str(v), "short": True} for k, v in (details or {}).items()],
                }
            ]
        }
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status >= 400:
                    logger.warning("Slack webhook returned %s", resp.status)
        except Exception as e:
            logger.warning("Slack alert failed: %s", e)


class LoggingAlertSink(AlertSink):
    """Log alerts only."""

    def send(
        self,
        kind: str,
        message: str,
        severity: str = "warning",
        details: dict[str, Any] | None = None,
    ) -> None:
        logger.warning("alert [%s] %s: %s %s", severity, kind, message, details or "")


class WebhookAlertSink(AlertSink):
    """POST alerts to any webhook URL (Slack, PagerDuty, custom)."""

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = dict(headers or {})
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"

    def send(
        self,
        kind: str,
        message: str,
        severity: str = "warning",
        details: dict[str, Any] | None = None,
    ) -> None:
        payload = {
            "source": "mcp-bastion",
            "kind": kind,
            "message": message,
            "severity": severity,
            "details": details or {},
        }
        try:
            req = urllib.request.Request(
                self.url,
                data=json.dumps(payload).encode(),
                headers=self.headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status >= 400:
                    logger.warning("Webhook %s returned %s", self.url[:50], resp.status)
        except Exception as e:  # pragma: no cover
            logger.warning("Webhook alert failed: %s", e)  # pragma: no cover


def _reason_from_error(reason: str | None) -> str:
    if not reason:
        return "unknown"
    reason_lower = reason.lower()
    if "injection" in reason_lower or "prompt" in reason_lower:
        return "injection"
    if "rate" in reason_lower or "iteration" in reason_lower:  # pragma: no cover
        return "rate_limit"  # pragma: no cover
    if "rbac" in reason_lower or "cannot access" in reason_lower:
        return "rbac"
    if "cost" in reason_lower or "budget" in reason_lower:
        return "cost"
    if "content" in reason_lower or "blocked" in reason_lower:
        return "content_filter"
    if "circuit" in reason_lower:
        return "circuit_breaker"
    if "replay" in reason_lower or "nonce" in reason_lower:
        return "replay"
    if "schema" in reason_lower or "validation" in reason_lower:
        return "schema_validation"
    return "other"


def notify_audit_entry(
    action: str,
    tool: str,
    reason: str | None,
    sinks: list[AlertSink],
    alert_on: set[str],
) -> None:
    """On BLOCKED, optionally send alert and update metrics."""
    store = MetricsStore.get()
    if action == "BLOCKED":
        kind = _reason_from_error(reason)
        store.add_alert(kind, reason or "Blocked", "warning")
        if kind in alert_on or "all" in alert_on:
            msg = f"Blocked: {tool} - {reason or 'unknown'}"
            for s in sinks:
                s.send(kind, msg, "warning", {"tool": tool, "reason": reason})


def make_audit_export_callback(
    alert_sinks: list[AlertSink] | None = None,
    alert_on: set[str] | None = None,
):
    """Return a callback for AuditLogMiddleware that updates MetricsStore and optionally sends alerts."""
    from mcp_bastion.pillars.audit_log import AuditEntry

    sinks = alert_sinks or []
    on_events = alert_on or {"injection", "rate_limit", "cost"}

    def _callback(entry: AuditEntry) -> None:
        store = MetricsStore.get()
        tool = entry.tool
        user = entry.session_id
        try:
            from mcp_bastion.otel import record_tool_span
            record_tool_span(entry.tool, entry.action, entry.latency_ms, entry.reason)
        except Exception:
            pass
        if entry.action == "ALLOWED":
            store.record_request(tool, user)
        else:
            reason = entry.reason or "unknown"
            store.record_blocked(reason, tool)
            notify_audit_entry(entry.action, tool, reason, sinks, on_events)

    return _callback


def check_cost_anomaly(store: MetricsStore, threshold_pct: float = 80.0, budget: float = 10.0) -> None:
    """If cost_total >= threshold_pct of budget, add alert."""
    m = store.get_metrics()
    cost = m["cost_total"]
    if budget <= 0:
        return
    pct = 100 * cost / budget
    if pct >= threshold_pct:
        store.add_alert("cost_threshold", f"Cost ${cost:.2f} is {pct:.0f}% of budget ${budget}", "warning")
