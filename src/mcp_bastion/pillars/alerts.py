"""
Alert sinks: Slack, PagerDuty, and cost anomaly detection.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
from typing import Any

from mcp_bastion.pillars.audit_hash_chain import AuditHashChain
from mcp_bastion.pillars.metrics import MetricsStore

logger = logging.getLogger(__name__)


def _post_audit_anchor(url: str, payload: dict[str, Any], *, timeout_seconds: float = 2.0) -> None:
    """Best-effort POST of a periodic anchor (immutable store / webhook)."""
    if not url:
        return

    def _req():
        return urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

    try:
        with urllib.request.urlopen(_req(), timeout=timeout_seconds) as resp:
            if int(getattr(resp, "status", 200)) >= 400:
                logger.debug("anchor webhook returned non-2xx")
    except Exception as e:
        logger.debug("audit anchor webhook failed: %s", e)


def _post_with_retry(
    req_factory,
    *,
    retry_attempts: int,
    retry_backoff_seconds: float,
    retry_backoff_max_seconds: float,
    timeout_seconds: float,
) -> int:
    attempts = max(1, int(retry_attempts))
    backoff = max(0.0, float(retry_backoff_seconds))
    max_backoff = max(backoff, float(retry_backoff_max_seconds))
    for attempt in range(1, attempts + 1):
        try:
            req = req_factory()
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                return int(getattr(resp, "status", 200))
        except Exception:
            if attempt >= attempts:
                raise
            if backoff > 0:
                time.sleep(min(backoff * (2 ** (attempt - 1)), max_backoff))


class AlertSink:
    """Base alert sink."""

    def send(self, kind: str, message: str, severity: str = "warning", details: dict[str, Any] | None = None) -> None:
        raise NotImplementedError


class SlackAlertSink(AlertSink):
    """Send alerts to Slack via webhook."""

    def __init__(
        self,
        webhook_url: str,
        *,
        retry_attempts: int = 3,
        retry_backoff_seconds: float = 0.25,
        retry_backoff_max_seconds: float = 2.0,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.webhook_url = webhook_url
        self.retry_attempts = retry_attempts
        self.retry_backoff_seconds = retry_backoff_seconds
        self.retry_backoff_max_seconds = retry_backoff_max_seconds
        self.timeout_seconds = timeout_seconds

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
        def _req():
            return urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
        try:
            status = _post_with_retry(
                _req,
                retry_attempts=self.retry_attempts,
                retry_backoff_seconds=self.retry_backoff_seconds,
                retry_backoff_max_seconds=self.retry_backoff_max_seconds,
                timeout_seconds=self.timeout_seconds,
            )
            if status is not None and status >= 400:
                logger.warning("Slack webhook returned %s", status)
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

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        *,
        retry_attempts: int = 3,
        retry_backoff_seconds: float = 0.25,
        retry_backoff_max_seconds: float = 2.0,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.url = url
        self.headers = dict(headers or {})
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"
        self.retry_attempts = retry_attempts
        self.retry_backoff_seconds = retry_backoff_seconds
        self.retry_backoff_max_seconds = retry_backoff_max_seconds
        self.timeout_seconds = timeout_seconds

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
        def _req():
            return urllib.request.Request(
                self.url,
                data=json.dumps(payload).encode(),
                headers=self.headers,
                method="POST",
            )
        try:
            status = _post_with_retry(
                _req,
                retry_attempts=self.retry_attempts,
                retry_backoff_seconds=self.retry_backoff_seconds,
                retry_backoff_max_seconds=self.retry_backoff_max_seconds,
                timeout_seconds=self.timeout_seconds,
            )
            if status is not None and status >= 400:
                logger.warning("Webhook %s returned %s", self.url[:50], status)
        except Exception as e:  # pragma: no cover
            logger.warning("Webhook alert failed: %s", e)  # pragma: no cover


def _reason_from_error(reason: str | None) -> str:
    if not reason:
        return "unknown"
    reason_lower = reason.lower()
    if "injection" in reason_lower or "prompt" in reason_lower:
        return "injection"
    if "rate" in reason_lower or "iteration" in reason_lower:
        return "rate_limit"
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
    if "semantic firewall" in reason_lower or "intent mismatch" in reason_lower or "dangerous tool chain" in reason_lower:
        return "semantic_firewall"
    if "external policy" in reason_lower or "opa denied" in reason_lower or "cedar denied" in reason_lower:
        return "external_policy"
    if "sensitive content" in reason_lower or "classifier" in reason_lower:
        return "sensitive_classifier"
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
    *,
    behavior_fingerprint: bool = True,
    anchor_webhook_url: str | None = None,
    telemetry_sinks: list[Any] | None = None,
    telemetry_export_mode: str = "all",
    audit_jsonl_sink: Any | None = None,
):
    """Return a callback for AuditLogMiddleware that updates MetricsStore and optionally sends alerts."""
    from mcp_bastion.pillars.audit_log import AuditEntry

    sinks = alert_sinks or []
    on_events = alert_on or {"injection", "rate_limit", "cost"}
    tel_sinks = list(telemetry_sinks or [])
    tel_mode = (telemetry_export_mode or "all").strip().lower()

    def _callback(entry: AuditEntry) -> None:
        if audit_jsonl_sink is not None:
            try:
                audit_jsonl_sink.write(entry)
            except Exception as ex:
                logger.debug("audit jsonl sink error: %s", ex)
        store = MetricsStore.get()
        tool = entry.tool
        user = entry.session_id
        tenant = getattr(entry, "tenant_id", None)
        evt: dict[str, Any] = {
            "event_id": getattr(entry, "forensic_event_id", None),
            "timestamp": getattr(entry, "timestamp", None),
            "tenant_id": tenant,
            "agent_id": getattr(entry, "agent_id", None),
            "request_id": getattr(entry, "request_id", None),
            "session_id": getattr(entry, "session_id", None),
            "tool": getattr(entry, "tool", "unknown"),
            "action": getattr(entry, "action", "unknown"),
            "reason": getattr(entry, "reason", None),
            "latency_ms": getattr(entry, "latency_ms", 0.0),
            "tokens_used": getattr(entry, "tokens_used", 0),
            "error_code": getattr(entry, "error_code", None),
            "cost_usd": float(getattr(entry, "cost_usd", 0.0) or 0.0),
            "cost_dimensions": getattr(entry, "cost_dimensions", None),
            "forensic_request": getattr(entry, "forensic_request", None),
            "forensic_response": getattr(entry, "forensic_response", None),
            "forensic_trace": getattr(entry, "forensic_trace", []),
            "replay_payload": getattr(entry, "replay_payload", None),
        }
        AuditHashChain.get().append(evt)
        anchor = evt.get("audit_anchor")
        if anchor_webhook_url and isinstance(anchor, dict):
            _post_audit_anchor(anchor_webhook_url, anchor)
        store.record_forensic_event(evt)
        if tel_sinks:
            send_telemetry = tel_mode == "all" or (tel_mode == "blocked_only" and entry.action == "BLOCKED")
            if send_telemetry:
                for fn in tel_sinks:
                    try:
                        fn(entry)
                    except Exception as ex:
                        logger.debug("telemetry sink error: %s", ex)
        try:
            from mcp_bastion.otel import record_tool_span
            record_tool_span(entry.tool, entry.action, entry.latency_ms, entry.reason)
        except Exception:
            pass
        try:
            latency = float(entry.latency_ms)
            store.record_latency_ms(latency)
            store.record_tool_latency_ms(tool, latency)
        except (TypeError, ValueError):
            pass  # missing or non-numeric latency on synthetic entries
        try:
            tu = int(getattr(entry, "tokens_used", 0) or 0)
            if tu > 0:
                store.record_tokens_used(tu)
        except (TypeError, ValueError):
            pass
        # Finops savings may be attached on metadata via forensic/replay payloads in future;
        # also accept optional tokens_saved on the entry if present.
        try:
            saved = getattr(entry, "tokens_saved", None)
            if saved is None and isinstance(getattr(entry, "cost_dimensions", None), dict):
                saved = entry.cost_dimensions.get("tokens_saved")
            if saved:
                store.record_tokens_saved(int(saved), source="audit")
        except (TypeError, ValueError):
            pass
        if entry.action == "ALLOWED":
            store.record_request(tool, user, tenant=tenant)
            if behavior_fingerprint:
                store.record_session_tool(entry.session_id, tool)
        else:
            reason = entry.reason or "unknown"
            store.record_blocked(
                reason,
                tool,
                tenant=tenant,
                agent_id=getattr(entry, "agent_id", None),
                trace_id=getattr(entry, "request_id", None),
                request_id=getattr(entry, "request_id", None),
                forensic_trace=getattr(entry, "forensic_trace", None) or None,
            )
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
