"""
HTTP telemetry sinks: forward structured audit events to Datadog, New Relic,
or any HTTPS endpoint (API Gateway → EventBridge, Azure Logic Apps, GCP
Pub/Sub push, Splunk HEC, etc.).

Uses stdlib urllib only; API keys via headers and ``os.path.expandvars``.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
import urllib.request
from collections.abc import Callable
from typing import Any

from mcp_bastion.pillars.alerts import _post_with_retry
from mcp_bastion.pillars.audit_log import AuditEntry

logger = logging.getLogger(__name__)


def _expand(s: str | None) -> str:
    if s is None:
        return ""
    return os.path.expandvars(str(s))


def audit_entry_to_event_dict(entry: AuditEntry) -> dict[str, Any]:
    """Stable JSON shape for SIEM / APM (matches audit export callback fields)."""
    return {
        "event_id": getattr(entry, "forensic_event_id", None),
        "timestamp": getattr(entry, "timestamp", None),
        "tenant_id": getattr(entry, "tenant_id", None),
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


def format_telemetry_body(format_name: str, evt: dict[str, Any], *, service: str, ddtags: str) -> bytes:
    """
    Serialize ``evt`` for the target intake.

    Supported ``format_name`` values:

    - ``http_json`` / ``generic``: ``{"source":"mcp-bastion","audit": evt}``
    - ``datadog_logs``: Datadog Logs API v2 JSON array (single element)
    - ``new_relic_logs``: New Relic Log API JSON array
    - ``splunk_hec``: Splunk HEC event envelope ``{"event": evt, "source": ...}``
    """
    fmt = (format_name or "http_json").strip().lower()
    if fmt in ("http_json", "generic", "aws", "azure", "gcp"):
        body = {"source": "mcp-bastion", "audit": evt}
        return json.dumps(body, default=str).encode("utf-8")

    if fmt in ("datadog_logs", "datadog"):
        row = {
            "message": json.dumps(evt, default=str),
            "service": service or "mcp-bastion",
            "ddsource": "mcp-bastion",
            "hostname": socket.gethostname(),
            "ddtags": ddtags or "service:mcp-bastion",
        }
        return json.dumps([row], default=str).encode("utf-8")

    if fmt in ("new_relic_logs", "newrelic", "new_relic"):
        ts_ms = int(time.time() * 1000)
        row = {
            "timestamp": ts_ms,
            "message": json.dumps(evt, default=str),
            "attributes": {
                "tool": evt.get("tool"),
                "action": evt.get("action"),
                "tenant_id": evt.get("tenant_id"),
                "session_id": evt.get("session_id"),
            },
        }
        return json.dumps([row], default=str).encode("utf-8")

    if fmt in ("splunk_hec", "splunk"):
        body = {
            "source": "mcp-bastion",
            "sourcetype": "_json",
            "event": evt,
        }
        return json.dumps(body, default=str).encode("utf-8")

    if fmt in ("syslog", "syslog_rfc5424"):
        # RFC 5424 structured data optional; message is JSON audit event
        pri = 14  # info
        msg = json.dumps(evt, default=str)
        line = f"<{pri}>1 {time.strftime('%Y-%m-%dT%H:%M:%S.000Z')} {socket.gethostname()} mcp-bastion - - - {msg}"
        return line.encode("utf-8")

    # Unknown format: send generic wrapper
    logger.warning("telemetry_sinks unknown format=%s; using http_json", format_name)
    return format_telemetry_body("http_json", evt, service=service, ddtags=ddtags)


def make_http_telemetry_sink(
    url: str,
    headers: dict[str, str],
    format_name: str,
    *,
    service: str = "mcp-bastion",
    ddtags: str = "",
    retry_attempts: int = 3,
    retry_backoff_seconds: float = 0.25,
    retry_backoff_max_seconds: float = 2.0,
    timeout_seconds: float = 5.0,
) -> Callable[[AuditEntry], None]:
    """Return a callable that POSTs one audit entry to ``url``."""

    hdrs = dict(headers)
    if "Content-Type" not in hdrs and "content-type" not in {k.lower() for k in hdrs}:
        hdrs["Content-Type"] = "application/json"

    def _send(entry: AuditEntry) -> None:
        evt = audit_entry_to_event_dict(entry)
        body = format_telemetry_body(format_name, evt, service=service, ddtags=ddtags or "service:mcp-bastion")

        def _req():
            return urllib.request.Request(
                url,
                data=body,
                headers=hdrs,
                method="POST",
            )

        try:
            status = _post_with_retry(
                _req,
                retry_attempts=retry_attempts,
                retry_backoff_seconds=retry_backoff_seconds,
                retry_backoff_max_seconds=retry_backoff_max_seconds,
                timeout_seconds=timeout_seconds,
            )
            if status is not None and status >= 400:
                logger.warning("telemetry sink returned %s url=%s", status, url[:64])
        except Exception as e:
            logger.debug("telemetry sink failed url=%s err=%s", url[:64], e)

    return _send


def _make_syslog_sink(host: str, port: int, format_name: str) -> Callable[[AuditEntry], None]:
    """UDP syslog sink (RFC 5424-ish); BYO SIEM collector."""

    def _send(entry: AuditEntry) -> None:
        evt = audit_entry_to_event_dict(entry)
        body = format_telemetry_body(format_name, evt, service="mcp-bastion", ddtags="")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(body, (host, port))
        except OSError as e:
            logger.debug("syslog sink failed host=%s:%s err=%s", host, port, e)

    return _send


def build_telemetry_sinks_from_config(config: Any) -> list[Callable[[AuditEntry], None]]:
    """Build POST sinks from ``BastionConfig.telemetry_sinks`` list."""
    specs = getattr(config, "telemetry_sinks", None) or []
    out: list[Callable[[AuditEntry], None]] = []
    if not isinstance(specs, list):
        return out

    ra = int(getattr(config, "alerts_retry_attempts", 3))
    rb = float(getattr(config, "alerts_retry_backoff_seconds", 0.25))
    rbm = float(getattr(config, "alerts_retry_backoff_max_seconds", 2.0))
    to = float(getattr(config, "alerts_timeout_seconds", 5.0))

    for spec in specs:
        if not isinstance(spec, dict):
            continue
        fmt = str(spec.get("format") or spec.get("type") or "http_json")
        url = _expand(str(spec.get("url") or "")).strip()
        if fmt in ("syslog", "syslog_rfc5424"):
            host = _expand(str(spec.get("host") or "127.0.0.1"))
            port = int(spec.get("port", 514))
            out.append(_make_syslog_sink(host, port, fmt))
            continue
        if not url:
            logger.warning("telemetry sink skipped: missing url format=%s", fmt)
            continue
        raw_headers = spec.get("headers") or {}
        headers: dict[str, str] = {}
        if isinstance(raw_headers, dict):
            for k, v in raw_headers.items():
                headers[str(k)] = _expand(str(v))
        service = _expand(str(spec.get("service") or "mcp-bastion"))
        ddtags = _expand(str(spec.get("ddtags") or ""))
        out.append(
            make_http_telemetry_sink(
                url,
                headers,
                fmt,
                service=service,
                ddtags=ddtags,
                retry_attempts=int(spec.get("retry_attempts", ra)),
                retry_backoff_seconds=float(spec.get("retry_backoff_seconds", rb)),
                retry_backoff_max_seconds=float(spec.get("retry_backoff_max_seconds", rbm)),
                timeout_seconds=float(spec.get("timeout_seconds", to)),
            )
        )
    return out
