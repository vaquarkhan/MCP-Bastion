"""
OpenTelemetry integration for MCP-Bastion.

Export spans to OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is set.
Metrics can be scraped from the dashboard /metrics (Prometheus) or exported via OTEL.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_tracer: Any = None
_meter: Any = None


def _init_otel() -> tuple[Any, Any]:
    global _tracer, _meter
    if _tracer is not None or _meter is not None:
        return _tracer, _meter
    import os
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return None, None
    try:
        from opentelemetry import trace, metrics
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource
    except ImportError:
        logger.debug("OpenTelemetry not installed; pip install opentelemetry-api opentelemetry-sdk")
        return None, None
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    except ImportError:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        except ImportError:  # pragma: no cover
            logger.debug("OTLP exporter not installed; pip install opentelemetry-exporter-otlp-proto-grpc")  # pragma: no cover
            return None, None  # pragma: no cover
    resource = Resource.create({"service.name": "mcp-bastion"})
    trace_provider = TracerProvider(resource=resource)
    trace_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(trace_provider)
    _tracer = trace.get_tracer("mcp-bastion", "1.0.0")
    return _tracer, _meter


def get_tracer() -> Any:
    """Return OpenTelemetry tracer or None if not configured."""
    tr, _ = _init_otel()
    return tr


def get_meter() -> Any:
    """Return OpenTelemetry meter or None if not configured."""
    _, m = _init_otel()
    return _meter


def record_tool_span(tool: str, action: str, latency_ms: float, error: str | None = None) -> None:
    """Record a tool call as a span. Call from audit export callback."""
    tracer = get_tracer()
    if tracer is None:
        return
    try:
        with tracer.start_as_current_span("mcp_bastion.tool_call") as span:
            span.set_attribute("mcp.tool", tool)
            span.set_attribute("mcp.action", action)
            span.set_attribute("mcp.latency_ms", latency_ms)
            if error:
                span.set_attribute("mcp.error", error)
                from opentelemetry.trace import Status, StatusCode
                span.set_status(Status(StatusCode.ERROR, error))
    except Exception as e:
        logger.debug("OTEL span record failed: %s", e)
