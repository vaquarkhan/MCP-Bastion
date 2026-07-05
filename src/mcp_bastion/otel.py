"""
OpenTelemetry integration for MCP-Bastion.

Zero-config observability:
- explicit OTEL endpoint if configured
- auto-detect Datadog agent / Grafana Cloud OTLP
- AWS fallback emits CloudWatch custom metrics when OTLP is unavailable
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Any

logger = logging.getLogger(__name__)

_tracer: Any = None
_meter: Any = None
_cw_client: Any = None
_observability_target: str | None = None
_otel_init_attempted = False


def _is_port_open(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _looks_like_aws() -> bool:
    return any(
        os.environ.get(k)
        for k in (
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "AWS_EXECUTION_ENV",
            "ECS_CONTAINER_METADATA_URI",
            "ECS_CONTAINER_METADATA_URI_V4",
        )
    )


def detect_observability_target() -> tuple[str | None, dict[str, str]]:
    """Auto-detect OTLP destination and optional headers."""
    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"], {}

    gf_endpoint = os.environ.get("GRAFANA_CLOUD_OTLP_ENDPOINT")
    gf_user = os.environ.get("GRAFANA_CLOUD_USERNAME")
    gf_key = os.environ.get("GRAFANA_CLOUD_API_KEY")
    if gf_endpoint:
        headers: dict[str, str] = {}
        if gf_user and gf_key:
            import base64

            token = base64.b64encode(f"{gf_user}:{gf_key}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        return gf_endpoint, headers

    dd_host = os.environ.get("DD_AGENT_HOST", "127.0.0.1")
    if _is_port_open(dd_host, 4317):
        return f"http://{dd_host}:4317", {}

    return None, {}


def _init_otel() -> tuple[Any, Any]:
    global _tracer, _meter, _cw_client, _observability_target, _otel_init_attempted
    if _otel_init_attempted:
        return _tracer, _meter
    if _tracer is not None or _meter is not None:
        _otel_init_attempted = True
        return _tracer, _meter
    _otel_init_attempted = True
    endpoint, headers = detect_observability_target()
    if not endpoint:
        if _looks_like_aws():
            try:
                import boto3

                _cw_client = boto3.client("cloudwatch", region_name=os.environ.get("AWS_REGION"))
                _observability_target = "cloudwatch"
            except Exception:
                _cw_client = None
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
    resource = Resource.create({"service.name": "mcp-bastion", "mcp.observability_target": endpoint})
    trace_provider = TracerProvider(resource=resource)
    exporter_kwargs: dict[str, Any] = {"endpoint": endpoint}
    if headers:
        exporter_kwargs["headers"] = headers
    trace_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(**exporter_kwargs)))
    trace.set_tracer_provider(trace_provider)
    _tracer = trace.get_tracer("mcp-bastion", "1.0.0")
    _observability_target = endpoint
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
        _record_cloudwatch_fallback(tool=tool, action=action, latency_ms=latency_ms)
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


def _record_cloudwatch_fallback(*, tool: str, action: str, latency_ms: float) -> None:
    if _cw_client is None:
        _init_otel()
    if _cw_client is None:
        return
    try:
        _cw_client.put_metric_data(
            Namespace="MCPBastion",
            MetricData=[
                {
                    "MetricName": "ToolCallCount",
                    "Value": 1.0,
                    "Unit": "Count",
                    "Dimensions": [
                        {"Name": "Tool", "Value": str(tool)},
                        {"Name": "Action", "Value": str(action)},
                    ],
                },
                {
                    "MetricName": "ToolLatencyMs",
                    "Value": float(latency_ms),
                    "Unit": "Milliseconds",
                    "Dimensions": [{"Name": "Tool", "Value": str(tool)}],
                },
            ],
        )
    except Exception as e:
        logger.debug("CloudWatch metric emit failed: %s", e)
