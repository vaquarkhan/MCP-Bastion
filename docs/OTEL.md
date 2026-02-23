# OpenTelemetry (OTEL)

MCP-Bastion can export spans to an OTLP endpoint for tracing.

## Setup

Set the OTLP endpoint:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

Install the optional OTEL dependencies:

```bash
pip install mcp-bastion-python[otel]
# or
pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc
```

## Behavior

- When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, every tool call is recorded as a span (`mcp_bastion.tool_call`) with attributes: `mcp.tool`, `mcp.action`, `mcp.latency_ms`, and `mcp.error` when blocked.
- The audit export callback (used when audit is enabled and metrics are wired) calls `record_tool_span` so no extra wiring is needed if you use `build_middleware_from_config()` or `make_audit_export_callback()`.

## Metrics

Dashboard Prometheus endpoint (`GET /metrics`) is the primary way to scrape metrics. For OTLP metrics export you can run a collector that scrapes the dashboard or forwards from your existing pipeline.
