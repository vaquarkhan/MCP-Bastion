# OpenTelemetry (OTEL)

MCP-Bastion can export spans to an OTLP endpoint for tracing, with **zero-config** fallbacks for common platforms.

## Setup (explicit OTLP)

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

## Zero-config targets (no `OTEL_EXPORTER_OTLP_ENDPOINT`)

If `OTEL_EXPORTER_OTLP_ENDPOINT` is **not** set, MCP-Bastion tries, in order:

1. **Grafana Cloud OTLP:** set `GRAFANA_CLOUD_OTLP_ENDPOINT` and optional `GRAFANA_CLOUD_USERNAME` + `GRAFANA_CLOUD_API_KEY` (Basic auth header is built automatically).
2. **Datadog agent:** probes `DD_AGENT_HOST` (default `127.0.0.1`) on OTLP gRPC port **4317**; if open, uses `http://<host>:4317`.
3. **AWS CloudWatch:** when running in AWS-like environments and OTLP is unavailable, tool-call metrics are emitted via `PutMetricData` (`ToolCallCount`, `ToolLatencyMs`) when `boto3` is installed.

You can still force explicit OTLP by setting `OTEL_EXPORTER_OTLP_ENDPOINT` (highest precedence).

## Behavior

- When an OTLP endpoint is selected, every tool call is recorded as a span (`mcp_bastion.tool_call`) with attributes: `mcp.tool`, `mcp.action`, `mcp.latency_ms`, and `mcp.error` when blocked.
- The audit export callback (used when audit is enabled and metrics are wired) calls `record_tool_span` so no extra wiring is needed if you use `build_middleware_from_config()` or `make_audit_export_callback()`.

## Metrics

Dashboard Prometheus endpoint (`GET /metrics`) is the primary way to scrape metrics. For OTLP metrics export you can run a collector that scrapes the dashboard or forwards from your existing pipeline.
