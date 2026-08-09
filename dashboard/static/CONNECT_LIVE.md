# Connect live production data

MCP-Bastion’s dashboard reads an **in-process** `MetricsStore`. A separate `mcp-bastion dashboard` process does **not** automatically see counters from another MCP server.

## Options

### 1. Tour / validate the UI (no wiring)

- Toggle **Demo data** in the header, or run `mcp-bastion dashboard --demo`
- Synthetic scenarios only — labeled with a DEMO banner
- Toggle off to clear seed and return to live/empty

### 2. Python / FastMCP (same process)

1. Enable audit in `bastion.yaml`:

```yaml
audit:
  enabled: true
```

2. Build middleware with `build_middleware_from_config()` / `AuditLogMiddleware` + `make_audit_export_callback` (default when `audit.enabled` is true).
3. Serve the dashboard **from the same Python process** that runs Bastion (or call into that process’s store). Opening only `mcp-bastion dashboard` in a second process will stay empty.

### 3. Bridge from another runtime (Node, sidecar, etc.)

POST JSON blocks into the dashboard:

```http
POST /api/ingest-block
Content-Type: application/json

{"reason":"[-32004] Semantic egress quarantined", "tool":"create_pull_request"}
```

Optional fields: `tenant_id`, `agent_id`, `request_id`, `pillar`, `rule`, `forensic_trace`.

## Related

- Demo mode API: `GET|POST /api/demo-mode`
- Metrics JSON: `GET /api/metrics`
- Full board docs: [dashboard/README.md](../README.md) · [DASHBOARD_AND_OBSERVABILITY.md](../../docs/DASHBOARD_AND_OBSERVABILITY.md)
