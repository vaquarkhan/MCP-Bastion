# Interpreting red-team / harness scores

## Built-in CLI harness

```bash
mcp-bastion redteam
mcp-bastion redteam --config path/to/bastion.yaml
```

The command runs the in-repo **OWASP + MCP Top 10** case suite in-process and prints a JSON report. The report includes:

| Field | Meaning |
|-------|---------|
| `score_blocked_pct` | All denials (includes guard-unavailable) |
| **`score_intended_blocked_pct`** | **Policy effectiveness** — blocks from enabled controls only |
| `score_guard_unavailable_pct` | Blocks because PromptGuard ML was unavailable (fail-closed) |
| `interpretation` | Human notes when scores are misleading |

**Use `score_intended_blocked_pct` for OWASP/control coverage.** With default fail-closed PromptGuard and no ML model, `score_blocked_pct` can hit 100% even when most pillars (PII, RBAC, schema, etc.) are off — those blocks are **not** evidence those controls work.

With `prompt_guard.fail_open: true` (dev only), a typical default-config run blocks roughly **prompt injection (heuristic)**, **path traversal (content filter)**, and **rate limit** cases (~32% intended block rate); PII, schema, credential, unknown-tool, edge-auth, and session-scope cases require enabling the corresponding pillars in `bastion.yaml`.

Use the same `bastion.yaml` you deploy with so the score matches your real toggles.

## What to enable to raise the score

| Goal | Policy lever (`bastion.yaml`) |
|------|-------------------------------|
| Prompt injection | `prompt_guard.enabled: true` (requires a runnable guard model / deps) |
| Tool surface | `rbac.enabled: true` + tight `permissions`; optional tool allowlists in your server |
| Abuse / flood | `rate_limit` (already on in the example) |
| Dangerous content in args | `content_filter.enabled: true` |
| Bad payloads | `schema_validation.enabled: true` (provide schemas for your tools) |
| Replay | `replay_guard.enabled: true` |
| Cost | `cost_tracker.enabled: true` |
| PII in responses | `pii.enabled: true` (Presidio + spaCy) |

After changing policy, **re-run the harness with the same profile** and compare.

## Sensitive / weighted classifiers (if your harness uses them)

Short sentences may score **below** a high classifier threshold with only one or two keywords. Lower the threshold or enrich weighted terms in **your** harness or classifier configuration so scores match your risk tolerance.

## Operational features

- **Hot reload:** Set `hot_reload.enabled: true` in `bastion.yaml` and load middleware via `build_middleware_from_config()` so `_HotReloadingMiddleware` wraps the chain. Changes to the YAML file on disk reload the policy without process restart (poll interval `hot_reload.poll_seconds`).
- **Webhook delivery:** Alert sinks (`alerts` in config) use **retries** (`retry_attempts`, `retry_backoff_seconds`, `retry_backoff_max_seconds`). Tune those if a single transient `POST` failure should not drop the alert.
- **Metrics persistence:** Dashboard metrics are **in-memory** in this process; for durable metrics use Prometheus scrape, OpenTelemetry export, or your own store.

## Node.js (`@mcp-bastion/core`)

The npm package focuses on **in-process rate limiting** and optional **sidecar** flows for prompt/PII. It does **not** mirror every Python control in `bastion.yaml` (content filter, replay, schema, etc.). For that full set, run **`mcp-bastion-python`** middleware or a sidecar you operate that implements the same checks. See `packages/core/README.md`.
