# Interpreting red-team / harness scores

External red-team harnesses often **disable** capabilities that need a local ML model or extra integration (for example prompt guard when the model is gated, RBAC when roles are not wired, or edge auth in a lab). A **low block rate** (e.g. ~27%) usually means **most pillars were off for that run**, not that MCP-Bastion “failed.”

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
