# Behavioral fingerprinting (3.3.0+)

Per-agent **tool baseline learning** with drift and rate-spike detection. Opt-in middleware pillar - **default OFF** so existing deployments behave exactly as before.

## Non-breaking defaults

| Setting | Default | Effect |
|---------|---------|--------|
| `behavior_fingerprint.enabled` | **`false`** | Middleware pillar does not run |
| `behavior_fingerprint.audit_metrics` | **`true`** | Legacy audit→metrics anomaly path (same as 3.2.0) |
| `on_detect` | **`warn`** | When enabled, never blocks unless you set `block` |

## Enable the middleware pillar

```yaml
behavior_fingerprint:
  enabled: true
  learn_min_calls: 12
  freeze_after_calls: 18
  drift_window: 10
  tool_overlap_threshold: 0.25
  rate_spike_multiplier: 10.0
  on_detect: warn   # warn | block

state_backend:
  type: redis   # recommended for load-balanced replicas
```

## Modes

| `on_detect` | Behavior |
|-------------|----------|
| `warn` | Stamp `metadata.behavior_fingerprint.anomaly`; show in dashboard **Insights & anomalies** |
| `block` | Deny with `BehaviorAnomalyError` (`-32031`) |

Pair with global `mode: observe` to dry-run block policies without denying traffic.

## Related

- [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md) - moat #3 positioning
- [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md) - Redis `state_backend`
