# Schema minimize + live catalog pin

Opt-in controls that address **context-window bloat** and **tool-poisoning drift** without changing Bastion’s zero-infra nature (no embeddings, no new heavy deps).

## Schema minimization

Shrink verbose `tools/list` manifests while keeping the same tools:

```yaml
discovery_filter:
  enabled: false          # allowlist strip is separate
  minimize_schemas: true  # default false
  max_description_chars: 160
  strip_schema_descriptions: true
```

- Truncates each tool `description`
- Recursively removes `description` keys inside `inputSchema` / `input_schema`
- Records estimated `tokens_saved` under FinOps metrics (`source=schema_minimize`)

Pair with `discovery_filter.enabled` + `tool_allowlist` when you also want fewer tools advertised.

## Live catalog pin

Runtime enforcement of tool metadata fingerprints (ROADMAP P1):

```yaml
tool_metadata_fingerprint:
  enabled: true
  pin_on_first_seen: true   # first tools/list becomes the pin
  on_drift: block           # warn | block
  pin_ttl_seconds: 604800   # 7 days (memory / Redis state_backend)
```

Or pin to a known hash / fingerprint file:

```yaml
tool_metadata_fingerprint:
  enabled: true
  fingerprint_path: tools.fingerprint.json   # from `mcp-bastion fingerprint`
  on_drift: block
```

- Runs on `tools/list` **after** allowlist discovery filter, **before** schema minimize (full metadata hashed)
- `warn`: allow response, set `catalog_drift_warnings` metadata
- `block`: raise `CatalogDriftError` (-32032)
- Multi-replica: use `state_backend.type: redis`

## Related

- [FEATURES.md](FEATURES.md)
- [BENCHMARKS.md](BENCHMARKS.md) - discovery filter token savings
- `mcp-bastion fingerprint` / `mcp-bastion scan`
