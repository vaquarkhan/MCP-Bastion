# Attack → defense demos (Python engine)

Runnable scenarios that print a markdown report: **attack**, **Bastion feature**, **block/redact outcome**, **error code**.

**Full demo hub (dashboard + all languages + payloads):** [docs/DEMOS.md](../../docs/DEMOS.md)

```bash
PYTHONPATH=src python -m examples.attack_demos
PYTHONPATH=src python -m examples.attack_demos --only rbac
PYTHONPATH=src python -m examples.attack_demos --strict
```

Payload catalog: [payloads.json](payloads.json)

| ID | Feature | Expected |
|----|---------|----------|
| 01 | prompt_guard | -32001 (may SKIP without ML) |
| 02 | pii | redacted (may SKIP without Presidio) |
| 03 | rate_limit | -32002 |
| 04 | content_filter | -32005 |
| 05 | rbac | -32006 |
| 06 | schema_validation | -32007 |
| 07 | replay_guard | -32008 |
| 08 | cost_tracker | -32009 |

Full write-up: **[docs/ATTACK_DEMOS.md](../../docs/ATTACK_DEMOS.md)** · Deep dive: **[docs/FEATURE_DEEP_DIVE.md](../../docs/FEATURE_DEEP_DIVE.md)**

For TypeScript / Java / Go / .NET / Kotlin / Rust connectors, use **[mcp-bastion-suite](https://github.com/vaquarkhan/mcp-bastion-suite)** — see [docs/MULTI_LANGUAGE_SUITE.md](../../docs/MULTI_LANGUAGE_SUITE.md).
