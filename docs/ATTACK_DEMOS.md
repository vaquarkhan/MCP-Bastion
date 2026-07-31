# Attack → defense demos

Runnable, feature-by-feature scenarios that show **what an attack looks like** and **how MCP-Bastion blocks or redacts it**. Keep visuals and long walkthroughs here (and in [FEATURE_DEEP_DIVE.md](FEATURE_DEEP_DIVE.md))—**not** in the root README.

| Related | Link |
|---------|------|
| Issue → solution → benefits | [FEATURE_DEEP_DIVE.md](FEATURE_DEEP_DIVE.md) |
| Narrative attack guide | [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md) |
| Multi-language connectors | [MULTI_LANGUAGE_SUITE.md](MULTI_LANGUAGE_SUITE.md) · [mcp-bastion-suite](https://github.com/vaquarkhan/mcp-bastion-suite) |
| Legacy combined script | [examples/full_demo.py](../examples/full_demo.py) |

---

## Quick run

From the MCP-Bastion repo root:

```bash
# Windows PowerShell
$env:PYTHONPATH="src"; python -m examples.attack_demos

# Linux / macOS
PYTHONPATH=src python -m examples.attack_demos

# One feature
PYTHONPATH=src python -m examples.attack_demos --only rate_limit

# Fail CI if core demos do not block
PYTHONPATH=src python -m examples.attack_demos --strict
```

Or: `python examples/attack_demos/runner.py` (adds `src/` to `sys.path` automatically).

Optional deps for full fidelity:

```bash
pip install torch transformers presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_sm
```

Without ML/Presidio, **prompt_guard** and **pii** may report `INFO`/`SKIP`; rate limit, content filter, RBAC, schema, replay, and cost still demonstrate blocks.

---

## Hero scenarios

| ID | Feature | Attack | Expected defense |
|----|---------|--------|------------------|
| 01 | `prompt_guard` | Jailbreak string in tool args | Block **-32001** (needs ML/heuristics) |
| 02 | `pii` | SSN/email/phone in tool output | Redact placeholders |
| 03 | `rate_limit` | Agent loop past `max_iterations` | Block **-32002** |
| 04 | `content_filter` | `/etc/passwd` path | Block **-32005** |
| 05 | `rbac` | `viewer` calls `write` | Block **-32006** |
| 06 | `schema_validation` | Missing / wrong arg types | Block **-32007** |
| 07 | `replay_guard` | Duplicate request_id + nonce | Block **-32008** |
| 08 | `cost_tracker` | Session spend over cap | Block **-32009** |

Each printed report includes: feature key, attack description, outcome, and MCP error code when present.

---

## How demos map to docs

In [FEATURE_DEEP_DIVE.md](FEATURE_DEEP_DIVE.md), hero controls link here under **Demo**. Example:

```bash
PYTHONPATH=src python -m examples.attack_demos --only content_filter
```

Sample output shape:

```text
### [04] Path traversal / sensitive file read
- **Feature:** `content_filter`
- **Attack:** read_file path="/etc/passwd"
- **Result:** PASS (blocked) code=-32005 expected=-32005
- **Detail:** Content filter blocked sensitive path. ...
```

---

## GIFs / visuals (optional)

Prefer **script output in docs** as the source of truth (always regenerable). Optional terminal GIFs can be added later under `docs/site/assets/demos/` using [VHS](https://github.com/charmbracelet/vhs) or asciinema—**do not** embed large GIFs in the root README.

Dashboard UI tour (separate from per-pillar attacks):

```bash
mcp-bastion dashboard --demo
python scripts/capture_dashboard_demo.py
```

See [dashboard/README.md](../dashboard/README.md).

---

## Extending

1. Add a function in `examples/attack_demos/scenarios.py` returning `ScenarioResult`.
2. Append it to `SCENARIOS`.
3. Document the row in the table above and link from FEATURE_DEEP_DIVE.

For TypeScript / Java / Go / .NET stacks, run the same policy via the suite proxy/adapters—see [MULTI_LANGUAGE_SUITE.md](MULTI_LANGUAGE_SUITE.md).
