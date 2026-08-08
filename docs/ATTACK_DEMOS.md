# Attack → defense demos

**Scripted GIF videos** (terminal-style) plus runnable Python scenarios so users **see Bastion value** for each hero feature: attack → intercept → block/redact → *how it helps you*.

| Related | Link |
|---------|------|
| **Documentation handbook** | [DOCUMENTATION_HANDBOOK.md](DOCUMENTATION_HANDBOOK.md) |
| Issue → solution → benefits (+ embedded GIFs) | [FEATURE_DEEP_DIVE.md](FEATURE_DEEP_DIVE.md) |
| Narrative attacks | [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md) |
| Multi-language | [MULTI_LANGUAGE_SUITE.md](MULTI_LANGUAGE_SUITE.md) |

---

## Master tour (GIF)

![Attack defense tour](images/mcp-bastion-attack-defense-tour.gif)

Each clip is **4 beats**: `1 ATTACK` → `2 BASTION` → `3 BLOCKED/REDACTED` → `4 VALUE`.

```bash
python scripts/generate_attack_demo_gifs.py   # regenerate GIFs
PYTHONPATH=src python -m examples.attack_demos --strict   # live scripted demos
```

---

## Quick run (live, same scenarios)

```bash
# Windows PowerShell
$env:PYTHONPATH="src"; python -m examples.attack_demos

# Linux / macOS
PYTHONPATH=src python -m examples.attack_demos

PYTHONPATH=src python -m examples.attack_demos --only rate_limit
PYTHONPATH=src python -m examples.attack_demos --strict
```

Optional deps for full prompt/PII fidelity: `torch`, `transformers`, `presidio-analyzer`, `en_core_web_sm`.

---

## Per-feature GIF gallery

### 01 — Prompt injection (`prompt_guard`) → **-32001**

![Prompt guard](images/attack-demos/01-prompt-guard.gif)

```bash
PYTHONPATH=src python -m examples.attack_demos --only prompt_guard
```

### 02 — PII leakage (`pii`) → redacted

![PII](images/attack-demos/02-pii.gif)

```bash
PYTHONPATH=src python -m examples.attack_demos --only pii
```

### 03 — Rate / denial of wallet (`rate_limit`) → **-32002**

![Rate limit](images/attack-demos/03-rate-limit.gif)

```bash
PYTHONPATH=src python -m examples.attack_demos --only rate_limit
```

### 04 — Path traversal (`content_filter`) → **-32005**

![Content filter](images/attack-demos/04-content-filter.gif)

```bash
PYTHONPATH=src python -m examples.attack_demos --only content_filter
```

### 05 — Unauthorized tool (`rbac`) → **-32006**

![RBAC](images/attack-demos/05-rbac.gif)

```bash
PYTHONPATH=src python -m examples.attack_demos --only rbac
```

### 06 — Schema bypass (`schema_validation`) → **-32007**

![Schema](images/attack-demos/06-schema.gif)

```bash
PYTHONPATH=src python -m examples.attack_demos --only schema
```

### 07 — Replay (`replay_guard`) → **-32008**

![Replay](images/attack-demos/07-replay.gif)

```bash
PYTHONPATH=src python -m examples.attack_demos --only replay
```

### 08 — Cost overrun (`cost_tracker`) → **-32009**

![Cost](images/attack-demos/08-cost.gif)

```bash
PYTHONPATH=src python -m examples.attack_demos --only cost
```

---

## Dashboard (runtime view of the same defenses)

![Dashboard tour](images/mcp-bastion-dashboard-tour.gif)

```bash
mcp-bastion dashboard --demo
# optional recapture:
# python scripts/capture_dashboard_demo.py
```

See [dashboard/README.md](../dashboard/README.md) and the [Documentation handbook](DOCUMENTATION_HANDBOOK.md).

---

## Hero table

| ID | Feature | Attack | Defense | GIF |
|----|---------|--------|---------|-----|
| 01 | `prompt_guard` | Jailbreak in args | **-32001** | [gif](images/attack-demos/01-prompt-guard.gif) |
| 02 | `pii` | SSN/email in output | Redact | [gif](images/attack-demos/02-pii.gif) |
| 03 | `rate_limit` | Agent loop | **-32002** | [gif](images/attack-demos/03-rate-limit.gif) |
| 04 | `content_filter` | `/etc/passwd` | **-32005** | [gif](images/attack-demos/04-content-filter.gif) |
| 05 | `rbac` | viewer→write | **-32006** | [gif](images/attack-demos/05-rbac.gif) |
| 06 | `schema_validation` | Bad args | **-32007** | [gif](images/attack-demos/06-schema.gif) |
| 07 | `replay_guard` | Dup nonce | **-32008** | [gif](images/attack-demos/07-replay.gif) |
| 08 | `cost_tracker` | Over budget | **-32009** | [gif](images/attack-demos/08-cost.gif) |

---

## Extending

1. Add scenario in `examples/attack_demos/scenarios.py`.
2. Add storyboard entry in `scripts/generate_attack_demo_gifs.py`.
3. Re-run generators; link from [DOCUMENTATION_HANDBOOK.md](DOCUMENTATION_HANDBOOK.md).
