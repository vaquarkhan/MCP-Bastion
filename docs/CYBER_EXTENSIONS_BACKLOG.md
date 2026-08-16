# Cyber extensions backlog — nature-preserving triage

**Single adopted plan for Bastion.** This document **replaces** the long consolidated dump as the working backlog: only items that keep Bastion a **zero-infra, in-process / opt-in library** (compose with gateways; do not become one) are **ADOPT**. Everything else is **DEFER** or **DISCARD**.

Companion (test side): keep harness suites in the harness repo / `MCP-TEST-HARNESS-CYBER-EXTENSIONS.md` — not duplicated here.

Shipped TS A/E/F how-to: [CYBER_EXTENSIONS_CORE.md](CYBER_EXTENSIONS_CORE.md).  
Nature: [ZERO_INFRA_STRATEGY.md](ZERO_INFRA_STRATEGY.md).

---

## Binding constraints (do not dilute)

1. **Mediation precondition:** Bastion governs **only MCP-mediated traffic** that flows through it. Out-of-band shell / direct git / Tor download never reaches Bastion — **capability reduction + OS sandbox**, not Bastion features.
2. **Nature:** zero required Redis/SaaS/daemon in core; opt-in; fail-closed when enabled; bounded cost; no “prevents emergent deception” claims.
3. **Two cores:** Python (`src/mcp_bastion`) and thin TS (`@mcp-bastion/core`). Prefer one core per control unless both are needed; do not fake “full coverage” across both.
4. **Honest evidence:** tamper-**evident** ≠ tamper-proof; panels never assert legal compliance.

---

## Corrections to the source dump

| Claim in dump | Reality (as of 5.0.x) |
|---------------|------------------------|
| Dashboard is demo-seeded by default; no DEMO banner / real-data path | **Fixed:** live/empty by default; Demo toggle + DEMO banner + connect-live docs (`dashboard.demo`, `--demo`, `GET\|POST /api/demo-mode`, `CONNECT_LIVE.md`) |
| Need full compliance product (R1–R10, OSCAL, jurisdiction packs) inside Bastion | **Out of nature** as a product line — Bastion emits evidence; compliance mapping lives outside core |
| Numbat / scanners as enforcement | **Evidence-only** at best; never sell as Bastion enforcement |

---

## Already done (do not re-propose)

| Capability | Core | Notes |
|------------|------|--------|
| Semantic egress (A) | TS | Sidecar; detect/quarantine; `-32004` |
| Result guard + provenance (E) | TS + Python response scan | Not IFC |
| Audit hash chain (F) | TS + Python | Tamper-evident |
| Tenancy / session isolation | Python | |
| Inbound content normalize | Python | |
| Server verification + attestation receipts | Python | Artifact hashes, not SMCP envelope |
| Prompt / PII / RBAC / rate / circuit / fingerprint / toxic_flow / … | Python pillars | |
| Dashboard live-first + Demo/Live UX | Python dashboard | Demo opt-in |

Coverage gate still **omits** heavy ML paths (`prompt_guard`, `pii_redaction`, scanners) from the 92% line gate — do not overclaim.

---

## ADOPT (build next — high value, nature-safe)

Priority order. All: **opt-in, off by default, fail-closed when on, deny codes in audit, harness suite required before “done”.**

### P0 — Incident-driven / cheap security wins

| ID | Item | Core | Why adopt | Deny / note |
|----|------|------|-----------|-------------|
| **A1 — implemented** | **Default-deny egress destination allowlist** (+ host check for MCP-mediated URL/host args) | TS + Python mirror | Highest incident value. Pure in-process; no DNS/OS enforcement claim. | Python `−32043` |
| **A2 — implemented** | **Concurrency / load shed** | TS + Python | Availability = security; O(1); pairs with rate limit / circuit breaker | Python `−32044` / `−32045` |
| **A3 — implemented** | **Live `tools/list` description screening** | Python middleware + TS | Deterministic heuristic floor; complements fingerprint + static scan | Reuses metadata deny taxonomy |
| **A4 — implemented** | **Memory-write guard (ASI06)** | TS `memory-guard.ts` | Write-path complement to result screening; deterministic floor | TS −32007 |

### P1 — Bounded extensions of existing controls

| ID | Item | Core | Why adopt | Caveat |
|----|------|------|-----------|--------|
| **B1 — implemented** | Resource/sampling **provenance tags** + optional context eviction hook | TS `provenance.ts` | Cheap tagging; reduces injection efficacy | Does **not** isolate (no IFC) |
| **B2 — implemented** | **Data-class-aware egress** (private→untrusted sink) | Python `toxic_flow` extension | Same class as Invariant toxic flows | Opt-in labels; no “complete” claim |
| **B3 — implemented** | **Per-parameter business rules** (tenant/amount/env/destination) | Python pillar, config-gated | Stops “allowed tool, wrong args” | Not a replacement for server object-ACL |
| **B4 — implemented** | Tool catalog **actionTier as metadata** | Config + audit metadata | Policy inputs only | No fourth enforcement path |

### P2 — DX / doctor (no new runtime plane)

| ID | Item | Why adopt | Caveat |
|----|------|-----------|--------|
| **C1 — implemented** | **One-command wrap** entry (`serve` / proxy quickstart → copy-paste client config, secure defaults) | Adoption lever; uses existing controls | Strict profile; relaxations explicit |
| **C2 — implemented** | **`mcp-bastion doctor --host`** (read-only local MCP client config audit) | Complements runtime; zero infra | Advisory snapshot only |

### P3 — Attestation (verify-only, advisory default)

| ID | Item | Why adopt | Caveat |
|----|------|-----------|--------|
| **D1 — implemented** | **SMCP-class envelope verify + sampling-origin auth** (TS) | TS `attestation.ts` (verify-only) | **Never re-sign**; require-mode breaks unsigned fleets → default **advisory** |

---

## DEFER (valuable later, not now)

| Item | Why defer |
|------|-----------|
| Covert-capacity ledger + media attestation (Ext B) | Mutation/signature risk; prefer A1 capacity-of-destination first |
| Full compliance layer (obligation library, crosswalk, R1–R10, OSCAL, jurisdiction packs) | Different product; Bastion should **emit** evidence only |
| Local CPU injection model backend | License/weights; keep regex floor; optional later |
| Enterprise registry / IdP discovery adapter | External state; gateway-adjacent; optional later |
| Scoped expiring agent credentials (richer than today’s IAM) | After A1–A4; improves `agent_iam`/`edge_auth` |
| Pre-tool-hook enforcer for IDE agents | Incomplete coverage; bypassable; experimental only |
| Numbat / mcp-scan / SARIF ingest | Evidence lane only; after dashboards stay honest |
| MITRE ATLAS ids on every control | Doc taxonomy pass, not a control |

---

## DISCARD (do not build in Bastion core)

| Item | Why discard |
|------|-------------|
| Kernel/eBPF/seccomp egress | Separate component |
| CaMeL / dual-LLM / IFC agent architecture | Agent-runtime concern |
| MCP tunnels / hosted connectivity | Infrastructure, not library |
| “Package hallucination” live registry checks on hot path | Breaks zero-infra / O(1); installs usually OOB |
| Colang / heavy conversational rail engines | Off-nature |
| AGPL gateway code reuse | License |
| Claiming Numbat or scanners as Bastion **enforcement** | False coverage |
| Guaranteeing compliance / auto-certification | Legal/product non-goal |
| Becoming a fourth “compliance console” product inside this repo | Violates zero-infra library strategy |

---

## Dashboard / evidence (Bastion-owned, scoped)

**Keep / improve (already mostly true):**

- Live metrics + forensics + audit chain panel + connect-live UX (done).
- Emit redacted decision traces / deny codes into `MetricsStore` + audit JSONL + hash chain.
- Optional: clearer deny-code breakdown for cyber codes (−32004…−32010) on the existing Attacks panel.

**Do not build here:**

- Coverage %, executive compliance dashboards, per-jurisdiction legal reports, OSCAL packs.
- Surfacing unwired TS-only features as if Python dashboard auto-sees them (use `POST /api/ingest-block` or same-process; no fake panels).

---

## Suggested ship order (implementation)

**Shipped in this branch (ADOPT complete):** A1–A4, B1–B4, C1–C2, D1 — opt-in, fail-closed when on, unit tests in Vitest/pytest. Paired harness suites remain in the companion harness doc.

Nothing is “done” for release marketing without: config off-by-default, fail-closed path, audit/deny code, Vitest or pytest suite, and an honest README/handbook note (mediation + limits).

---

## OWASP / ASI (honest one-liner)

Within MCP-mediated scope: **ASI02** strong; **ASI03/04/06/08** partial→strong as ADOPT items land; **ASI01/05/09** partial with limits; **ASI07/10** delegated. Full row mapping stays in handbook / threat model — do not inflate status in marketing.
