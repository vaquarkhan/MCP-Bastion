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
| **A1** | **Default-deny egress destination allowlist** (+ DNS/host check for MCP-mediated URL/host args) | Prefer **TS** `egress-allowlist.ts` *or* Python pillar (one first; mirror later) | Highest incident value (postmark BCC, Slack unfurl, toxic public PR). Pure in-process. | `EGRESS_DENIED` (−32010 proposed) |
| **A2** | **Concurrency / load shed** | TS `concurrency.ts` (then Python if needed) | Availability = security; O(1); pairs with rate limit / circuit breaker | `CONCURRENCY_LIMIT` / `LOAD_SHED` (−32006) |
| **A3** | **Live `tools/list` description screening** | Python middleware +/or TS wrap of list handler | Closes line-jumping gap; deterministic; complements fingerprint + static scan | Reuse injection/metadata deny taxonomy |
| **A4** | **Memory-write guard (ASI06)** | Land TS prototype if present (`memory-guard.ts`) | Write-path complement to result screening; deterministic floor | −32007 (as designed) |

### P1 — Bounded extensions of existing controls

| ID | Item | Core | Why adopt | Caveat |
|----|------|------|-----------|--------|
| **B1** | Resource/sampling **provenance tags** + optional context eviction hook | Extend TS provenance | Cheap tagging; reduces injection efficacy | Does **not** isolate (no IFC) |
| **B2** | **Data-class-aware egress** (private→untrusted sink) | Python `toxic_flow` extension | Same class as Invariant toxic flows | Needs clear labels; no false “complete” claims |
| **B3** | **Per-parameter business rules** (tenant/amount/env/destination) | Python pillar, config-gated | Stops “allowed tool, wrong args” | Not a replacement for server object-ACL |
| **B4** | Tool catalog **actionTier as metadata** (keep READ/MUTATE/DESTRUCTIVE enforcement) | Config + audit | Policy inputs only | Do not invent a fourth enforcement path |

### P2 — DX / doctor (no new runtime plane)

| ID | Item | Why adopt | Caveat |
|----|------|-----------|--------|
| **C1** | **One-command wrap** entry (`serve` / proxy quickstart → copy-paste client config, secure defaults) | Adoption lever; uses existing controls | Defaults must be **strict**; relaxations explicit |
| **C2** | **`mcp-bastion doctor --host`** (read-only local MCP client config audit) | Complements runtime; zero infra | Advisory snapshot only |

### P3 — Attestation (verify-only, advisory default)

| ID | Item | Why adopt | Caveat |
|----|------|-----------|--------|
| **D1** | **SMCP-class envelope verify + sampling-origin auth** (TS) | Real gap vs self-declared tools | **Never re-sign**; require-mode breaks unsigned fleets → default **advisory** |

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

1. **A1** egress allowlist (TS or Python — pick one, tests + deny code + docs).  
2. **A2** concurrency limiter (TS).  
3. **A3** live tools/list screen.  
4. **A4** memory-guard land + harness.  
5. **B2** toxic_flow / data-class egress.  
6. **C1** secure one-line wrap DX.  
7. **D1** attestation verify (advisory).  

Nothing is “done” without: config off-by-default, fail-closed path, audit/deny code, Vitest or pytest suite, and an honest README/handbook note (mediation + limits).

---

## OWASP / ASI (honest one-liner)

Within MCP-mediated scope: **ASI02** strong; **ASI03/04/06/08** partial→strong as ADOPT items land; **ASI01/05/09** partial with limits; **ASI07/10** delegated. Full row mapping stays in handbook / threat model — do not inflate status in marketing.
