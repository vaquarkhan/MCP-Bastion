# TypeScript cyber extensions (`@mcp-bastion/core`)

Opt-in Extensions **A** (semantic egress), **E** (result provenance / result guard), **F** (hash-chained audit), plus ADOPT controls (egress allowlist, concurrency, memory guard, tools/list screen, attestation verify, resource provenance) for the Node middleware. They preserve Bastion’s **zero-infrastructure** core: no inline model, heavy scoring only via sidecar.

**Working backlog (nature-preserving ADOPT / DEFER / DISCARD):** [CYBER_EXTENSIONS_BACKLOG.md](CYBER_EXTENSIONS_BACKLOG.md).

## Mediation precondition (read first)

These controls apply **only** to MCP traffic that flows through `wrapWithMcpBastion` / `wrapCallToolHandler`.  
Out-of-band shell or code-exec **never** hits them. For that path use **capability reduction** and a separate OS sandbox — not a Bastion feature.

## Honest claims

| Extension | What it does | What it does **not** claim |
|-----------|--------------|----------------------------|
| **A** Semantic egress | Sidecar-scored screen of allowlisted outbound tools; `detect` (default) or `quarantine` | Prevents social engineering; sees non-MCP egress |
| **E** Result provenance / guard | Tags tool results as untrusted; optional sidecar scan | Isolates content (needs IFC in the agent runtime) |
| **F** Audit chain | Tamper-evident SHA-256 chain + offline `verify` | Tamper-proof / immutable without an external seal |

## Quick start

```typescript
import { wrapWithMcpBastion, AuditChain } from "@mcp-bastion/core";

const auditRows: Parameters<NonNullable<Parameters<typeof wrapWithMcpBastion>[1]["onAudit"]>>[0][] = [];

wrapWithMcpBastion(server, {
  enableRateLimit: true,
  sidecarUrl: process.env.MCP_BASTION_URL || "",

  // A — advisory by default
  enableSemanticEgress: true,
  semanticEgressMode: "detect", // or "quarantine" for a tiny high-risk allowlist
  semanticEgressTools: ["create_pull_request", "send_email", "post_comment"],
  semanticThreshold: 0.7,
  semanticTimeoutMs: 800,

  // E — in-process tags; optional sidecar
  tagResultProvenance: true,
  enableResultGuard: true,
  resultGuardMode: "detect", // or "strict"
  resultGuardTimeoutMs: 800,

  // F — in-memory chain; sink via onAudit (e.g. JSONL).
  // After restart: AuditChain.fromLastRecord(lastJsonlRow) so verify() stays continuous.
  enableAudit: true,
  onAudit: (rec) => auditRows.push(rec),

  // ADOPT (all off by default) — examples:
  // enableEgressAllowlist: true, egressAllowedHosts: ["api.example.com"],
  // enableConcurrencyLimit: true, maxInflightPerCaller: 8,
  // enableMemoryGuard: true,
  // enableToolsListScreen: true,
  // tagResourceProvenance: true,
  // enableAttestation: true, attestationMode: "advisory",
});

// Later: AuditChain.verify(auditRows)
// Or, if unseeded across restarts: AuditChain.verifyAllowingRestartSegments(auditRows)
```

## Sidecar endpoints

| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/semantic-egress` | `{ "text": "..." }` | `{ "score": 0..1, "dimensions"?: string[], "verdict"?: "benign"\|"suspicious"\|"manipulative" }` |
| POST | `/result-guard` | `{ "content": [...] }` | `{ "malicious"?: boolean }` |

Existing: `/prompt-guard`, `/pii-redact`.

When `quarantine` / `strict` is on and the sidecar is missing or errors → **fail closed**.  
When `detect` is on → log and continue (average path stays fast).

## Error messages (TypeScript)

TS returns MCP tool results with `isError: true`. The deny **code is included in the text** and in `_meta.bastionDenyCode`:

```text
[MCP-Bastion][-32005] Tool result quarantined: …
```

| Feature | Message contains | Deny code |
|---------|------------------|-----------|
| Prompt / rate (existing) | message text | −32001 / −32002 |
| Semantic quarantine | `quarantined` / `no sidecar URL` / `unavailable` | −32004 |
| Result quarantine | `quarantined` / `no sidecar URL` / `unavailable` | −32005 |
| Concurrency / load shed | `concurrency limit` / `load shed` (`_meta.bastionDenyReason`) | −32006 |
| Memory write guard | `Memory write blocked` | −32007 |
| Attestation (require mode) | `attestation` | −32009 |
| Egress allowlist | `egress destination not allowlisted` | −32010 |

Python JSON-RPC codes for other pillars are listed in the main README; do not conflate them with these TS tool-result messages. TS codes above are **stack-local** to `@mcp-bastion/core`.

## Provenance markers

When `tagResultProvenance: true`, text content becomes:

```text
<untrusted_tool_result>…original…</untrusted_tool_result>
```

This **reduces** indirect-injection efficacy; it does not enforce isolation.  
When both result-guard and tagging are enabled, the sidecar scan runs on the **raw** result, then tags are applied.

## Audit chain restarts (Extension F)

`AuditChain` keeps `prev` **in memory** per wrapper instance. After a process restart it reseeds to genesis (`64` zeros) unless you resume:

```typescript
import { AuditChain, type AuditRecord } from "@mcp-bastion/core";
import fs from "node:fs";

function lastPersisted(): AuditRecord | null {
  const lines = fs.readFileSync("audit.jsonl", "utf8").trim().split("\n");
  if (!lines[0]) return null;
  return JSON.parse(lines[lines.length - 1]) as AuditRecord;
}

const chain = AuditChain.fromLastRecord(lastPersisted());
// use this chain (or pass seed into your onAudit wiring) so JSONL stays one continuous verify()
```

- Prefer **seed on startup** so `AuditChain.verify(allRows)` succeeds across restarts.
- If you did not seed, the file is multiple **segments**; use `AuditChain.verifyAllowingRestartSegments(rows)` instead of `verify`.

## Tests

```bash
npm test --workspace=@mcp-bastion/core
npm run build --workspace=@mcp-bastion/core
```

Suites: `semantic-egress*.test.ts`, `result-guard.test.ts`, `audit.test.ts`, `cyber-extensions.e2e.test.ts`, plus existing `guard.test.ts`.

## Related

- Package README: [packages/core/README.md](../packages/core/README.md)
- Tutorials: [TUTORIALS.md](TUTORIALS.md) (Tutorial 2)
- Multi-language scope: [MULTI_LANGUAGE_SUITE.md](MULTI_LANGUAGE_SUITE.md)

## Ownership note (TS vs Python)

These A/E/F controls live in **`@mcp-bastion/core` (TypeScript)** for Node MCP servers. The **Python** runtime already ships a separate audit hash chain, attestation, circuit breaker, PII vault, etc. Prefer the language stack you wrap: do not assume this TS chain replaces Python’s, and do not duplicate both on the same path unless you intend two independent evidence streams.

## Acknowledged follow-ups (out of this PR)

- PII redaction on sidecar failure remains **best-effort / fail-open** (returns unredacted). Label as such; fail-closed is a separate product decision.
- Concurrency caps / Extension G (if enabled elsewhere): caller identity from client `_meta` is only trustworthy when assigned by an authenticated upstream.
