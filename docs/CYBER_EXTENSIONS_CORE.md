# TypeScript cyber extensions (`@mcp-bastion/core`)

Opt-in Extensions **A** (semantic egress), **E** (result provenance / result guard), and **F** (hash-chained audit) for the Node middleware. They preserve Bastion’s **zero-infrastructure** core: no inline model, heavy scoring only via sidecar.

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

  // F — in-memory chain; sink via onAudit (e.g. JSONL)
  enableAudit: true,
  onAudit: (rec) => auditRows.push(rec),
});

// Later: AuditChain.verify(auditRows)
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

TS returns MCP tool results with `isError: true` and a text message (same pattern as prompt guard):

| Feature | Message contains | Design taxonomy |
|---------|------------------|-----------------|
| Semantic quarantine | `quarantined` / `no sidecar URL` / `unavailable` | SEMANTIC_QUARANTINE (−32004 in design notes) |
| Result quarantine | `quarantined` / `no sidecar URL` / `unavailable` | RESULT_QUARANTINE (−32005 in design notes) |

Python JSON-RPC codes for other pillars are listed in the main README; do not conflate them with these TS tool-result messages.

## Provenance markers

When `tagResultProvenance: true`, text content becomes:

```text
<untrusted_tool_result>…original…</untrusted_tool_result>
```

This **reduces** indirect-injection efficacy; it does not enforce isolation.

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
