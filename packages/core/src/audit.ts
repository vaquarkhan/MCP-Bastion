/**
 * Append-only, hash-chained audit. Tamper-evident, not tamper-proof.
 *
 * Honest scope: a compromised host can stop logging or truncate; the chain
 * proves records were not altered undetected, not that none were omitted.
 * Do not claim immutability without an external seal.
 */

import { createHash } from "node:crypto";

export interface AuditRecord {
  ts: string;
  requestId: string;
  tool?: string;
  decision: string;
  prevHash: string;
  hash?: string;
}

/** SHA-256 over a canonical JSON subset (order-stable keys). */
export function hashRecord(rec: Omit<AuditRecord, "hash">): string {
  const canonical = JSON.stringify({
    ts: rec.ts,
    requestId: rec.requestId,
    tool: rec.tool ?? "",
    decision: rec.decision,
    prevHash: rec.prevHash,
  });
  return createHash("sha256").update(canonical).digest("hex");
}

export class AuditChain {
  private prev = "0".repeat(64);

  append(entry: Omit<AuditRecord, "prevHash" | "hash">): AuditRecord {
    const base = { ...entry, prevHash: this.prev };
    const hash = hashRecord(base);
    this.prev = hash;
    return { ...base, hash };
  }

  /** Offline verify: linked prevHash and recomputed digests. */
  static verify(records: AuditRecord[]): boolean {
    let prev = "0".repeat(64);
    for (const r of records) {
      if (r.prevHash !== prev) return false;
      const { hash, ...rest } = r;
      if (hashRecord(rest) !== hash) return false;
      prev = hash!;
    }
    return true;
  }
}
