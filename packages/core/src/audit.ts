/**
 * Append-only, hash-chained audit. Tamper-evident, not tamper-proof.
 *
 * Honest scope: a compromised host can stop logging or truncate; the chain
 * proves records were not altered undetected, not that none were omitted.
 * Do not claim immutability without an external seal.
 *
 * Process restarts: in-memory `prev` reseeds to genesis unless you pass
 * `seedPrevHash` / `AuditChain.fromLastRecord(...)` from the last persisted
 * JSONL row. Without seeding, a file spanning restarts is multiple segments —
 * use `verifyAllowingRestartSegments` or seed on startup.
 */

import { createHash } from "node:crypto";

const GENESIS = "0".repeat(64);

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

function isSha256Hex(value: string | undefined): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/i.test(value);
}

export class AuditChain {
  private prev: string;

  constructor(options?: { seedPrevHash?: string }) {
    const seed = options?.seedPrevHash;
    this.prev = isSha256Hex(seed) ? seed.toLowerCase() : GENESIS;
  }

  /**
   * Resume after a process restart from the last persisted record's hash.
   * Pass `null`/`undefined` to start a new genesis segment.
   */
  static fromLastRecord(
    last: Pick<AuditRecord, "hash"> | null | undefined
  ): AuditChain {
    return new AuditChain({ seedPrevHash: last?.hash });
  }

  append(entry: Omit<AuditRecord, "prevHash" | "hash">): AuditRecord {
    const base = { ...entry, prevHash: this.prev };
    const hash = hashRecord(base);
    this.prev = hash;
    return { ...base, hash };
  }

  /** Offline verify: single continuous segment starting at genesis. */
  static verify(records: AuditRecord[]): boolean {
    let prev = GENESIS;
    for (const r of records) {
      if (r.prevHash !== prev) return false;
      const { hash, ...rest } = r;
      if (hashRecord(rest) !== hash) return false;
      prev = hash!;
    }
    return true;
  }

  /**
   * Verify a log that may contain multiple genesis segments (one per process
   * lifetime when the chain was not seeded from disk). Within each segment,
   * linkage and digests must still hold.
   */
  static verifyAllowingRestartSegments(records: AuditRecord[]): boolean {
    let prev = GENESIS;
    for (const r of records) {
      if (r.prevHash !== prev) {
        if (r.prevHash !== GENESIS) return false;
        prev = GENESIS;
      }
      const { hash, ...rest } = r;
      if (hashRecord(rest) !== hash) return false;
      prev = hash!;
    }
    return true;
  }
}
