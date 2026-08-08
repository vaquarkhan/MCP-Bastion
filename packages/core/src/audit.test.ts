import { describe, it, expect } from "vitest";
import { AuditChain, hashRecord, type AuditRecord } from "./audit.js";

describe("audit", () => {
  it("genesis prevHash is 64 zeros", () => {
    const chain = new AuditChain();
    const rec = chain.append({
      ts: "2026-08-08T00:00:00.000Z",
      requestId: "r1",
      decision: "allow",
    });
    expect(rec.prevHash).toBe("0".repeat(64));
    expect(rec.hash).toHaveLength(64);
  });

  it("appending records links prevHash to the prior hash", () => {
    const chain = new AuditChain();
    const a = chain.append({
      ts: "2026-08-08T00:00:00.000Z",
      requestId: "r1",
      tool: "add",
      decision: "allow",
    });
    const b = chain.append({
      ts: "2026-08-08T00:00:01.000Z",
      requestId: "r2",
      tool: "add",
      decision: "allow",
    });
    expect(b.prevHash).toBe(a.hash);
  });

  it("verify returns true for an intact chain", () => {
    const chain = new AuditChain();
    const records: AuditRecord[] = [
      chain.append({
        ts: "2026-08-08T00:00:00.000Z",
        requestId: "r1",
        decision: "allow",
      }),
      chain.append({
        ts: "2026-08-08T00:00:01.000Z",
        requestId: "r2",
        decision: "rate_limit",
      }),
    ];
    expect(AuditChain.verify(records)).toBe(true);
  });

  it("tampered decision fails verify", () => {
    const chain = new AuditChain();
    const records: AuditRecord[] = [
      chain.append({
        ts: "2026-08-08T00:00:00.000Z",
        requestId: "r1",
        decision: "allow",
      }),
    ];
    records[0] = { ...records[0], decision: "tampered" };
    expect(AuditChain.verify(records)).toBe(false);
  });

  it("reordered or truncated chain fails verify", () => {
    const chain = new AuditChain();
    const a = chain.append({
      ts: "2026-08-08T00:00:00.000Z",
      requestId: "r1",
      decision: "allow",
    });
    const b = chain.append({
      ts: "2026-08-08T00:00:01.000Z",
      requestId: "r2",
      decision: "allow",
    });
    expect(AuditChain.verify([b, a])).toBe(false);
    expect(AuditChain.verify([b])).toBe(false);
  });

  it("hashRecord is deterministic for the same fields", () => {
    const base = {
      ts: "2026-08-08T00:00:00.000Z",
      requestId: "r1",
      tool: "add",
      decision: "allow",
      prevHash: "0".repeat(64),
    };
    expect(hashRecord(base)).toBe(hashRecord(base));
  });

  it("fromLastRecord resumes the chain across a simulated restart", () => {
    const first = new AuditChain();
    const a = first.append({
      ts: "2026-08-08T00:00:00.000Z",
      requestId: "r1",
      decision: "allow",
    });
    const second = AuditChain.fromLastRecord(a);
    const b = second.append({
      ts: "2026-08-08T00:00:01.000Z",
      requestId: "r2",
      decision: "allow",
    });
    expect(b.prevHash).toBe(a.hash);
    expect(AuditChain.verify([a, b])).toBe(true);
  });

  it("verifyAllowingRestartSegments accepts genesis breaks without seeding", () => {
    const s1 = new AuditChain();
    const a = s1.append({
      ts: "2026-08-08T00:00:00.000Z",
      requestId: "r1",
      decision: "allow",
    });
    const s2 = new AuditChain(); // restart without seed
    const b = s2.append({
      ts: "2026-08-08T00:00:01.000Z",
      requestId: "r2",
      decision: "allow",
    });
    expect(AuditChain.verify([a, b])).toBe(false);
    expect(AuditChain.verifyAllowingRestartSegments([a, b])).toBe(true);
  });
});
