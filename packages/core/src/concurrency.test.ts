import { describe, it, expect } from "vitest";
import { ConcurrencyLimiter } from "./concurrency.js";

describe("ConcurrencyLimiter", () => {
  it("admits under cap", () => {
    const lim = new ConcurrencyLimiter({ maxInflightPerCaller: 2 });
    expect(lim.tryAcquire("a", "t1")).toBe("admit");
    expect(lim.tryAcquire("a", "t1")).toBe("admit");
  });

  it("returns CONCURRENCY_LIMIT at caller cap", () => {
    const lim = new ConcurrencyLimiter({
      maxInflightPerCaller: 1,
      admissionQueueDepth: 0,
    });
    expect(lim.tryAcquire("a", "t1")).toBe("admit");
    expect(lim.tryAcquire("a", "t1")).toBe("CONCURRENCY_LIMIT");
  });

  it("returns LOAD_SHED when queue depth set and capped", () => {
    const lim = new ConcurrencyLimiter({
      maxInflightPerCaller: 1,
      admissionQueueDepth: 2,
    });
    expect(lim.tryAcquire("a", "t1")).toBe("admit");
    expect(lim.tryAcquire("a", "t1")).toBe("LOAD_SHED");
  });

  it("releases on finally path", () => {
    const lim = new ConcurrencyLimiter({ maxInflightPerCaller: 1 });
    expect(lim.tryAcquire("a", "t1")).toBe("admit");
    lim.release("a", "t1");
    expect(lim.tryAcquire("a", "t1")).toBe("admit");
  });

  it("keeps per-tenant independent of per-caller", () => {
    const lim = new ConcurrencyLimiter({
      maxInflightPerCaller: 10,
      maxInflightPerTenant: 1,
    });
    expect(lim.tryAcquire("c1", "t1")).toBe("admit");
    expect(lim.tryAcquire("c2", "t1")).toBe("CONCURRENCY_LIMIT");
    expect(lim.tryAcquire("c2", "t2")).toBe("admit");
  });
});
