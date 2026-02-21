import { describe, it, expect } from "vitest";
import { TokenBucketRateLimiter } from "./rate-limit.js";

describe("TokenBucketRateLimiter", () => {
  it("allows iterations within limit", () => {
    const limiter = new TokenBucketRateLimiter(3, 120_000);
    for (let i = 0; i < 3; i++) {
      const { allowed } = limiter.checkIteration("req1");
      expect(allowed).toBe(true);
      limiter.consumeIteration("req1");
    }
  });

  it("blocks when iteration cap exceeded", () => {
    const limiter = new TokenBucketRateLimiter(2, 120_000);
    limiter.consumeIteration("req2");
    limiter.consumeIteration("req2");
    const { allowed, error } = limiter.checkIteration("req2");
    expect(allowed).toBe(false);
    expect(error).toContain("Maximum iterations");
  });

  it("resets session when resetSession called", () => {
    const limiter = new TokenBucketRateLimiter(1, 120_000);
    limiter.consumeIteration("req3");
    limiter.resetSession("req3");
    const { allowed } = limiter.checkIteration("req3");
    expect(allowed).toBe(true);
  });
});
