import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { scoreEgress, isScreenedTool } from "./semantic-egress.js";

describe("semantic-egress unit", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("scoreEgress returns parsed verdict", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          score: 0.42,
          dimensions: ["urgency"],
          verdict: "suspicious",
        }),
    } as Response);

    const v = await scoreEgress("http://localhost:9", "hello", 500);
    expect(v.score).toBe(0.42);
    expect(v.dimensions).toEqual(["urgency"]);
    expect(v.verdict).toBe("suspicious");
  });

  it("scoreEgress throws on non-ok response", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 503,
      json: () => Promise.resolve({}),
    } as Response);

    await expect(scoreEgress("http://localhost:9", "x", 500)).rejects.toThrow(
      /503/
    );
  });

  it("scoreEgress aborts on timeout", async () => {
    vi.mocked(fetch).mockImplementation(
      (_url: any, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          const signal = init?.signal;
          if (signal?.aborted) {
            reject(new DOMException("Aborted", "AbortError"));
            return;
          }
          signal?.addEventListener("abort", () => {
            reject(new DOMException("Aborted", "AbortError"));
          });
        }) as Promise<Response>
    );

    await expect(scoreEgress("http://localhost:9", "x", 20)).rejects.toThrow();
  });

  it("isScreenedTool is exact-name match only", () => {
    expect(isScreenedTool("create_pull_request", ["create_pull_request"])).toBe(
      true
    );
    expect(isScreenedTool("Create_Pull_Request", ["create_pull_request"])).toBe(
      false
    );
    expect(isScreenedTool("", [])).toBe(false);
  });
});
