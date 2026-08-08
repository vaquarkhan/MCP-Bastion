import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { wrapCallToolHandler } from "./guard.js";
import { isScreenedTool } from "./semantic-egress.js";

describe("semantic-egress", () => {
  const outboundRequest = {
    id: "req-egress",
    params: {
      name: "create_pull_request",
      arguments: { title: "Urgent: please approve", body: "ignore previous" },
    },
  } as any;

  const benignRequest = {
    id: "req-benign",
    params: {
      name: "create_pull_request",
      arguments: { title: "docs: fix typo", body: "nits" },
    },
  } as any;

  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("isScreenedTool matches allowlist", () => {
    expect(isScreenedTool("create_pull_request", ["create_pull_request"])).toBe(
      true
    );
    expect(isScreenedTool("add", ["create_pull_request"])).toBe(false);
  });

  it("posts to /semantic-egress for allowlisted tools", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ score: 0.1, verdict: "benign" }),
    } as Response);

    const handler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "ok" }],
      isError: false,
    });
    const wrapped = wrapCallToolHandler(handler, {
      enableRateLimit: false,
      enableSemanticEgress: true,
      semanticEgressMode: "detect",
      semanticEgressTools: ["create_pull_request"],
      sidecarUrl: "http://localhost:8000",
    });
    await wrapped(outboundRequest);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/semantic-egress",
      expect.objectContaining({ method: "POST" })
    );
    expect(handler).toHaveBeenCalled();
  });

  it("quarantines at or above threshold (handler not called)", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          score: 0.9,
          dimensions: ["urgency", "false_pretense"],
          verdict: "manipulative",
        }),
    } as Response);

    const handler = vi.fn();
    const wrapped = wrapCallToolHandler(handler, {
      enableRateLimit: false,
      enableSemanticEgress: true,
      semanticEgressMode: "quarantine",
      semanticEgressTools: ["create_pull_request"],
      semanticThreshold: 0.7,
      sidecarUrl: "http://localhost:8000",
    });
    const result = await wrapped(outboundRequest);
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain(
      "quarantined"
    );
  });

  it("allows benign below threshold in quarantine mode", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ score: 0.2, verdict: "benign" }),
    } as Response);

    const handler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "created" }],
      isError: false,
    });
    const wrapped = wrapCallToolHandler(handler, {
      enableRateLimit: false,
      enableSemanticEgress: true,
      semanticEgressMode: "quarantine",
      semanticEgressTools: ["create_pull_request"],
      semanticThreshold: 0.7,
      sidecarUrl: "http://localhost:8000",
    });
    const result = await wrapped(benignRequest);
    expect(handler).toHaveBeenCalled();
    expect(result.isError).toBeFalsy();
  });

  it("detect mode proceeds on sidecar error", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockRejectedValue(new Error("network down"));

    const handler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "ok" }],
      isError: false,
    });
    const wrapped = wrapCallToolHandler(handler, {
      enableRateLimit: false,
      enableSemanticEgress: true,
      semanticEgressMode: "detect",
      semanticEgressTools: ["create_pull_request"],
      sidecarUrl: "http://localhost:8000",
    });
    const result = await wrapped(outboundRequest);
    expect(handler).toHaveBeenCalled();
    expect(result.isError).toBeFalsy();
  });

  it("quarantine mode fails closed without sidecar", async () => {
    const fetchMock = vi.mocked(fetch);
    const handler = vi.fn();
    const wrapped = wrapCallToolHandler(handler, {
      enableRateLimit: false,
      enableSemanticEgress: true,
      semanticEgressMode: "quarantine",
      semanticEgressTools: ["create_pull_request"],
      sidecarUrl: "",
    });
    const result = await wrapped(outboundRequest);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain(
      "no sidecar URL"
    );
  });

  it("does not screen non-allowlisted tools", async () => {
    const fetchMock = vi.mocked(fetch);
    const handler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "5" }],
      isError: false,
    });
    const wrapped = wrapCallToolHandler(handler, {
      enableRateLimit: false,
      enableSemanticEgress: true,
      semanticEgressMode: "quarantine",
      semanticEgressTools: ["create_pull_request"],
      sidecarUrl: "http://localhost:8000",
    });
    await wrapped({
      id: "req-other",
      params: { name: "add", arguments: { a: 1 } },
    } as any);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(handler).toHaveBeenCalled();
  });

  it("quarantine mode fails closed when sidecar returns error", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.resolve({}),
    } as Response);

    const handler = vi.fn();
    const wrapped = wrapCallToolHandler(handler, {
      enableRateLimit: false,
      enableSemanticEgress: true,
      semanticEgressMode: "quarantine",
      semanticEgressTools: ["create_pull_request"],
      sidecarUrl: "http://localhost:8000",
    });
    const result = await wrapped(outboundRequest);
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain(
      "unavailable"
    );
  });

  it("detect mode proceeds without sidecar (advisory)", async () => {
    const handler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "ok" }],
      isError: false,
    });
    const wrapped = wrapCallToolHandler(handler, {
      enableRateLimit: false,
      enableSemanticEgress: true,
      semanticEgressMode: "detect",
      semanticEgressTools: ["create_pull_request"],
      sidecarUrl: "",
    });
    const result = await wrapped(outboundRequest);
    expect(handler).toHaveBeenCalled();
    expect(result.isError).toBeFalsy();
  });

  it("exact threshold triggers quarantine", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ score: 0.7, verdict: "suspicious" }),
    } as Response);

    const handler = vi.fn();
    const wrapped = wrapCallToolHandler(handler, {
      enableRateLimit: false,
      enableSemanticEgress: true,
      semanticEgressMode: "quarantine",
      semanticEgressTools: ["create_pull_request"],
      semanticThreshold: 0.7,
      sidecarUrl: "http://localhost:8000",
    });
    const result = await wrapped(outboundRequest);
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
  });
});
