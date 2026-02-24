import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  wrapCallToolHandler,
  wrapReadResourceHandler,
  wrapWithMcpBastion,
  type McpBastionOptions,
} from "./guard.js";

describe("guard", () => {
  const mockToolRequest = {
    id: "req1",
    params: { name: "add", arguments: { a: 1, b: 2 } },
  } as any;

  const mockResourceRequest = {} as any;

  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete (process as any).env.MCP_BASTION_URL;
  });

  it("uses sidecarUrl when provided and enablePromptGuard true", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ malicious: false }),
    } as Response);

    const handler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "5" }],
      isError: false,
    });
    const wrapped = wrapCallToolHandler(handler, {
      sidecarUrl: "http://localhost:8000",
      enablePromptGuard: true,
      enableRateLimit: false,
    });
    const result = await wrapped(mockToolRequest);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/prompt-guard",
      expect.objectContaining({ method: "POST" })
    );
    expect(handler).toHaveBeenCalled();
    expect(result.content[0]).toHaveProperty("text", "5");
  });

  it("uses MCP_BASTION_URL when sidecarUrl not set", async () => {
    (process as any).env = { ...process.env, MCP_BASTION_URL: "http://env:9000" };
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ malicious: false }),
    } as Response);

    const handler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "ok" }],
      isError: false,
    });
    const wrapped = wrapCallToolHandler(handler, {
      enablePromptGuard: true,
      enableRateLimit: false,
    });
    await wrapped(mockToolRequest);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://env:9000/prompt-guard",
      expect.any(Object)
    );
  });

  it("does not call fetch when sidecarUrl and MCP_BASTION_URL both empty", async () => {
    const fetchMock = vi.mocked(fetch);
    const handler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "3" }],
      isError: false,
    });
    const wrapped = wrapCallToolHandler(handler, {
      enablePromptGuard: true,
      enableRateLimit: false,
      sidecarUrl: "",
    });
    const result = await wrapped(mockToolRequest);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(handler).toHaveBeenCalled();
    expect(result.content[0].text).toBe("3");
  });

  it("returns error when prompt guard says malicious", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ malicious: true }),
    } as Response);

    const handler = vi.fn();
    const wrapped = wrapCallToolHandler(handler, {
      sidecarUrl: "http://localhost:8000",
      enablePromptGuard: true,
      enableRateLimit: false,
    });
    const result = await wrapped(mockToolRequest);
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("prompt injection");
  });

  it("wrapReadResourceHandler with sidecarUrl and PII redaction", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          content: [{ type: "text", text: "redacted" }],
        }),
    } as Response);

    const handler = vi.fn().mockResolvedValue({
      contents: [{ type: "text", text: "raw" }],
    });
    const wrapped = wrapReadResourceHandler(handler, {
      sidecarUrl: "http://localhost:8000",
      enablePiiRedaction: true,
    });
    const result = await wrapped(mockResourceRequest);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/pii-redact",
      expect.any(Object)
    );
    expect(result.contents[0].text).toBe("redacted");
  });

  it("wrapWithMcpBastion patches setRequestHandler", () => {
    const handlers: Record<string, unknown> = {};
    const server = {
      setRequestHandler(schema: any, handler: unknown) {
        const name = schema?.name ?? schema;
        handlers[String(name)] = handler;
      },
    };
    wrapWithMcpBastion(server as any, { enableRateLimit: false });
    server.setRequestHandler("tools/call", () => Promise.resolve({ content: [], isError: false }));
    expect(handlers["tools/call"]).toBeDefined();
  });
});
