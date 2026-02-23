/**
 * MCP-Bastion proxy wrapper for MCP server handlers.
 * Wraps CallTool and ReadResource; rate limit in-process, ML via sidecar.
 */

import type {
  CallToolRequest,
  CallToolResult,
  ReadResourceRequest,
  ReadResourceResult,
} from "@modelcontextprotocol/sdk/types.js";
import { TokenBucketRateLimiter } from "./rate-limit.js";
import { logger } from "./logger.js";

export interface McpBastionOptions {
  maxIterations?: number;
  timeoutMs?: number;
  enableRateLimit?: boolean;
  sidecarUrl?: string;
  enablePromptGuard?: boolean;
  enablePiiRedaction?: boolean;
}

const DEFAULT_OPTIONS: Required<McpBastionOptions> = {
  maxIterations: 15,
  timeoutMs: 60_000,
  enableRateLimit: true,
  sidecarUrl: "",
  enablePromptGuard: false,
  enablePiiRedaction: false,
};

function createMcpError(code: number, message: string): CallToolResult {
  return {
    content: [{ type: "text", text: `[MCP-Bastion] ${message}` }],
    isError: true,
  };
}

/** Resolve sidecar base URL from options or env MCP_BASTION_URL. */
function getSidecarUrl(opts: Required<McpBastionOptions>): string {
  if (opts.sidecarUrl) return opts.sidecarUrl;
  if (typeof process !== "undefined" && process.env?.MCP_BASTION_URL)
    return process.env.MCP_BASTION_URL;
  return "";
}

async function callSidecar(
  baseUrl: string,
  endpoint: "prompt-guard" | "pii-redact",
  payload: unknown
): Promise<unknown> {
  const res = await fetch(`${baseUrl}/${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Sidecar ${endpoint} failed: ${res.status}`);
  }
  return res.json();
}

type CallToolHandler = (request: CallToolRequest) => Promise<CallToolResult>;
type ReadResourceHandler = (
  request: ReadResourceRequest
) => Promise<ReadResourceResult>;

/** Wraps CallTool handler. Rate limit in-process; prompt guard via sidecar. */
export function wrapCallToolHandler(
  handler: CallToolHandler,
  options: McpBastionOptions = {}
): CallToolHandler {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const sidecarUrl = getSidecarUrl(opts);
  const rateLimiter = new TokenBucketRateLimiter(
    opts.maxIterations,
    opts.timeoutMs
  );

  return async (request: CallToolRequest): Promise<CallToolResult> => {
    const requestId = String((request as { id?: string | number }).id ?? "");
    const sessionId = (request.params?._meta as Record<string, string>)?.["session_id"];

    if (opts.enableRateLimit) {
      const { allowed, error } = rateLimiter.checkIteration(
        requestId,
        sessionId
      );
      if (!allowed) {
        logger.warn("rate_limit_blocked", requestId, sessionId, error);
        return createMcpError(-32002, error ?? "Rate limit exceeded");
      }
    }

    if (opts.enablePromptGuard && sidecarUrl) {
      try {
        const args = request.params?.arguments ?? {};
        const text = JSON.stringify(args);
        const result = (await callSidecar(
          sidecarUrl,
          "prompt-guard",
          { text }
        )) as { malicious?: boolean };
        if (result?.malicious) {
          logger.warn("prompt_injection_blocked", requestId);
          return createMcpError(
            -32001,
            "Request blocked: potential prompt injection detected"
          );
        }
      } catch (err) {
        logger.warn("prompt_guard_sidecar_unavailable", err);
        return createMcpError(-32001, "Prompt guard sidecar unavailable");
      }
    }

    rateLimiter.consumeIteration(requestId, sessionId);

    let result = await handler(request);

    if (opts.enablePiiRedaction && sidecarUrl && result?.content) {
      try {
        const redacted = (await callSidecar(
          sidecarUrl,
          "pii-redact",
          { content: result.content }
        )) as { content?: CallToolResult["content"] };
        if (redacted?.content) {
          result = { ...result, content: redacted.content };
        }
      } catch {
        return result;
      }
    }

    return result;
  };
}

/** Wraps ReadResource handler. PII redaction via sidecar when enabled. */
export function wrapReadResourceHandler(
  handler: ReadResourceHandler,
  options: McpBastionOptions = {}
): ReadResourceHandler {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const sidecarUrl = getSidecarUrl(opts);

  return async (request: ReadResourceRequest): Promise<ReadResourceResult> => {
    const result = await handler(request);

    if (opts.enablePiiRedaction && sidecarUrl && result?.contents) {
      try {
        const redacted = (await callSidecar(
          sidecarUrl,
          "pii-redact",
          { content: result.contents }
        )) as { content?: ReadResourceResult["contents"] };
        if (redacted?.content) {
          return { ...result, contents: redacted.content };
        }
      } catch {
        return result;
      }
    }

    return result;
  };
}

/** Patches setRequestHandler to wrap CallTool and ReadResource handlers. */
export function wrapWithMcpBastion<T extends { setRequestHandler: (schema: unknown, handler: unknown) => void }>(
  server: T,
  options: McpBastionOptions = {}
): T {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const original = server.setRequestHandler.bind(server);

  server.setRequestHandler = function (
    schema: unknown,
    handler: unknown
  ): void {
    const schemaStr = String((schema as { name?: string })?.name ?? schema);
    if (schemaStr.includes("CallTool") || schemaStr.includes("tools/call")) {
      return original(
        schema,
        wrapCallToolHandler(handler as CallToolHandler, opts)
      );
    }
    if (schemaStr.includes("ReadResource") || schemaStr.includes("resources/read")) {
      return original(
        schema,
        wrapReadResourceHandler(handler as ReadResourceHandler, opts)
      );
    }
    return original(schema, handler);
  } as T["setRequestHandler"];

  return server;
}
