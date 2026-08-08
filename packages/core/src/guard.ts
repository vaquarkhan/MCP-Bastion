/**
 * MCP-Bastion proxy wrapper for MCP server handlers.
 * Wraps CallTool and ReadResource; rate limit in-process, ML via sidecar.
 *
 * Mediation precondition: controls apply only to MCP traffic that flows
 * through these wrappers. Out-of-band execution (shell / code-exec) is out of
 * scope — capability reduction and an OS sandbox address that path.
 */

import type {
  CallToolRequest,
  CallToolResult,
  ReadResourceRequest,
  ReadResourceResult,
} from "@modelcontextprotocol/sdk/types.js";
import { TokenBucketRateLimiter } from "./rate-limit.js";
import { logger } from "./logger.js";
import { scoreEgress, isScreenedTool } from "./semantic-egress.js";
import { tagResultProvenance, scanResult } from "./result-guard.js";
import { AuditChain, type AuditRecord } from "./audit.js";

export interface McpBastionOptions {
  maxIterations?: number;
  timeoutMs?: number;
  enableRateLimit?: boolean;
  sidecarUrl?: string;
  enablePromptGuard?: boolean;
  enablePiiRedaction?: boolean;
  /** Opt-in semantic egress screen (sidecar). Default false. */
  enableSemanticEgress?: boolean;
  /** detect = log only; quarantine = block high scores. Default detect. */
  semanticEgressMode?: "detect" | "quarantine";
  /** Tool names to screen (empty = screen none). */
  semanticEgressTools?: string[];
  /** Quarantine when score >= threshold. Default 0.7. */
  semanticThreshold?: number;
  /** Sidecar timeout for semantic egress. Default 800ms. */
  semanticTimeoutMs?: number;
  /** Wrap tool result text in untrusted markers. Deterministic, no sidecar. */
  tagResultProvenance?: boolean;
  /** Opt-in result-side semantic scan via sidecar. Default false. */
  enableResultGuard?: boolean;
  /** detect = log; strict = block. Default detect. */
  resultGuardMode?: "detect" | "strict";
  /** Sidecar timeout for result guard. Default 800ms. */
  resultGuardTimeoutMs?: number;
  /** Append hash-chained audit records in-memory (tamper-evident). */
  enableAudit?: boolean;
  /** Optional sink for each audit record (e.g. append JSONL). Zero-infra. */
  onAudit?: (record: AuditRecord) => void;
}

const DEFAULT_OPTIONS: Required<McpBastionOptions> = {
  maxIterations: 15,
  timeoutMs: 60_000,
  enableRateLimit: true,
  sidecarUrl: "",
  enablePromptGuard: false,
  enablePiiRedaction: false,
  enableSemanticEgress: false,
  semanticEgressMode: "detect",
  semanticEgressTools: [],
  semanticThreshold: 0.7,
  semanticTimeoutMs: 800,
  tagResultProvenance: false,
  enableResultGuard: false,
  resultGuardMode: "detect",
  resultGuardTimeoutMs: 800,
  enableAudit: false,
  onAudit: (() => undefined) as Required<McpBastionOptions>["onAudit"],
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

/** Wraps CallTool handler. Rate limit in-process; ML features via sidecar. */
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
  const audit = opts.enableAudit ? new AuditChain() : null;

  return async (request: CallToolRequest): Promise<CallToolResult> => {
    const requestId = String((request as { id?: string | number }).id ?? "");
    const sessionId = (request.params?._meta as Record<string, string>)?.["session_id"];
    const toolName = request.params?.name ?? "";

    const record = (decision: string) => {
      if (!audit) return;
      const entry = audit.append({
        ts: new Date().toISOString(),
        requestId,
        tool: toolName || undefined,
        decision,
      });
      try {
        opts.onAudit(entry);
      } catch {
        // Audit sink must never break the request path.
      }
    };

    if (opts.enableRateLimit) {
      const { allowed, error } = rateLimiter.checkIteration(
        requestId,
        sessionId
      );
      if (!allowed) {
        logger.warn("rate_limit_blocked", requestId, sessionId, error);
        record("rate_limit");
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
          record("prompt_injection");
          return createMcpError(
            -32001,
            "Request blocked: potential prompt injection detected"
          );
        }
      } catch (err) {
        logger.warn("prompt_guard_sidecar_unavailable", err);
        record("prompt_guard_unavailable");
        return createMcpError(-32001, "Prompt guard sidecar unavailable");
      }
    } else if (opts.enablePromptGuard && !sidecarUrl) {
      logger.error(
        "prompt_guard_enabled_without_sidecar",
        "enablePromptGuard is true but sidecarUrl/MCP_BASTION_URL is empty — failing closed"
      );
      record("prompt_guard_no_sidecar");
      return createMcpError(
        -32001,
        "Prompt guard enabled but no sidecar URL (set sidecarUrl or MCP_BASTION_URL)"
      );
    }

    // Extension A: semantic egress — after prompt guard, before consume/handler.
    // detect = async advisory (never blocks on sidecar error).
    // quarantine = sync fail-closed for the explicit tool allowlist only.
    if (
      opts.enableSemanticEgress &&
      isScreenedTool(toolName, opts.semanticEgressTools)
    ) {
      if (!sidecarUrl) {
        if (opts.semanticEgressMode === "quarantine") {
          record("semantic_egress_no_sidecar");
          return createMcpError(
            -32004,
            "Semantic egress quarantine enabled but no sidecar URL"
          );
        }
        logger.warn("semantic_egress_no_sidecar_detect_only", toolName);
      } else {
        try {
          const verdict = await scoreEgress(
            sidecarUrl,
            JSON.stringify(request.params?.arguments ?? {}),
            opts.semanticTimeoutMs
          );
          logger.warn(
            "semantic_egress_score",
            toolName,
            verdict.score,
            verdict.dimensions
          );
          if (
            opts.semanticEgressMode === "quarantine" &&
            verdict.score >= opts.semanticThreshold
          ) {
            record("semantic_quarantine");
            return createMcpError(
              -32004,
              "Request quarantined: outbound payload flagged as manipulative"
            );
          }
        } catch (err) {
          if (opts.semanticEgressMode === "quarantine") {
            record("semantic_egress_unavailable");
            return createMcpError(
              -32004,
              "Semantic egress sidecar unavailable"
            );
          }
          logger.warn("semantic_egress_sidecar_error_detect", toolName, err);
        }
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
        // PII redaction is best-effort; return unredacted on sidecar failure.
      }
    }

    // Extension E: result-side provenance + optional sidecar scan.
    if (opts.tagResultProvenance) {
      result = tagResultProvenance(result);
    }

    if (opts.enableResultGuard) {
      if (!sidecarUrl) {
        if (opts.resultGuardMode === "strict") {
          record("result_guard_no_sidecar");
          return createMcpError(
            -32005,
            "Result guard strict mode enabled but no sidecar URL"
          );
        }
        logger.warn("result_guard_no_sidecar_detect_only", toolName);
      } else {
        try {
          const scan = await scanResult(
            sidecarUrl,
            result,
            opts.resultGuardTimeoutMs
          );
          if (scan?.malicious) {
            logger.warn("result_guard_blocked", toolName);
            if (opts.resultGuardMode === "strict") {
              record("result_quarantine");
              return createMcpError(
                -32005,
                "Tool result quarantined: embedded instructions detected"
              );
            }
          }
        } catch (err) {
          if (opts.resultGuardMode === "strict") {
            record("result_guard_unavailable");
            return createMcpError(
              -32005,
              "Result guard sidecar unavailable"
            );
          }
          logger.warn("result_guard_sidecar_error_detect", err);
        }
      }
    }

    record("allow");
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
