/**
 * MCP-Bastion proxy wrapper for MCP server handlers.
 * Wraps CallTool, ReadResource, and optionally ListTools.
 *
 * Mediation precondition: controls apply only to MCP traffic that flows
 * through these wrappers. Out-of-band execution (shell / code-exec) is out of
 * scope — capability reduction and an OS sandbox address that path.
 */

import type {
  CallToolRequest,
  CallToolResult,
  ListToolsRequest,
  ListToolsResult,
  ReadResourceRequest,
  ReadResourceResult,
} from "@modelcontextprotocol/sdk/types.js";
import { TokenBucketRateLimiter } from "./rate-limit.js";
import { logger } from "./logger.js";
import { scoreEgress, isScreenedTool } from "./semantic-egress.js";
import { tagResultProvenance, scanResult } from "./result-guard.js";
import { tagResourceProvenance } from "./provenance.js";
import { AuditChain, type AuditRecord } from "./audit.js";
import {
  checkEgressAllowlist,
  EGRESS_DENIED_CODE,
} from "./egress-allowlist.js";
import {
  ConcurrencyLimiter,
  CONCURRENCY_LIMIT_CODE,
  LOAD_SHED_CODE,
} from "./concurrency.js";
import {
  checkMemoryWrite,
  MEMORY_GUARD_CODE,
} from "./memory-guard.js";
import {
  AttestationVerifier,
  ATTESTATION_FAILED_CODE,
  samplingOriginAllowed,
  type AttestationMode,
  type ServerAttestation,
} from "./attestation.js";
import {
  screenToolsList,
  TOOL_LIST_POISON_CODE,
  type ListScreenAction,
} from "./tools-list-screen.js";

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
  /** Tag resource read text with provenance markers. Default false. */
  tagResourceProvenance?: boolean;
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
  /** Opt-in default-deny egress host allowlist. Default false. */
  enableEgressAllowlist?: boolean;
  /** Allowed destination hostnames (exact or *.suffix). */
  egressAllowedHosts?: string[];
  egressToolHints?: string[];
  /** Opt-in concurrency / load shed. Default false. */
  enableConcurrencyLimit?: boolean;
  maxInflightPerCaller?: number;
  maxInflightPerTenant?: number;
  admissionQueueDepth?: number;
  /** Opt-in ASI06 memory write guard. Default false. */
  enableMemoryGuard?: boolean;
  memoryToolHints?: string[];
  memoryProtectedKeyGlobs?: string[];
  memoryImmutableKeyBaselines?: Record<string, string>;
  /** Opt-in live tools/list screening. Default false. */
  enableToolsListScreen?: boolean;
  toolsListScreenAction?: ListScreenAction;
  /** Opt-in attestation verify. Default false; mode advisory. */
  enableAttestation?: boolean;
  attestationMode?: AttestationMode;
  attestationRoots?: ServerAttestation[];
  /** Shared concurrency limiter (tests / multi-handler). */
  concurrencyLimiter?: ConcurrencyLimiter;
  /** Shared attestation verifier. */
  attestationVerifier?: AttestationVerifier;
}

const DEFAULT_OPTIONS: Required<
  Omit<
    McpBastionOptions,
    | "concurrencyLimiter"
    | "attestationVerifier"
    | "memoryImmutableKeyBaselines"
    | "egressToolHints"
    | "memoryToolHints"
    | "memoryProtectedKeyGlobs"
    | "attestationRoots"
  >
> & {
  concurrencyLimiter: ConcurrencyLimiter | null;
  attestationVerifier: AttestationVerifier | null;
  memoryImmutableKeyBaselines: Record<string, string>;
  egressToolHints: string[];
  memoryToolHints: string[];
  memoryProtectedKeyGlobs: string[];
  attestationRoots: ServerAttestation[];
} = {
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
  tagResourceProvenance: false,
  enableResultGuard: false,
  resultGuardMode: "detect",
  resultGuardTimeoutMs: 800,
  enableAudit: false,
  onAudit: (() => undefined) as Required<McpBastionOptions>["onAudit"],
  enableEgressAllowlist: false,
  egressAllowedHosts: [],
  egressToolHints: [],
  enableConcurrencyLimit: false,
  maxInflightPerCaller: 8,
  maxInflightPerTenant: 32,
  admissionQueueDepth: 0,
  enableMemoryGuard: false,
  memoryToolHints: [],
  memoryProtectedKeyGlobs: [],
  memoryImmutableKeyBaselines: {},
  enableToolsListScreen: false,
  toolsListScreenAction: "remove_tool",
  enableAttestation: false,
  attestationMode: "advisory",
  attestationRoots: [],
  concurrencyLimiter: null,
  attestationVerifier: null,
};

function createMcpError(
  code: number,
  message: string,
  reason?: string
): CallToolResult {
  return {
    content: [{ type: "text", text: `[MCP-Bastion][${code}] ${message}` }],
    isError: true,
    _meta: {
      bastionDenyCode: code,
      ...(reason ? { bastionDenyReason: reason } : {}),
    },
  };
}

/** Resolve sidecar base URL from options or env MCP_BASTION_URL. */
function getSidecarUrl(opts: typeof DEFAULT_OPTIONS): string {
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
type ListToolsHandler = (
  request: ListToolsRequest
) => Promise<ListToolsResult>;

function mergeOpts(options: McpBastionOptions): typeof DEFAULT_OPTIONS {
  return { ...DEFAULT_OPTIONS, ...options };
}

function metaField(
  request: { params?: { _meta?: unknown } },
  key: string
): string | undefined {
  const meta = request.params?._meta as Record<string, unknown> | undefined;
  const v = meta?.[key];
  return typeof v === "string" ? v : undefined;
}

/** Wraps CallTool handler. Rate limit in-process; ML features via sidecar. */
export function wrapCallToolHandler(
  handler: CallToolHandler,
  options: McpBastionOptions = {}
): CallToolHandler {
  const opts = mergeOpts(options);
  const sidecarUrl = getSidecarUrl(opts);
  const rateLimiter = new TokenBucketRateLimiter(
    opts.maxIterations,
    opts.timeoutMs
  );
  const audit = opts.enableAudit ? new AuditChain() : null;
  const concurrency =
    opts.concurrencyLimiter ||
    (opts.enableConcurrencyLimit
      ? new ConcurrencyLimiter({
          maxInflightPerCaller: opts.maxInflightPerCaller,
          maxInflightPerTenant: opts.maxInflightPerTenant,
          admissionQueueDepth: opts.admissionQueueDepth,
        })
      : null);
  const attestation =
    opts.attestationVerifier ||
    (opts.enableAttestation
      ? new AttestationVerifier(opts.attestationRoots)
      : null);

  return async (request: CallToolRequest): Promise<CallToolResult> => {
    const requestId = String((request as { id?: string | number }).id ?? "");
    const sessionId = metaField(request, "session_id");
    const callerId =
      metaField(request, "caller_id") ||
      metaField(request, "agent_id") ||
      sessionId ||
      requestId;
    const tenantId =
      metaField(request, "tenant_id") || metaField(request, "tenant") || "default";
    const toolName = request.params?.name ?? "";
    const serverId = metaField(request, "server_id") || metaField(request, "mcp_server");

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

    let acquired = false;
    try {
      if (opts.enableConcurrencyLimit && concurrency) {
        const admit = concurrency.tryAcquire(callerId, tenantId);
        if (admit === "CONCURRENCY_LIMIT") {
          record("concurrency_limit");
          return createMcpError(
            CONCURRENCY_LIMIT_CODE,
            "Request blocked: concurrency limit exceeded",
            "CONCURRENCY_LIMIT"
          );
        }
        if (admit === "LOAD_SHED") {
          record("load_shed");
          return createMcpError(
            LOAD_SHED_CODE,
            "Request blocked: load shed (admission queue full)",
            "LOAD_SHED"
          );
        }
        acquired = true;
      }

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

      if (opts.enableAttestation && attestation) {
        const samplingOk = samplingOriginAllowed(
          {
            authenticated: metaField(request, "sampling_authenticated") === "true",
            serverId,
          },
          opts.attestationMode
        );
        if (!samplingOk) {
          record("attestation_sampling_origin");
          return createMcpError(
            ATTESTATION_FAILED_CODE,
            "Request blocked: sampling origin not authenticated",
            "ATTESTATION_FAILED"
          );
        }
        if (serverId && !attestation.toolAllowed(serverId, toolName)) {
          if (opts.attestationMode === "require") {
            record("attestation_tool_denied");
            return createMcpError(
              ATTESTATION_FAILED_CODE,
              `Request blocked: tool ${toolName} not on attested allowlist`,
              "ATTESTATION_FAILED"
            );
          }
          logger.warn("attestation_tool_advisory", serverId, toolName);
        }
        const sig = metaField(request, "attestation_signature");
        if (sig && serverId) {
          const verdict = attestation.verifyEnvelope({
            serverId,
            payload: {
              tool: toolName,
              arguments: request.params?.arguments ?? {},
            },
            signatureBase64: sig,
          });
          if (!verdict.ok) {
            if (opts.attestationMode === "require") {
              record("attestation_failed");
              return createMcpError(
                ATTESTATION_FAILED_CODE,
                `Request blocked: attestation failed (${verdict.reason})`,
                "ATTESTATION_FAILED"
              );
            }
            logger.warn("attestation_advisory_fail", serverId, verdict.reason);
          }
        } else if (opts.attestationMode === "require") {
          record("attestation_missing");
          return createMcpError(
            ATTESTATION_FAILED_CODE,
            "Request blocked: attestation required but missing",
            "ATTESTATION_FAILED"
          );
        }
      }

      if (opts.enablePromptGuard && sidecarUrl) {
        try {
          const args = request.params?.arguments ?? {};
          const text = JSON.stringify(args);
          const result = (await callSidecar(sidecarUrl, "prompt-guard", {
            text,
          })) as { malicious?: boolean };
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

      if (opts.enableEgressAllowlist) {
        const egress = checkEgressAllowlist(
          toolName,
          request.params?.arguments ?? {},
          {
            allowedHosts: opts.egressAllowedHosts,
            egressToolHints: opts.egressToolHints.length
              ? opts.egressToolHints
              : undefined,
          }
        );
        if (!egress.ok) {
          record("egress_denied");
          return createMcpError(
            EGRESS_DENIED_CODE,
            `Request blocked: egress destination not allowlisted (${egress.deniedHost})`,
            "EGRESS_DENIED"
          );
        }
      }

      if (opts.enableMemoryGuard) {
        const mem = await checkMemoryWrite(
          toolName,
          request.params?.arguments ?? {},
          {
            memoryToolHints: opts.memoryToolHints.length
              ? opts.memoryToolHints
              : undefined,
            protectedKeyGlobs: opts.memoryProtectedKeyGlobs.length
              ? opts.memoryProtectedKeyGlobs
              : undefined,
            immutableKeyBaselines: opts.memoryImmutableKeyBaselines,
          }
        );
        if (!mem.ok) {
          record("memory_guard");
          return createMcpError(MEMORY_GUARD_CODE, mem.reason, "MEMORY_GUARD");
        }
      }

      // Extension A: semantic egress — after prompt guard, before consume/handler.
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
          const redacted = (await callSidecar(sidecarUrl, "pii-redact", {
            content: result.content,
          })) as { content?: CallToolResult["content"] };
          if (redacted?.content) {
            result = { ...result, content: redacted.content };
          }
        } catch {
          // PII redaction is best-effort; return unredacted on sidecar failure.
        }
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

      if (opts.tagResultProvenance) {
        result = tagResultProvenance(result);
      }

      record("allow");
      return result;
    } finally {
      if (acquired && concurrency) {
        concurrency.release(callerId, tenantId);
      }
    }
  };
}

/** Wraps ReadResource handler. PII + optional provenance. */
export function wrapReadResourceHandler(
  handler: ReadResourceHandler,
  options: McpBastionOptions = {}
): ReadResourceHandler {
  const opts = mergeOpts(options);
  const sidecarUrl = getSidecarUrl(opts);

  return async (request: ReadResourceRequest): Promise<ReadResourceResult> => {
    let result = await handler(request);

    if (opts.enablePiiRedaction && sidecarUrl && result?.contents) {
      try {
        const redacted = (await callSidecar(sidecarUrl, "pii-redact", {
          content: result.contents,
        })) as { content?: ReadResourceResult["contents"] };
        if (redacted?.content) {
          result = { ...result, contents: redacted.content };
        }
      } catch {
        /* best-effort */
      }
    }

    if (opts.tagResourceProvenance) {
      result = tagResourceProvenance(result, "resource");
    }

    return result;
  };
}

/** Wraps ListTools handler with live description screening. */
export function wrapListToolsHandler(
  handler: ListToolsHandler,
  options: McpBastionOptions = {}
): ListToolsHandler {
  const opts = mergeOpts(options);

  return async (request: ListToolsRequest): Promise<ListToolsResult> => {
    const result = await handler(request);
    if (!opts.enableToolsListScreen || !result?.tools) {
      return result;
    }
    const screened = screenToolsList(
      result.tools as Parameters<typeof screenToolsList>[0],
      opts.toolsListScreenAction
    );
    if (screened.blocked) {
      return {
        tools: [],
        _meta: {
          bastionDenyCode: TOOL_LIST_POISON_CODE,
          bastionDenyReason: screened.reason,
          removedTools: screened.removed,
        },
      } as ListToolsResult;
    }
    if (screened.removed.length) {
      return {
        ...result,
        tools: screened.tools as ListToolsResult["tools"],
        _meta: {
          ...(result as { _meta?: Record<string, unknown> })._meta,
          removedTools: screened.removed,
        },
      };
    }
    return result;
  };
}

/** Patches setRequestHandler to wrap CallTool, ReadResource, ListTools. */
export function wrapWithMcpBastion<
  T extends { setRequestHandler: (schema: unknown, handler: unknown) => void },
>(server: T, options: McpBastionOptions = {}): T {
  const opts = mergeOpts(options);
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
    if (
      schemaStr.includes("ReadResource") ||
      schemaStr.includes("resources/read")
    ) {
      return original(
        schema,
        wrapReadResourceHandler(handler as ReadResourceHandler, opts)
      );
    }
    if (schemaStr.includes("ListTools") || schemaStr.includes("tools/list")) {
      return original(
        schema,
        wrapListToolsHandler(handler as ListToolsHandler, opts)
      );
    }
    return original(schema, handler);
  } as T["setRequestHandler"];

  return server;
}
