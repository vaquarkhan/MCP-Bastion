/**
 * MCP-Bastion Core: Security middleware for MCP servers.
 * Rate limiting in-process; prompt injection, PII, semantic egress, and
 * result guard via optional Python/sidecar. Provenance tagging and
 * hash-chained audit are deterministic in-process.
 */

export {
  wrapWithMcpBastion,
  wrapCallToolHandler,
  wrapReadResourceHandler,
  wrapListToolsHandler,
} from "./guard.js";
export type { McpBastionOptions } from "./guard.js";
export { TokenBucketRateLimiter } from "./rate-limit.js";
export { logger, setLogLevel } from "./logger.js";
export type { LogLevel } from "./logger.js";
export { scoreEgress, isScreenedTool } from "./semantic-egress.js";
export type { SemanticVerdict } from "./semantic-egress.js";
export { tagResultProvenance, scanResult } from "./result-guard.js";
export {
  tagProvenance,
  tagResourceProvenance,
  registerContextEvictionHook,
  evictContext,
} from "./provenance.js";
export type { TrustClass, ContextEvictFn } from "./provenance.js";
export { AuditChain, hashRecord } from "./audit.js";
export type { AuditRecord } from "./audit.js";
export {
  checkEgressAllowlist,
  extractHostname,
  hostAllowed,
  isEgressLikeTool,
  EGRESS_DENIED_CODE,
} from "./egress-allowlist.js";
export {
  ConcurrencyLimiter,
  CONCURRENCY_LIMIT_CODE,
  LOAD_SHED_CODE,
} from "./concurrency.js";
export {
  checkMemoryWrite,
  isMemoryWriteTool,
  MEMORY_GUARD_CODE,
} from "./memory-guard.js";
export {
  AttestationVerifier,
  verifySecurityEnvelope,
  samplingOriginAllowed,
  ATTESTATION_FAILED_CODE,
} from "./attestation.js";
export type {
  AttestationMode,
  ServerAttestation,
  AttestationEnvelope,
} from "./attestation.js";
export { screenToolsList, TOOL_LIST_POISON_CODE } from "./tools-list-screen.js";
