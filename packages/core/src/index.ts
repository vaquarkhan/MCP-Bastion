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
} from "./guard.js";
export type { McpBastionOptions } from "./guard.js";
export { TokenBucketRateLimiter } from "./rate-limit.js";
export { logger, setLogLevel } from "./logger.js";
export type { LogLevel } from "./logger.js";
export {
  scoreEgress,
  isScreenedTool,
} from "./semantic-egress.js";
export type { SemanticVerdict } from "./semantic-egress.js";
export {
  tagResultProvenance,
  scanResult,
} from "./result-guard.js";
export { AuditChain, hashRecord } from "./audit.js";
export type { AuditRecord } from "./audit.js";
