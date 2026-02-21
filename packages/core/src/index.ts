/**
 * MCP-Bastion Core: Security middleware for MCP servers.
 * Rate limiting in-process; prompt injection and PII via Python sidecar.
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
