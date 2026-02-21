/**
 * Simple logger for MCP-Bastion. Uses console with level filtering.
 */

const PREFIX = "[mcp-bastion]";

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

let currentLevel: LogLevel = "info";

export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

function shouldLog(level: LogLevel): boolean {
  return LEVEL_ORDER[level] >= LEVEL_ORDER[currentLevel];
}

export const logger = {
  debug(msg: string, ...args: unknown[]): void {
    if (shouldLog("debug")) console.debug(PREFIX, msg, ...args);
  },
  info(msg: string, ...args: unknown[]): void {
    if (shouldLog("info")) console.info(PREFIX, msg, ...args);
  },
  warn(msg: string, ...args: unknown[]): void {
    if (shouldLog("warn")) console.warn(PREFIX, msg, ...args);
  },
  error(msg: string, ...args: unknown[]): void {
    if (shouldLog("error")) console.error(PREFIX, msg, ...args);
  },
};
