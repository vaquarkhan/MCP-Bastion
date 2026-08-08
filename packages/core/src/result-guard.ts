/**
 * Result-side screening. Tags untrusted tool output and optionally scans it.
 *
 * Honest scope: provenance markers reduce indirect-injection efficacy; they
 * do not isolate content in the information-flow-control sense. Optional
 * semantic scan runs in a sidecar and is advisory (detect) by default.
 */

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { logger } from "./logger.js";

const OPEN = "<untrusted_tool_result>";
const CLOSE = "</untrusted_tool_result>";

/** Wrap text result content in provenance markers. Deterministic, no network. */
export function tagResultProvenance(result: CallToolResult): CallToolResult {
  if (!result?.content) return result;
  const content = result.content.map((c) => {
    const item = c as { type?: string; text?: string };
    if (item.type === "text" && typeof item.text === "string") {
      return { ...c, text: `${OPEN}${item.text}${CLOSE}` };
    }
    return c;
  });
  return { ...result, content };
}

/** POST result content to sidecar /result-guard with a hard timeout. */
export async function scanResult(
  baseUrl: string,
  result: CallToolResult,
  timeoutMs: number
): Promise<{ malicious?: boolean }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl}/result-guard`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: result.content }),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`result-guard failed: ${res.status}`);
    return (await res.json()) as { malicious?: boolean };
  } finally {
    clearTimeout(timer);
  }
}

export function logResultGuardBlocked(toolName: string): void {
  logger.warn("result_guard_blocked", toolName);
}
