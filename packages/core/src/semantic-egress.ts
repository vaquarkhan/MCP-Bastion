/**
 * Semantic egress screen. Sidecar-scored, never inline.
 * Advisory (detect) by default; quarantine only for an explicit tool allowlist.
 *
 * Honest scope: screens MCP-mediated outbound tool calls only. Blind to
 * out-of-band execution. Raises cost for unsubtle manipulation; does not
 * prevent social engineering.
 */

import { logger } from "./logger.js";

export interface SemanticVerdict {
  score: number;
  dimensions?: string[];
  verdict?: "benign" | "suspicious" | "manipulative";
}

/** POST text to sidecar /semantic-egress with a hard timeout. */
export async function scoreEgress(
  baseUrl: string,
  text: string,
  timeoutMs: number
): Promise<SemanticVerdict> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl}/semantic-egress`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`semantic-egress failed: ${res.status}`);
    return (await res.json()) as SemanticVerdict;
  } finally {
    clearTimeout(timer);
  }
}

/** True when tool name is on the operator-configured screen list. */
export function isScreenedTool(name: string, tools: string[]): boolean {
  return tools.includes(name);
}

/** Log detect-mode scoring without blocking. */
export function logSemanticDetect(
  toolName: string,
  verdict: SemanticVerdict
): void {
  logger.warn(
    "semantic_egress_score",
    toolName,
    verdict.score,
    verdict.dimensions
  );
}
