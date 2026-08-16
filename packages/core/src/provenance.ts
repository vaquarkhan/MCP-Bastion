/**
 * Provenance tagging for tool results, resources, and sampling-shaped payloads.
 * Reduces injection efficacy; does not isolate (no IFC).
 */

import type {
  CallToolResult,
  ReadResourceResult,
} from "@modelcontextprotocol/sdk/types.js";

export type TrustClass = "untrusted" | "tool" | "resource" | "sampling" | "external";

const MARKERS: Record<TrustClass, { open: string; close: string }> = {
  untrusted: {
    open: "<untrusted_tool_result>",
    close: "</untrusted_tool_result>",
  },
  tool: {
    open: "<untrusted_tool_result>",
    close: "</untrusted_tool_result>",
  },
  resource: {
    open: "<untrusted_resource>",
    close: "</untrusted_resource>",
  },
  sampling: {
    open: "<untrusted_sampling>",
    close: "</untrusted_sampling>",
  },
  external: {
    open: "<untrusted_external>",
    close: "</untrusted_external>",
  },
};

function wrapText(text: string, trust: TrustClass): string {
  const m = MARKERS[trust] || MARKERS.untrusted;
  if (text.startsWith(m.open) && text.endsWith(m.close)) return text;
  return `${m.open}${text}${m.close}`;
}

/** Tag CallToolResult text blocks with a trust class. */
export function tagProvenance(
  result: CallToolResult,
  trust: TrustClass = "tool"
): CallToolResult {
  if (!result?.content) return result;
  const content = result.content.map((c) => {
    const item = c as { type?: string; text?: string };
    if (item.type === "text" && typeof item.text === "string") {
      return { ...c, text: wrapText(item.text, trust) };
    }
    return c;
  });
  return {
    ...result,
    content,
    _meta: {
      ...(result as { _meta?: Record<string, unknown> })._meta,
      bastionTrustClass: trust,
    },
  };
}

/** Tag ReadResourceResult text contents. */
export function tagResourceProvenance(
  result: ReadResourceResult,
  trust: TrustClass = "resource"
): ReadResourceResult {
  if (!result?.contents) return result;
  const contents = result.contents.map((c) => {
    const item = c as { text?: string; uri?: string };
    if (typeof item.text === "string") {
      return { ...c, text: wrapText(item.text, trust) };
    }
    return c;
  });
  return {
    ...result,
    contents,
    _meta: {
      ...(result as { _meta?: Record<string, unknown> })._meta,
      bastionTrustClass: trust,
    },
  };
}

/** Explicit session/task context eviction hook (caller-owned store). */
export type ContextEvictFn = (sessionId: string) => void;

const evictionHooks = new Set<ContextEvictFn>();

export function registerContextEvictionHook(fn: ContextEvictFn): () => void {
  evictionHooks.add(fn);
  return () => {
    evictionHooks.delete(fn);
  };
}

/** Notify registered hooks that a session/task completed (best-effort). */
export function evictContext(sessionId: string): void {
  for (const fn of evictionHooks) {
    try {
      fn(sessionId);
    } catch {
      // never break callers
    }
  }
}
