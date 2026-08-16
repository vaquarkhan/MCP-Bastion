/**
 * Live tools/list description screening (line-jumping defense).
 * Deterministic injection markers; complements fingerprint + static scan.
 */

export const TOOL_LIST_POISON_CODE = -32016;

const POISON_PATTERNS = [
  /ignore\s+(?:all\s+)?previous\s+instructions/i,
  /disregard\s+(?:all\s+)?(?:prior|previous)\s+instructions/i,
  /<\s*system\s*>/i,
  /\[INST\]/i,
  /jailbreak/i,
  /do\s+not\s+tell\s+the\s+user/i,
  /reveal\s+(?:your\s+)?system\s+prompt/i,
  /exfiltrat/i,
  /<!--\s*hidden/i,
];

export interface ToolListEntry {
  name?: string;
  description?: string;
  inputSchema?: unknown;
  [key: string]: unknown;
}

export type ListScreenAction = "remove_tool" | "block_all";

export interface ListScreenResult {
  tools: ToolListEntry[];
  removed: string[];
  blocked: boolean;
  reason?: string;
}

function scanText(text: string): string | null {
  for (const re of POISON_PATTERNS) {
    if (re.test(text)) return `matched ${re.source}`;
  }
  return null;
}

function entryScanText(tool: ToolListEntry): string {
  const parts = [tool.name || "", tool.description || ""];
  try {
    parts.push(JSON.stringify(tool.inputSchema ?? {}));
  } catch {
    /* ignore */
  }
  return parts.join("\n");
}

/**
 * Screen a tools/list payload. Opt-in caller decides action.
 */
export function screenToolsList(
  tools: ToolListEntry[],
  action: ListScreenAction = "remove_tool"
): ListScreenResult {
  const kept: ToolListEntry[] = [];
  const removed: string[] = [];
  for (const tool of tools) {
    const name = String(tool.name || "unknown");
    const detail = scanText(entryScanText(tool));
    if (!detail) {
      kept.push(tool);
      continue;
    }
    removed.push(name);
    if (action === "block_all") {
      return {
        tools: [],
        removed,
        blocked: true,
        reason: `Tool list blocked: metadata failed safety checks for tool ${JSON.stringify(name)}: ${detail}`,
      };
    }
  }
  if (!kept.length && removed.length) {
    return {
      tools: [],
      removed,
      blocked: true,
      reason:
        "Tool list blocked: no tools remained after metadata safety checks",
    };
  }
  return { tools: kept, removed, blocked: false };
}
