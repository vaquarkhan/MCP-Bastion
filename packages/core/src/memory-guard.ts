/**
 * Memory / context write-path guard (ASI06 floor).
 * Deterministic markers + protected-key globs. Opt-in, fail-closed when on.
 * Complements result-side screening; not a classifier.
 */

export const MEMORY_GUARD_CODE = -32007;

const DEFAULT_MEMORY_TOOL_HINTS = [
  "memory",
  "remember",
  "store",
  "save_context",
  "set_memory",
  "write_memory",
  "kb_write",
  "knowledge_write",
];

const INJECTION_MARKERS = [
  /ignore\s+(?:all\s+)?previous\s+instructions/i,
  /disregard\s+(?:all\s+)?(?:prior|previous)\s+instructions/i,
  /<\s*system\s*>/i,
  /\[INST\]/i,
  /jailbreak/i,
  /reveal\s+(?:your\s+)?system\s+prompt/i,
];

export interface MemoryGuardOptions {
  /** Tool name substrings that trigger checks. */
  memoryToolHints?: string[];
  /** Glob-like patterns for protected keys (supports * suffix/prefix). */
  protectedKeyGlobs?: string[];
  /** key → sha256 hex of immutable baseline value. */
  immutableKeyBaselines?: Record<string, string>;
}

function matchGlob(key: string, glob: string): boolean {
  const g = glob.trim().toLowerCase();
  const k = key.toLowerCase();
  if (g === k) return true;
  if (g.startsWith("*") && g.endsWith("*")) {
    return k.includes(g.slice(1, -1));
  }
  if (g.startsWith("*")) return k.endsWith(g.slice(1));
  if (g.endsWith("*")) return k.startsWith(g.slice(0, -1));
  return false;
}

function flatten(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const buf = await crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  // Node fallback without importing node:crypto (keeps browser-ish build happy).
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(text).digest("hex");
}

export function isMemoryWriteTool(
  toolName: string,
  hints: string[] = DEFAULT_MEMORY_TOOL_HINTS
): boolean {
  const t = (toolName || "").toLowerCase();
  return hints.some((h) => t.includes(h.toLowerCase()));
}

export type MemoryGuardResult =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * Screen memory-style writes: protected keys, immutable baselines, injection markers.
 */
export async function checkMemoryWrite(
  toolName: string,
  arguments_: unknown,
  options: MemoryGuardOptions = {}
): Promise<MemoryGuardResult> {
  const hints = options.memoryToolHints?.length
    ? options.memoryToolHints
    : DEFAULT_MEMORY_TOOL_HINTS;
  if (!isMemoryWriteTool(toolName, hints)) {
    return { ok: true };
  }

  const args =
    arguments_ && typeof arguments_ === "object"
      ? (arguments_ as Record<string, unknown>)
      : {};
  const key = String(args.key ?? args.name ?? args.path ?? args.id ?? "");
  const value = args.value ?? args.content ?? args.text ?? args.data ?? "";

  const protectedGlobs = options.protectedKeyGlobs || [
    "system*",
    "*prompt*",
    "policy*",
    "secret*",
  ];
  if (key && protectedGlobs.some((g) => matchGlob(key, g))) {
    return {
      ok: false,
      reason: `Memory write blocked: protected key ${JSON.stringify(key)}`,
    };
  }

  const baselines = options.immutableKeyBaselines || {};
  if (key && baselines[key]) {
    const digest = await sha256Hex(flatten(value));
    if (digest !== baselines[key].toLowerCase()) {
      return {
        ok: false,
        reason: `Memory write blocked: immutable key ${JSON.stringify(key)} baseline mismatch`,
      };
    }
  }

  const text = flatten(value);
  for (const re of INJECTION_MARKERS) {
    if (re.test(text)) {
      return {
        ok: false,
        reason: "Memory write blocked: injection marker in payload",
      };
    }
  }

  return { ok: true };
}
