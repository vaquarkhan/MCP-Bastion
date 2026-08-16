/**
 * Default-deny outbound destination allowlist for MCP-mediated tool args.
 *
 * Opt-in, fail-closed when enabled. Bounds destinations Bastion can see in
 * tool arguments (URL/host fields). Does not cover out-of-band sockets/DNS.
 */

const URL_RE =
  /\bhttps?:\/\/[^\s"'<>]+/gi;
const HOST_KEY_RE =
  /^(?:url|uri|host|hostname|endpoint|base_url|baseUrl|webhook|target|destination|server|domain)$/i;

export interface EgressAllowlistOptions {
  /** Allowed hostnames (exact or leading "*." wildcard). Empty = deny all. */
  allowedHosts: string[];
  /** Extra tool names treated as egress sinks (substring match, lowercased). */
  egressToolHints?: string[];
}

const DEFAULT_EGRESS_HINTS = [
  "http",
  "fetch",
  "webhook",
  "email",
  "mail",
  "slack",
  "discord",
  "telegram",
  "post",
  "send",
  "upload",
  "publish",
  "request",
  "api",
];

/** Stack-local deny code (TS core). Python uses a separate registry code. */
export const EGRESS_DENIED_CODE = -32010;

export function isEgressLikeTool(
  toolName: string,
  hints: string[] = DEFAULT_EGRESS_HINTS
): boolean {
  const t = (toolName || "").toLowerCase();
  return hints.some((h) => t.includes(h.toLowerCase()));
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

/** Extract hostname from a URL or bare host string. */
export function extractHostname(raw: string): string | null {
  const s = (raw || "").trim();
  if (!s) return null;
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
    const u = new URL(withScheme);
    if (!u.hostname) return null;
    return normalizeHost(u.hostname);
  } catch {
    const bare = s.split("/")[0]?.split(":")[0];
    return bare ? normalizeHost(bare) : null;
  }
}

export function hostAllowed(host: string, allowedHosts: string[]): boolean {
  const h = normalizeHost(host);
  if (!h) return false;
  for (const entry of allowedHosts) {
    const a = normalizeHost(entry);
    if (!a) continue;
    if (a.startsWith("*.")) {
      const suffix = a.slice(2);
      if (h === suffix || h.endsWith(`.${suffix}`)) return true;
    } else if (h === a) {
      return true;
    }
  }
  return false;
}

function collectDestinations(value: unknown, out: Set<string>, keyHint = ""): void {
  if (value == null) return;
  if (typeof value === "string") {
    if (HOST_KEY_RE.test(keyHint)) {
      const host = extractHostname(value);
      if (host) out.add(host);
    }
    for (const m of value.matchAll(URL_RE)) {
      const host = extractHostname(m[0]);
      if (host) out.add(host);
    }
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") return;
  if (Array.isArray(value)) {
    for (const item of value) collectDestinations(item, out, keyHint);
    return;
  }
  if (typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      collectDestinations(v, out, k);
    }
  }
}

export type EgressCheckResult =
  | { ok: true; hosts: string[] }
  | { ok: false; deniedHost: string; hosts: string[] };

/**
 * When enabled for an egress-like tool, every discovered host must be allowlisted.
 * No hosts discovered → allow (nothing to deny); empty allowlist with hosts → deny.
 */
export function checkEgressAllowlist(
  toolName: string,
  arguments_: unknown,
  options: EgressAllowlistOptions
): EgressCheckResult {
  const hints = options.egressToolHints?.length
    ? options.egressToolHints
    : DEFAULT_EGRESS_HINTS;
  if (!isEgressLikeTool(toolName, hints)) {
    return { ok: true, hosts: [] };
  }
  const hosts = new Set<string>();
  collectDestinations(arguments_, hosts);
  const list = [...hosts];
  if (list.length === 0) {
    return { ok: true, hosts: list };
  }
  for (const host of list) {
    if (!hostAllowed(host, options.allowedHosts || [])) {
      return { ok: false, deniedHost: host, hosts: list };
    }
  }
  return { ok: true, hosts: list };
}
