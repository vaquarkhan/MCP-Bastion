/**
 * SMCP-class attestation verify (advisory by default). Never re-signs envelopes.
 * Proves who/what when signatures verify; does not prove why (orthogonal to egress).
 */

import { createPublicKey, verify } from "node:crypto";

export const ATTESTATION_FAILED_CODE = -32009;

export type AttestationMode = "advisory" | "require";

export interface ServerAttestation {
  /** Server id / name. */
  serverId: string;
  /** Ed25519 public key (SPKI PEM or raw base64). */
  publicKeyPem?: string;
  publicKeyBase64?: string;
  /** Optional tool allowlist asserted by the attestation. */
  allowedTools?: string[];
  /** Clearance expiry ISO timestamp. */
  expiresAt?: string;
}

export interface AttestationEnvelope {
  serverId: string;
  /** Canonical payload that was signed (JSON string or object). */
  payload: unknown;
  /** Base64 Ed25519 signature over UTF-8 canonical JSON. */
  signatureBase64: string;
  issuedAt?: string;
  expiresAt?: string;
}

export interface AttestationVerifyResult {
  ok: boolean;
  reason?: string;
  cached?: boolean;
}

function canonicalJson(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function loadPublicKey(att: ServerAttestation) {
  if (att.publicKeyPem) {
    return createPublicKey(att.publicKeyPem);
  }
  if (att.publicKeyBase64) {
    const der = Buffer.from(att.publicKeyBase64, "base64");
    return createPublicKey({ key: der, format: "der", type: "spki" });
  }
  throw new Error("attestation missing public key");
}

export class AttestationVerifier {
  private readonly trust = new Map<string, ServerAttestation>();
  private readonly cache = new Map<
    string,
    { ok: boolean; expires: number; reason?: string }
  >();
  private readonly cacheTtlMs: number;

  constructor(
    roots: ServerAttestation[] = [],
    options: { cacheTtlMs?: number } = {}
  ) {
    for (const r of roots) {
      this.trust.set(r.serverId, r);
    }
    this.cacheTtlMs = options.cacheTtlMs ?? 60_000;
  }

  pin(att: ServerAttestation): void {
    this.trust.set(att.serverId, att);
  }

  verifyEnvelope(env: AttestationEnvelope): AttestationVerifyResult {
    const cached = this.cache.get(env.serverId);
    if (cached && cached.expires > Date.now()) {
      return { ok: cached.ok, reason: cached.reason, cached: true };
    }

    const root = this.trust.get(env.serverId);
    if (!root) {
      return this._store(env.serverId, {
        ok: false,
        reason: `no pinned trust root for server ${env.serverId}`,
      });
    }

    const exp = env.expiresAt || root.expiresAt;
    if (exp && Date.parse(exp) < Date.now()) {
      return this._store(env.serverId, {
        ok: false,
        reason: "attestation expired",
      });
    }

    try {
      const key = loadPublicKey(root);
      const payload = Buffer.from(canonicalJson(env.payload), "utf8");
      const sig = Buffer.from(env.signatureBase64, "base64");
      const ok = verify(null, payload, key, sig);
      if (!ok) {
        return this._store(env.serverId, {
          ok: false,
          reason: "signature mismatch",
        });
      }
      return this._store(env.serverId, { ok: true });
    } catch (err) {
      return this._store(env.serverId, {
        ok: false,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /** Deny-by-default tool allowlist from pinned attestation (when present). */
  toolAllowed(serverId: string, toolName: string): boolean {
    const root = this.trust.get(serverId);
    if (!root?.allowedTools?.length) return true;
    return root.allowedTools.includes(toolName);
  }

  private _store(
    serverId: string,
    result: AttestationVerifyResult
  ): AttestationVerifyResult {
    this.cache.set(serverId, {
      ok: result.ok,
      reason: result.reason,
      expires: Date.now() + this.cacheTtlMs,
    });
    return result;
  }
}

/**
 * Verify a JSON-RPC security envelope without mutating or re-signing it.
 */
export function verifySecurityEnvelope(
  envelope: {
    payload?: unknown;
    signatureBase64?: string;
    serverId?: string;
  },
  verifier: AttestationVerifier
): AttestationVerifyResult {
  if (!envelope.serverId || !envelope.signatureBase64) {
    return { ok: false, reason: "missing serverId or signature" };
  }
  return verifier.verifyEnvelope({
    serverId: envelope.serverId,
    payload: envelope.payload ?? {},
    signatureBase64: envelope.signatureBase64,
  });
}

/**
 * Sampling-origin auth: drop when origin is unauthenticated under require mode.
 */
export function samplingOriginAllowed(
  origin: { authenticated?: boolean; serverId?: string } | undefined,
  mode: AttestationMode
): boolean {
  if (mode === "advisory") return true;
  return Boolean(origin?.authenticated && origin.serverId);
}
