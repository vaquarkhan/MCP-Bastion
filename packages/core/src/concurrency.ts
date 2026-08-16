/**
 * In-process concurrency / load-shed admission (O(1)).
 * Opt-in; fail-closed with distinct deny codes. Bounds governed MCP traffic only.
 */

export const CONCURRENCY_LIMIT_CODE = -32006;
export const LOAD_SHED_CODE = -32006;

export type AdmitResult = "admit" | "CONCURRENCY_LIMIT" | "LOAD_SHED";

export interface ConcurrencyLimiterOptions {
  maxInflightPerCaller?: number;
  maxInflightPerTenant?: number;
  /** 0 = reject immediately when caps hit (no queue). Default 0. */
  admissionQueueDepth?: number;
}

interface Counter {
  n: number;
}

/**
 * Per-caller and per-tenant in-flight caps. release() must run in finally.
 * Queue depth > 0 is reserved for future wait; today depth 0 sheds immediately.
 */
export class ConcurrencyLimiter {
  private readonly maxCaller: number;
  private readonly maxTenant: number;
  private readonly queueDepth: number;
  private readonly byCaller = new Map<string, Counter>();
  private readonly byTenant = new Map<string, Counter>();
  private waiting = 0;

  constructor(options: ConcurrencyLimiterOptions = {}) {
    this.maxCaller = Math.max(0, options.maxInflightPerCaller ?? 0);
    this.maxTenant = Math.max(0, options.maxInflightPerTenant ?? 0);
    this.queueDepth = Math.max(0, options.admissionQueueDepth ?? 0);
  }

  private bump(map: Map<string, Counter>, key: string, delta: number): number {
    let c = map.get(key);
    if (!c) {
      c = { n: 0 };
      map.set(key, c);
    }
    c.n += delta;
    if (c.n <= 0) {
      map.delete(key);
      return 0;
    }
    return c.n;
  }

  tryAcquire(callerId?: string | null, tenantId?: string | null): AdmitResult {
    const caller = (callerId || "").trim() || "anonymous";
    const tenant = (tenantId || "").trim() || "default";

    const callerCount = this.byCaller.get(caller)?.n ?? 0;
    const tenantCount = this.byTenant.get(tenant)?.n ?? 0;

    if (this.maxCaller > 0 && callerCount >= this.maxCaller) {
      if (this.queueDepth > 0 && this.waiting < this.queueDepth) {
        // No async wait in core path — treat as shed for deterministic deny.
        return "LOAD_SHED";
      }
      return this.queueDepth === 0 ? "CONCURRENCY_LIMIT" : "LOAD_SHED";
    }
    if (this.maxTenant > 0 && tenantCount >= this.maxTenant) {
      if (this.queueDepth > 0) return "LOAD_SHED";
      return "CONCURRENCY_LIMIT";
    }

    this.bump(this.byCaller, caller, 1);
    this.bump(this.byTenant, tenant, 1);
    return "admit";
  }

  release(callerId?: string | null, tenantId?: string | null): void {
    const caller = (callerId || "").trim() || "anonymous";
    const tenant = (tenantId || "").trim() || "default";
    this.bump(this.byCaller, caller, -1);
    this.bump(this.byTenant, tenant, -1);
  }

  /** Test helper */
  inflight(callerId?: string | null, tenantId?: string | null): {
    caller: number;
    tenant: number;
  } {
    const caller = (callerId || "").trim() || "anonymous";
    const tenant = (tenantId || "").trim() || "default";
    return {
      caller: this.byCaller.get(caller)?.n ?? 0,
      tenant: this.byTenant.get(tenant)?.n ?? 0,
    };
  }
}
