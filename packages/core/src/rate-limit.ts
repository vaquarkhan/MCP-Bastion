/**
 * Token bucket rate limiter for MCP tool calls.
 * Iteration cap (15), timeout (60s).
 */

const DEFAULT_MAX_ITERATIONS = 15;
const DEFAULT_TIMEOUT_MS = 60_000;

interface SessionState {
  iterations: number;
  startedAt: number;
}

export class TokenBucketRateLimiter {
  private readonly maxIterations: number;
  private readonly timeoutMs: number;
  private readonly sessions = new Map<string, SessionState>();

  constructor(
    maxIterations = DEFAULT_MAX_ITERATIONS,
    timeoutMs = DEFAULT_TIMEOUT_MS
  ) {
    this.maxIterations = maxIterations;
    this.timeoutMs = timeoutMs;
  }

  private getSessionKey(requestId?: string | null, sessionId?: string | null): string {
    return sessionId ?? requestId ?? "default";
  }

  private cleanupExpired(key: string): void {
    const state = this.sessions.get(key);
    if (!state) return;
    const elapsed = Date.now() - state.startedAt;
    if (elapsed > this.timeoutMs) {
      this.sessions.delete(key);
    }
  }

  checkIteration(
    requestId?: string | null,
    sessionId?: string | null
  ): { allowed: boolean; error?: string } {
    const key = this.getSessionKey(requestId, sessionId);
    this.cleanupExpired(key);

    const state = this.sessions.get(key);
    if (!state) {
      return { allowed: true };
    }

    const elapsed = Date.now() - state.startedAt;
    if (elapsed > this.timeoutMs) {
      this.sessions.delete(key);
      return { allowed: false, error: "Session timeout exceeded (60s limit)" };
    }

    if (state.iterations >= this.maxIterations) {
      return {
        allowed: false,
        error: `Maximum iterations exceeded (${this.maxIterations} limit)`,
      };
    }

    return { allowed: true };
  }

  consumeIteration(
    requestId?: string | null,
    sessionId?: string | null
  ): void {
    const key = this.getSessionKey(requestId, sessionId);
    let state = this.sessions.get(key);
    if (!state) {
      state = { iterations: 0, startedAt: Date.now() };
      this.sessions.set(key, state);
    }
    state.iterations += 1;
  }

  resetSession(requestId?: string | null, sessionId?: string | null): void {
    const key = this.getSessionKey(requestId, sessionId);
    this.sessions.delete(key);
  }
}
