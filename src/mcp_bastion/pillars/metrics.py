"""
In-memory metrics for dashboard and OpenTelemetry export.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Rolling window for dashboard sparkline: 20 × 30s = 10 minutes
TIME_BUCKET_SECONDS = 30
TIME_BUCKET_COUNT = 20
LATENCY_SAMPLE_CAP = 2000
# Recent blocked calls with ids for dashboard forensics (newest appended; maxlen enforced)
BLOCKED_INCIDENT_CAP = 48


@dataclass
class DashboardMetrics:
    """Aggregated metrics for real-time dashboard."""

    requests_total: int = 0
    blocked_total: int = 0
    pii_redacted_total: int = 0
    cost_total: float = 0.0
    blocked_by_reason: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    blocked_by_kind: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    top_tools: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    cost_by_user: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    pii_by_entity: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    alerts: list[dict[str, Any]] = field(default_factory=list)
    window_start: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        reason_sum = sum(self.blocked_by_reason.values())
        # Ensure total is at least sum of reasons (avoids display mismatch if multiple paths record)
        blocked = max(self.blocked_total, reason_sum)
        return {
            "requests_total": self.requests_total,
            "blocked_total": blocked,
            "blocked_pct": round(100 * blocked / max(1, self.requests_total), 2),
            "pii_redacted_total": self.pii_redacted_total,
            "pii_by_entity": dict(sorted(self.pii_by_entity.items(), key=lambda x: -x[1])[:20]),
            "cost_total": round(self.cost_total, 2),
            "blocked_by_reason": dict(self.blocked_by_reason),
            "blocked_by_kind": dict(self.blocked_by_kind),
            "top_tools": dict(sorted(self.top_tools.items(), key=lambda x: -x[1])[:10]),
            "cost_by_user": dict(sorted(self.cost_by_user.items(), key=lambda x: -x[1])[:10]),
            "alerts": self.alerts[-10:],
            "window_start": self.window_start,
        }


class MetricsStore:
    """Thread-safe in-memory metrics. Single global instance for dashboard."""

    _lock = threading.Lock()
    _instance: MetricsStore | None = None

    def __init__(self) -> None:
        self._metrics = DashboardMetrics()
        # bucket_id -> [allowed_count, blocked_count]
        self._time_buckets: dict[int, list[int]] = {}
        self._latency_ms: deque[float] = deque(maxlen=LATENCY_SAMPLE_CAP)
        self._tool_allowed: dict[str, int] = defaultdict(int)
        self._tool_blocked: dict[str, int] = defaultdict(int)
        self._tool_reason_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._tool_latency_ms: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=LATENCY_SAMPLE_CAP // 4)
        )
        self._blocked_incidents: deque[dict[str, Any]] = deque(maxlen=BLOCKED_INCIDENT_CAP)

    @staticmethod
    def _normalize_reason_kind(reason: str | None) -> str:
        if not reason:
            return "unknown"
        lower = reason.lower()
        if "injection" in lower or "prompt" in lower:
            return "injection"
        if "rate" in lower or "iteration" in lower:
            return "rate_limit"
        if "rbac" in lower or "cannot access" in lower:
            return "rbac"
        if "cost" in lower or "budget" in lower:
            return "cost"
        if "content" in lower or "blocked" in lower:
            return "content_filter"
        if "circuit" in lower:
            return "circuit_breaker"
        if "replay" in lower or "nonce" in lower:
            return "replay"
        if "schema" in lower or "validation" in lower:
            return "schema_validation"
        return "other"

    @staticmethod
    def _percentile_ms(samples: list[float], p: float) -> float:
        if not samples:
            return 0.0
        s = sorted(samples)
        if len(s) == 1:
            return round(s[0], 2)
        k = (len(s) - 1) * (p / 100.0)
        f = int(k)
        c = k - f
        if f + 1 < len(s):
            return round(s[f] * (1 - c) + s[f + 1] * c, 2)
        return round(s[f], 2)

    @staticmethod
    def _elapsed_seconds_window(window_start_iso: str) -> float:
        try:
            ts = window_start_iso.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return max((datetime.now(timezone.utc) - dt).total_seconds(), 1.0)
        except Exception:
            return 1.0

    def _bucket_id(self, t: float) -> int:
        return int(t // TIME_BUCKET_SECONDS)

    def _bump_time_bucket(self, *, allowed: int = 0, blocked: int = 0) -> None:
        if not allowed and not blocked:
            return
        bid = self._bucket_id(time.time())
        if bid not in self._time_buckets:
            self._time_buckets[bid] = [0, 0]
        self._time_buckets[bid][0] += allowed
        self._time_buckets[bid][1] += blocked
        cutoff = bid - TIME_BUCKET_COUNT + 1
        for k in list(self._time_buckets):
            if k < cutoff:
                del self._time_buckets[k]

    def _snapshot_time_series(self) -> list[dict[str, Any]]:
        bid = self._bucket_id(time.time())
        start_bid = bid - TIME_BUCKET_COUNT + 1
        out: list[dict[str, Any]] = []
        for b in range(start_bid, bid + 1):
            a, blk = self._time_buckets.get(b, (0, 0))
            out.append(
                {
                    "bucket_start": datetime.fromtimestamp(
                        b * TIME_BUCKET_SECONDS, tz=timezone.utc
                    ).isoformat(),
                    "allowed": a,
                    "blocked": blk,
                }
            )
        return out

    @classmethod
    def get(cls) -> MetricsStore:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = MetricsStore()
        return cls._instance

    def record_request(self, tool: str, user: str | None = None) -> None:
        with self._lock:
            self._metrics.requests_total += 1
            self._metrics.top_tools[tool] += 1
            self._tool_allowed[tool] += 1
            self._bump_time_bucket(allowed=1)
            if user:
                pass  # cost_by_user updated by record_cost

    def record_blocked(
        self,
        reason: str,
        tool: str = "unknown",
        *,
        tenant_id: str | None = None,
        trace_id: str | None = None,
        request_id: str | None = None,
    ) -> None:
        with self._lock:
            kind = self._normalize_reason_kind(reason)
            self._metrics.blocked_total += 1
            self._metrics.blocked_by_reason[reason] += 1
            self._metrics.blocked_by_kind[kind] += 1
            self._metrics.top_tools[tool] += 1
            self._tool_blocked[tool] += 1
            self._tool_reason_counts[tool][kind] += 1
            self._bump_time_bucket(blocked=1)
            self._blocked_incidents.append(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "tenant_id": tenant_id or "default",
                    "tool": tool,
                    "reason": (reason or "")[:2000],
                    "trace_id": trace_id or f"trc-{uuid.uuid4().hex[:20]}",
                    "request_id": request_id or f"req-{uuid.uuid4().hex[:16]}",
                }
            )

    def record_pii_redacted(self, count: int = 1) -> None:
        with self._lock:
            self._metrics.pii_redacted_total += count

    def record_pii_entities(self, entity_counts: dict[str, int]) -> None:
        """Increment per-entity PII counts and total redacted (from Presidio detection)."""
        if not entity_counts:
            return
        with self._lock:
            for k, v in entity_counts.items():
                if v <= 0:
                    continue
                self._metrics.pii_by_entity[k] += v
                self._metrics.pii_redacted_total += v

    def record_latency_ms(self, ms: float) -> None:
        """Record one middleware round-trip latency sample (milliseconds)."""
        if ms < 0 or ms > 600_000:
            return
        with self._lock:
            self._latency_ms.append(float(ms))

    def record_tool_latency_ms(self, tool: str, ms: float) -> None:
        """Record per-tool latency sample (milliseconds)."""
        if ms < 0 or ms > 600_000:
            return
        with self._lock:
            self._tool_latency_ms[tool].append(float(ms))

    def _build_tool_stats(self) -> dict[str, dict[str, Any]]:
        tools = set(self._tool_allowed) | set(self._tool_blocked) | set(self._tool_latency_ms)
        ranked = sorted(
            tools,
            key=lambda t: -(self._tool_allowed.get(t, 0) + self._tool_blocked.get(t, 0)),
        )[:12]
        out: dict[str, dict[str, Any]] = {}
        for tool in ranked:
            allowed = self._tool_allowed.get(tool, 0)
            blocked = self._tool_blocked.get(tool, 0)
            total = allowed + blocked
            lat_samples = list(self._tool_latency_ms.get(tool, []))
            out[tool] = {
                "allowed": allowed,
                "blocked": blocked,
                "total": total,
                "blocked_pct": round(100 * blocked / max(1, total), 2),
                "latency_ms_avg": round(sum(lat_samples) / max(1, len(lat_samples)), 2),
                "latency_ms_p95": self._percentile_ms(lat_samples, 95),
                "latency_samples": len(lat_samples),
                "blocked_reasons": dict(
                    sorted(self._tool_reason_counts.get(tool, {}).items(), key=lambda x: -x[1])[:3]
                ),
            }
        return out

    @staticmethod
    def _pillar_item(name: str, status: str, detail: str) -> dict[str, str]:
        return {"name": name, "status": status, "detail": detail}

    def _build_pillar_health(self) -> list[dict[str, str]]:
        req = self._metrics.requests_total
        blk = self._metrics.blocked_by_kind
        total_traffic = req + self._metrics.blocked_total

        def blocker_pillar(name: str, kind: str) -> dict[str, str]:
            n = int(blk.get(kind, 0))
            if n > 0:
                return self._pillar_item(name, "active", f"{n} protections triggered")
            if total_traffic > 0:
                return self._pillar_item(name, "healthy", "No triggers observed")
            return self._pillar_item(name, "idle", "No traffic observed yet")

        items = [
            blocker_pillar("Prompt Guard", "injection"),
            self._pillar_item(
                "PII Redaction",
                "active" if self._metrics.pii_redacted_total > 0 else ("healthy" if total_traffic > 0 else "idle"),
                (
                    f"{self._metrics.pii_redacted_total} entities redacted"
                    if self._metrics.pii_redacted_total > 0
                    else ("No PII detections observed" if total_traffic > 0 else "No traffic observed yet")
                ),
            ),
            blocker_pillar("Rate Limiter", "rate_limit"),
            blocker_pillar("Circuit Breaker", "circuit_breaker"),
            blocker_pillar("Content Filter", "content_filter"),
            blocker_pillar("RBAC", "rbac"),
            blocker_pillar("Schema Validation", "schema_validation"),
            blocker_pillar("Replay Guard", "replay"),
            self._pillar_item(
                "Cost Tracker",
                "active" if self._metrics.cost_total > 0 else ("healthy" if total_traffic > 0 else "idle"),
                (
                    f"${self._metrics.cost_total:.2f} tracked"
                    if self._metrics.cost_total > 0
                    else ("No spend observed" if total_traffic > 0 else "No traffic observed yet")
                ),
            ),
            self._pillar_item(
                "Semantic Cache",
                "healthy" if total_traffic > 0 else "idle",
                "Cache telemetry not yet instrumented",
            ),
            self._pillar_item(
                "Audit Log",
                "healthy" if total_traffic > 0 else "idle",
                "Receiving events" if total_traffic > 0 else "No events observed yet",
            ),
        ]
        return items

    def _build_dashboard_insights(self) -> list[dict[str, Any]]:
        """Heuristic anomaly / tuning hints from current aggregates (not ML)."""
        out: list[dict[str, Any]] = []
        m = self._metrics
        req = int(m.requests_total)
        reason_sum = sum(m.blocked_by_reason.values())
        blk = max(int(m.blocked_total), int(reason_sum))
        total_inv = req + blk

        if total_inv >= 8:
            share = blk / max(total_inv, 1)
            if share > 0.14:
                out.append(
                    {
                        "severity": "warning",
                        "code": "high_block_share",
                        "title": "Elevated block share",
                        "detail": f"{share * 100:.1f}% of invocations blocked — review policies, tenants, and top tools.",
                    }
                )

        samples = list(self._latency_ms)
        if len(samples) >= 25:
            p50 = self._percentile_ms(samples, 50)
            p95 = self._percentile_ms(samples, 95)
            if p50 > 0.5 and p95 > 2.8 * p50:
                out.append(
                    {
                        "severity": "info",
                        "code": "latency_tail",
                        "title": "Latency tail vs median",
                        "detail": f"P95 {p95:.1f} ms vs P50 {p50:.1f} ms — inspect slow tools and upstream MCP latency.",
                    }
                )

        ts = self._snapshot_time_series()
        if len(ts) >= 10:
            lb = [int(b.get("blocked") or 0) for b in ts]
            recent = sum(lb[-3:])
            baseline = sum(lb[-10:-3]) / 7.0
            if baseline >= 1.5 and recent >= baseline * 2.2:
                out.append(
                    {
                        "severity": "warning",
                        "code": "blocked_spike",
                        "title": "Blocked traffic spike",
                        "detail": "Recent 30s buckets show more blocks than the prior window — possible abuse or misconfiguration.",
                    }
                )

        stats = self._build_tool_stats()
        for tname, s in stats.items():
            tot = int(s.get("total") or 0)
            bp = float(s.get("blocked_pct") or 0)
            if tot >= 12 and bp >= 32:
                out.append(
                    {
                        "severity": "warning",
                        "code": "tool_hot",
                        "title": f'Tool "{tname}" is denial-heavy',
                        "detail": f"{bp:.0f}% blocked ({s.get('blocked', 0)} / {tot}) — check RBAC, rate limits, and reasons column.",
                    }
                )
                break

        elapsed = self._elapsed_seconds_window(m.window_start)
        if m.cost_total > 0 and elapsed > 2 and req > 0:
            per_h = float(m.cost_total) / elapsed * 3600.0
            if per_h >= 4.0:
                out.append(
                    {
                        "severity": "info",
                        "code": "cost_run",
                        "title": "Sustained cost burn",
                        "detail": f"~${per_h:.2f}/hr implied from this metrics window — align with FinOps budgets.",
                    }
                )

        if m.pii_redacted_total > 25 and req > 0:
            ratio = m.pii_redacted_total / max(req, 1)
            if ratio > 0.4:
                out.append(
                    {
                        "severity": "info",
                        "code": "pii_dense",
                        "title": "High PII touch rate",
                        "detail": f"{m.pii_redacted_total} redactions vs {req} allowed calls — validate detectors and data minimization.",
                    }
                )

        kinds = dict(m.blocked_by_kind)
        if kinds and blk >= 6:
            top_kind, top_n = max(kinds.items(), key=lambda x: x[1])
            if top_n / max(blk, 1) >= 0.52:
                out.append(
                    {
                        "severity": "info",
                        "code": "kind_skew",
                        "title": f'Blocks skew toward "{top_kind}"',
                        "detail": f"{100 * top_n / max(blk, 1):.0f}% of blocks share one category — tune rules if unintended.",
                    }
                )

        for a in m.alerts[-8:]:
            if a.get("severity") == "critical":
                out.append(
                    {
                        "severity": "warning",
                        "code": "alert_critical",
                        "title": "Critical alert in feed",
                        "detail": (a.get("message") or "")[:220],
                    }
                )
                break

        return out[:12]

    def record_cost(self, amount: float, user: str | None = None) -> None:
        with self._lock:
            self._metrics.cost_total += amount
            if user:
                self._metrics.cost_by_user[user] += amount

    def add_alert(self, kind: str, message: str, severity: str = "warning") -> None:
        with self._lock:
            self._metrics.alerts.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "kind": kind,
                "message": message,
                "severity": severity,
            })
            if len(self._metrics.alerts) > 100:
                self._metrics.alerts = self._metrics.alerts[-100:]

    def get_metrics(self) -> dict[str, Any]:
        with self._lock:
            d = self._metrics.to_dict()
            d["time_series"] = self._snapshot_time_series()
            d["time_series_bucket_seconds"] = TIME_BUCKET_SECONDS
            d["time_series_window_seconds"] = TIME_BUCKET_SECONDS * TIME_BUCKET_COUNT
            samples = list(self._latency_ms)
            d["latency_ms"] = {
                "p50": self._percentile_ms(samples, 50),
                "p95": self._percentile_ms(samples, 95),
                "p99": self._percentile_ms(samples, 99),
                "samples": len(samples),
            }
            elapsed = self._elapsed_seconds_window(self._metrics.window_start)
            cost = float(self._metrics.cost_total)
            per_hour = cost / elapsed * 3600.0
            d["cost_burn"] = {
                "per_hour_usd": round(per_hour, 4),
                "projected_daily_usd": round(per_hour * 24.0, 2),
                "window_elapsed_seconds": round(elapsed, 1),
            }
            d["tool_stats"] = self._build_tool_stats()
            d["pillar_health"] = self._build_pillar_health()
            d["blocked_incidents"] = list(reversed(self._blocked_incidents))
            d["dashboard_insights"] = self._build_dashboard_insights()
            return d

    def reset(self) -> None:
        with self._lock:
            self._metrics = DashboardMetrics()
            self._time_buckets = {}
            self._latency_ms.clear()
            self._tool_allowed = defaultdict(int)
            self._tool_blocked = defaultdict(int)
            self._tool_reason_counts = defaultdict(lambda: defaultdict(int))
            self._tool_latency_ms = defaultdict(lambda: deque(maxlen=LATENCY_SAMPLE_CAP // 4))
            self._blocked_incidents.clear()
