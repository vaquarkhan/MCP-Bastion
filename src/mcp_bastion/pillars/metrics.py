"""
In-memory metrics for dashboard and OpenTelemetry export.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from mcp_bastion.pillars.audit_hash_chain import AuditHashChain
from datetime import datetime, timezone
from typing import Any

# Rolling window for dashboard sparkline: 20 × 30s = 10 minutes
TIME_BUCKET_SECONDS = 30
TIME_BUCKET_COUNT = 20
LATENCY_SAMPLE_CAP = 2000
FORENSIC_EVENT_CAP = 500
ANOMALY_EVENT_CAP = 200


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
        self._forensic_events: deque[dict[str, Any]] = deque(maxlen=FORENSIC_EVENT_CAP)
        self._anomalies: deque[dict[str, Any]] = deque(maxlen=ANOMALY_EVENT_CAP)
        self._tool_rate_window: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=500))
        self._tool_rate_baseline: dict[str, float] = defaultdict(float)
        self._tool_latency_baseline: dict[str, float] = defaultdict(float)
        self._last_anomaly_key_ts: dict[str, float] = {}
        self._cost_by_provider: dict[str, float] = defaultdict(float)
        self._cost_by_model: dict[str, float] = defaultdict(float)
        self._cost_by_tool_dim: dict[str, float] = defaultdict(float)
        self._cost_by_dataset: dict[str, float] = defaultdict(float)
        self._tenant_requests: dict[str, int] = defaultdict(int)
        self._tenant_blocked: dict[str, int] = defaultdict(int)
        self._tenant_cost: dict[str, float] = defaultdict(float)
        self._session_sequences: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=24))
        self._session_frozen_baseline: dict[str, set[str]] = {}
        self._session_calls: dict[str, int] = defaultdict(int)

    def _record_anomaly(self, *, kind: str, tool: str, message: str, value: float, baseline: float) -> None:
        now = time.time()
        key = f"{kind}:{tool}"
        last = self._last_anomaly_key_ts.get(key, 0.0)
        if now - last < 30.0:
            return
        self._last_anomaly_key_ts[key] = now
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "tool": tool,
            "message": message,
            "value": round(value, 4),
            "baseline": round(baseline, 4),
        }
        self._anomalies.append(event)
        self._metrics.alerts.append(
            {
                "ts": event["ts"],
                "kind": "auto_tune_anomaly",
                "message": message,
                "severity": "warning",
            }
        )
        if len(self._metrics.alerts) > 100:
            self._metrics.alerts = self._metrics.alerts[-100:]

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
        if "semantic firewall" in lower or "intent mismatch" in lower or "dangerous tool chain" in lower:
            return "semantic_firewall"
        if "external policy" in lower or "opa denied" in lower or "cedar denied" in lower:
            return "external_policy"
        if "sensitive content" in lower or "classifier" in lower:
            return "sensitive_classifier"
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

    def record_session_tool(self, session_id: str | None, tool: str) -> None:
        """Track per-session tool sequence for behavior fingerprinting."""
        sid = session_id or "default"
        with self._lock:
            self._session_calls[sid] += 1
            self._session_sequences[sid].append(tool)
            n = self._session_calls[sid]
            if sid not in self._session_frozen_baseline and n >= 18:
                self._session_frozen_baseline[sid] = set(self._session_sequences[sid])
            baseline = self._session_frozen_baseline.get(sid)
            if baseline and n >= 28 and len(self._session_sequences[sid]) >= 10:
                window = list(self._session_sequences[sid])[-10:]
                uniq = set(window)
                overlap = len(uniq & baseline) / max(1, len(uniq))
                if overlap < 0.25:
                    self._record_anomaly(
                        kind="behavior_drift",
                        tool=tool,
                        message=f"session {sid} recent tools diverge from established baseline (overlap={overlap:.2f})",
                        value=float(overlap),
                        baseline=1.0,
                    )

    def record_request(self, tool: str, user: str | None = None, tenant: str | None = None) -> None:
        with self._lock:
            self._metrics.requests_total += 1
            self._metrics.top_tools[tool] += 1
            self._tool_allowed[tool] += 1
            if tenant:
                self._tenant_requests[str(tenant)] += 1
            now = time.time()
            win = self._tool_rate_window[tool]
            win.append(now)
            cutoff = now - 60.0
            while win and win[0] < cutoff:
                win.popleft()
            current_rate = float(len(win))
            baseline = self._tool_rate_baseline.get(tool, 0.0)
            if baseline <= 0:
                self._tool_rate_baseline[tool] = max(1.0, current_rate)
            else:
                self._tool_rate_baseline[tool] = baseline * 0.95 + current_rate * 0.05
                if baseline >= 2.0 and current_rate >= baseline * 10.0:
                    self._record_anomaly(
                        kind="call_rate_spike",
                        tool=tool,
                        message=f"tool {tool} call rate is {current_rate:.1f}/min vs baseline {baseline:.1f}/min",
                        value=current_rate,
                        baseline=baseline,
                    )
            self._bump_time_bucket(allowed=1)
            if user:
                pass  # cost_by_user updated by record_cost

    def record_blocked(self, reason: str, tool: str = "unknown", tenant: str | None = None) -> None:
        with self._lock:
            kind = self._normalize_reason_kind(reason)
            self._metrics.blocked_total += 1
            self._metrics.blocked_by_reason[reason] += 1
            self._metrics.blocked_by_kind[kind] += 1
            self._metrics.top_tools[tool] += 1
            self._tool_blocked[tool] += 1
            self._tool_reason_counts[tool][kind] += 1
            if tenant:
                self._tenant_blocked[str(tenant)] += 1
            self._bump_time_bucket(blocked=1)

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
            baseline = self._tool_latency_baseline.get(tool, 0.0)
            if baseline <= 0:
                self._tool_latency_baseline[tool] = float(ms)
            else:
                self._tool_latency_baseline[tool] = baseline * 0.95 + float(ms) * 0.05
                if baseline >= 5.0 and float(ms) >= baseline * 10.0:
                    self._record_anomaly(
                        kind="latency_spike",
                        tool=tool,
                        message=f"tool {tool} latency is {float(ms):.2f}ms vs baseline {baseline:.2f}ms",
                        value=float(ms),
                        baseline=baseline,
                    )

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
            blocker_pillar("Semantic Firewall", "semantic_firewall"),
            blocker_pillar("Sensitive Classifier", "sensitive_classifier"),
            blocker_pillar("External Policy", "external_policy"),
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

    def record_cost(
        self,
        amount: float,
        user: str | None = None,
        dimensions: dict[str, Any] | None = None,
        tenant: str | None = None,
    ) -> None:
        with self._lock:
            self._metrics.cost_total += amount
            if user:
                self._metrics.cost_by_user[user] += amount
            if tenant:
                self._tenant_cost[str(tenant)] += amount
            if dimensions and amount > 0:
                p = dimensions.get("llm_provider")
                m = dimensions.get("llm_model")
                t = dimensions.get("tool")
                d = dimensions.get("dataset")
                if p:
                    self._cost_by_provider[str(p)] += amount
                if m:
                    self._cost_by_model[str(m)] += amount
                if t:
                    self._cost_by_tool_dim[str(t)] += amount
                if d:
                    self._cost_by_dataset[str(d)] += amount

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

    def record_forensic_event(self, event: dict[str, Any]) -> None:
        """Store a forensic event for dashboard drill-down and replay payload export."""
        if not isinstance(event, dict):
            return
        with self._lock:
            self._forensic_events.append(dict(event))

    def list_forensic_events(
        self,
        *,
        limit: int = 20,
        blocked_only: bool = False,
        include_full: bool = False,
    ) -> list[dict[str, Any]]:
        """List latest forensic events; optionally summaries only."""
        with self._lock:
            events = list(self._forensic_events)
        return self._build_forensic_list(
            events,
            limit=limit,
            blocked_only=blocked_only,
            include_full=include_full,
        )

    @staticmethod
    def _build_forensic_list(
        events: list[dict[str, Any]],
        *,
        limit: int,
        blocked_only: bool,
        include_full: bool,
    ) -> list[dict[str, Any]]:
        max_items = max(1, int(limit))
        events = list(reversed(events))
        out: list[dict[str, Any]] = []
        for event in events:
            if blocked_only and event.get("action") != "BLOCKED":
                continue
            if include_full:
                out.append(dict(event))
            else:
                out.append(
                    {
                        "event_id": event.get("event_id"),
                        "timestamp": event.get("timestamp"),
                        "tool": event.get("tool"),
                        "action": event.get("action"),
                        "reason": event.get("reason"),
                        "request_id": event.get("request_id"),
                        "session_id": event.get("session_id"),
                        "tenant_id": event.get("tenant_id"),
                        "latency_ms": event.get("latency_ms"),
                    }
                )
            if len(out) >= max_items:
                break
        return out

    def get_forensic_event(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            for event in reversed(self._forensic_events):
                if event.get("event_id") == event_id:
                    return dict(event)
        return None

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
            d["forensic_recent_blocked"] = self._build_forensic_list(
                list(self._forensic_events),
                limit=20,
                blocked_only=True,
                include_full=False,
            )
            d["auto_tune"] = {
                "latency_baseline_ms": dict(
                    sorted(((k, round(v, 2)) for k, v in self._tool_latency_baseline.items()), key=lambda x: -x[1])[:20]
                ),
                "call_rate_baseline_per_min": dict(
                    sorted(((k, round(v, 2)) for k, v in self._tool_rate_baseline.items()), key=lambda x: -x[1])[:20]
                ),
                "recent_anomalies": list(self._anomalies)[-20:],
            }
            d["cost_attribution"] = {
                "by_provider": dict(sorted(self._cost_by_provider.items(), key=lambda x: -x[1])[:15]),
                "by_model": dict(sorted(self._cost_by_model.items(), key=lambda x: -x[1])[:15]),
                "by_tool": dict(sorted(self._cost_by_tool_dim.items(), key=lambda x: -x[1])[:15]),
                "by_dataset": dict(sorted(self._cost_by_dataset.items(), key=lambda x: -x[1])[:15]),
            }
            tenants = set(self._tenant_requests) | set(self._tenant_blocked) | set(self._tenant_cost)
            d["tenants"] = {
                t: {
                    "requests_total": int(self._tenant_requests.get(t, 0)),
                    "blocked_total": int(self._tenant_blocked.get(t, 0)),
                    "cost_total": round(float(self._tenant_cost.get(t, 0.0)), 4),
                }
                for t in sorted(
                    tenants,
                    key=lambda x: -(
                        self._tenant_requests.get(x, 0)
                        + self._tenant_blocked.get(x, 0)
                    ),
                )[:50]
            }
            d["audit_chain"] = {
                **AuditHashChain.get().head(),
                "recent_links": AuditHashChain.get().recent_links(12),
                "anchors": AuditHashChain.get().anchors()[-5:],
            }
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
            self._forensic_events = deque(maxlen=FORENSIC_EVENT_CAP)
            self._anomalies = deque(maxlen=ANOMALY_EVENT_CAP)
            self._tool_rate_window = defaultdict(lambda: deque(maxlen=500))
            self._tool_rate_baseline = defaultdict(float)
            self._tool_latency_baseline = defaultdict(float)
            self._last_anomaly_key_ts = {}
            self._cost_by_provider = defaultdict(float)
            self._cost_by_model = defaultdict(float)
            self._cost_by_tool_dim = defaultdict(float)
            self._cost_by_dataset = defaultdict(float)
            self._tenant_requests = defaultdict(int)
            self._tenant_blocked = defaultdict(int)
            self._tenant_cost = defaultdict(float)
            self._session_sequences = defaultdict(lambda: deque(maxlen=24))
            self._session_frozen_baseline = {}
            self._session_calls = defaultdict(int)
            AuditHashChain.get().reset()
