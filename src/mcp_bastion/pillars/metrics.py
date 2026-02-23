"""
In-memory metrics for dashboard and OpenTelemetry export.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class DashboardMetrics:
    """Aggregated metrics for real-time dashboard."""

    requests_total: int = 0
    blocked_total: int = 0
    pii_redacted_total: int = 0
    cost_total: float = 0.0
    blocked_by_reason: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    top_tools: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    cost_by_user: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    alerts: list[dict[str, Any]] = field(default_factory=list)
    window_start: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests_total": self.requests_total,
            "blocked_total": self.blocked_total,
            "blocked_pct": round(100 * self.blocked_total / max(1, self.requests_total), 2),
            "pii_redacted_total": self.pii_redacted_total,
            "cost_total": round(self.cost_total, 2),
            "blocked_by_reason": dict(self.blocked_by_reason),
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
            if user:
                pass  # cost_by_user updated by record_cost

    def record_blocked(self, reason: str, tool: str = "unknown") -> None:
        with self._lock:
            self._metrics.blocked_total += 1
            self._metrics.blocked_by_reason[reason] += 1
            self._metrics.top_tools[tool] += 1

    def record_pii_redacted(self, count: int = 1) -> None:
        with self._lock:
            self._metrics.pii_redacted_total += count

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
            return self._metrics.to_dict()

    def reset(self) -> None:
        with self._lock:
            self._metrics = DashboardMetrics()
