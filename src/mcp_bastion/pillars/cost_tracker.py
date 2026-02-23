"""
Cost tracking and budgets for MCP-Bastion.

Track actual cost per session/user. Kill switch when budget exceeded.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CostState:
    """Per-session cost state."""

    cost: float = 0.0
    started_at: float = field(default_factory=time.monotonic)


from mcp_bastion.errors import CostBudgetExceededError


class CostTracker:
    """
    Track cost per session. Enforce budgets.

    Uses simple cost model: pass cost per call or use token-based estimate.
    """

    def __init__(
        self,
        max_cost_per_session: float = 0.50,
        max_cost_per_day: float = 10.0,
        alert_threshold: float = 0.80,
        day_reset_seconds: float = 86400,
    ) -> None:
        self.max_cost_per_session = max_cost_per_session
        self.max_cost_per_day = max_cost_per_day
        self.alert_threshold = alert_threshold
        self.day_reset_seconds = day_reset_seconds
        self._sessions: dict[str, CostState] = defaultdict(CostState)
        self._daily: dict[str, list[tuple[float, float]]] = defaultdict(list)

    def _get_key(self, session_id: str | None, request_id: str | None) -> str:
        return session_id or request_id or "default"

    def _cleanup_old_daily(self, key: str) -> None:
        now = time.monotonic()
        self._daily[key] = [(t, c) for t, c in self._daily[key] if now - t < self.day_reset_seconds]

    def check(self, session_id: str | None = None, request_id: str | None = None) -> None:
        """
        Check if session can proceed. Raises CostBudgetExceededError if over budget.
        """
        key = self._get_key(session_id, request_id)
        state = self._sessions[key]
        self._cleanup_old_daily(key)

        if state.cost >= self.max_cost_per_session:
            raise CostBudgetExceededError(
                f"Session cost ${state.cost:.2f} exceeds limit ${self.max_cost_per_session:.2f}"
            )

        daily_total = sum(c for _, c in self._daily[key])
        if daily_total >= self.max_cost_per_day:
            raise CostBudgetExceededError(
                f"Daily cost ${daily_total:.2f} exceeds limit ${self.max_cost_per_day:.2f}"
            )

    def record(self, cost: float, session_id: str | None = None, request_id: str | None = None) -> None:
        """Record cost for session."""
        key = self._get_key(session_id, request_id)
        now = time.monotonic()
        self._sessions[key].cost += cost
        self._daily[key].append((now, cost))

        state = self._sessions[key]
        if state.cost >= self.max_cost_per_session * self.alert_threshold:
            logger.warning("cost_tracker alert session=%s cost=%.2f threshold=%.0f%%", key, state.cost, self.alert_threshold * 100)

    def reset_session(self, session_id: str | None = None, request_id: str | None = None) -> None:
        """Reset session cost."""
        key = self._get_key(session_id, request_id)
        if key in self._sessions:
            del self._sessions[key]
