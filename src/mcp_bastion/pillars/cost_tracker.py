"""
Cost tracking and budgets for MCP-Bastion.

Track actual cost per session/user. Kill switch when budget exceeded.
Supports pluggable StateBackend (Redis) for multi-replica deployments.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from mcp_bastion.errors import CostBudgetExceededError
from mcp_bastion.pillars.state_backend import MemoryStateBackend, StateBackend

logger = logging.getLogger(__name__)


@dataclass
class CostState:
    """Per-session cost state."""

    cost: float = 0.0
    started_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"cost": self.cost, "started_at": self.started_at}

    @classmethod
    def from_dict(cls, data: dict) -> CostState:
        return cls(
            cost=float(data.get("cost", 0.0)),
            started_at=float(data.get("started_at", time.time())),
        )


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
        *,
        backend: StateBackend | None = None,
        backend_namespace: str = "cost",
        checkpoint_path: str | Path | None = None,
    ) -> None:
        if max_cost_per_session < 0:
            raise ValueError("max_cost_per_session must be >= 0")
        if max_cost_per_day < 0:
            raise ValueError("max_cost_per_day must be >= 0")
        if not 0.0 <= alert_threshold <= 1.0:
            raise ValueError("alert_threshold must be between 0.0 and 1.0")
        self.max_cost_per_session = max_cost_per_session
        self.max_cost_per_day = max_cost_per_day
        self.alert_threshold = alert_threshold
        self.day_reset_seconds = day_reset_seconds
        self._backend = backend or MemoryStateBackend()
        self._backend_namespace = backend_namespace
        self._uses_shared_backend = backend is not None
        self._sessions: dict[str, CostState] = defaultdict(CostState)
        self._daily: dict[str, list[tuple[float, float]]] = defaultdict(list)
        self._lock = threading.Lock()
        self._checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
        if self._checkpoint_path and not self._uses_shared_backend:
            self._load_checkpoint()

    def _load_checkpoint(self) -> None:
        if self._checkpoint_path is None or not self._checkpoint_path.exists():
            return
        try:
            raw = json.loads(self._checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            return
        sessions = raw.get("sessions") if isinstance(raw, dict) else None
        if isinstance(sessions, dict):
            for key, state in sessions.items():
                if isinstance(state, dict):
                    self._sessions[str(key)] = CostState.from_dict(state)

    def _save_checkpoint(self) -> None:
        if self._checkpoint_path is None or self._uses_shared_backend:
            return
        payload = {
            "sessions": {key: state.to_dict() for key, state in self._sessions.items()},
        }
        tmp = self._checkpoint_path.with_suffix(self._checkpoint_path.suffix + ".tmp")
        self._checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(self._checkpoint_path)

    def _session_key(self, key: str) -> str:
        return f"{self._backend_namespace}:session:{key}"

    def _daily_key(self, key: str) -> str:
        return f"{self._backend_namespace}:daily:{key}"

    def _get_key(self, session_id: str | None, request_id: str | None) -> str:
        return session_id or request_id or "default"

    def _session_budget_key(
        self,
        session_id: str | None,
        request_id: str | None,
        principal_id: str | None,
    ) -> str:
        if principal_id:
            return f"principal:{principal_id}"
        return self._get_key(session_id, request_id)

    def _daily_budget_key(self, tenant_id: str | None) -> str:
        return f"daily:tenant:{tenant_id or 'default'}"

    def _load_session(self, key: str) -> CostState:
        if not self._uses_shared_backend:
            return self._sessions[key]
        raw = self._backend.get_json(self._session_key(key))
        if raw:
            return CostState.from_dict(raw)
        return CostState()

    def _save_session(self, key: str, state: CostState) -> None:
        if not self._uses_shared_backend:
            self._sessions[key] = state
            return
        self._backend.set_json(self._session_key(key), state.to_dict())

    def _load_daily(self, key: str) -> list[tuple[float, float]]:
        if not self._uses_shared_backend:
            return list(self._daily[key])
        raw = self._backend.get_json(self._daily_key(key))
        if not raw:
            return []
        entries = raw.get("entries") or []
        out: list[tuple[float, float]] = []
        for item in entries:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                out.append((float(item[0]), float(item[1])))
        return out

    def _save_daily(self, key: str, entries: list[tuple[float, float]]) -> None:
        if not self._uses_shared_backend:
            self._daily[key] = entries
            return
        self._backend.set_json(
            self._daily_key(key),
            {"entries": [[t, c] for t, c in entries]},
            ttl_seconds=self.day_reset_seconds,
        )

    def _cleanup_old_daily(self, key: str) -> list[tuple[float, float]]:
        now = time.time()
        entries = self._load_daily(key)
        kept = [(t, c) for t, c in entries if now - t < self.day_reset_seconds]
        if len(kept) != len(entries):
            self._save_daily(key, kept)
        return kept

    def check(
        self,
        session_id: str | None = None,
        request_id: str | None = None,
        *,
        principal_id: str | None = None,
        tenant_id: str | None = None,
    ) -> None:
        """
        Check if session can proceed. Raises CostBudgetExceededError if over budget.
        """
        key = self._session_budget_key(session_id, request_id, principal_id)
        daily_key = self._daily_budget_key(tenant_id)
        with self._lock:
            state = self._load_session(key)
            daily = self._cleanup_old_daily(daily_key)

            if round(state.cost, 2) >= self.max_cost_per_session:
                raise CostBudgetExceededError(
                    f"Session cost ${state.cost:.2f} exceeds limit ${self.max_cost_per_session:.2f}"
                )

            daily_total = round(sum(c for _, c in daily), 2)
            if daily_total >= self.max_cost_per_day:
                raise CostBudgetExceededError(
                    f"Daily cost ${daily_total:.2f} exceeds limit ${self.max_cost_per_day:.2f}"
                )

    def record(
        self,
        cost: float,
        session_id: str | None = None,
        request_id: str | None = None,
        *,
        principal_id: str | None = None,
        tenant_id: str | None = None,
    ) -> None:
        """Record cost for principal/session and tenant-global daily aggregate."""
        if cost < 0:
            raise ValueError("cost must be >= 0")
        key = self._session_budget_key(session_id, request_id, principal_id)
        daily_key = self._daily_budget_key(tenant_id)
        now = time.time()
        with self._lock:
            state = self._load_session(key)
            state.cost += cost
            self._save_session(key, state)

            daily = self._cleanup_old_daily(daily_key)
            daily.append((now, cost))
            self._save_daily(daily_key, daily)

            if state.cost >= self.max_cost_per_session * self.alert_threshold:
                logger.warning(
                    "cost_tracker alert principal=%s cost=%.2f threshold=%.0f%%",
                    key,
                    state.cost,
                    self.alert_threshold * 100,
                )
            self._save_checkpoint()

    def reset_session(
        self,
        session_id: str | None = None,
        request_id: str | None = None,
        *,
        principal_id: str | None = None,
    ) -> None:
        """Reset session/principal cost."""
        key = self._session_budget_key(session_id, request_id, principal_id)
        with self._lock:
            if self._uses_shared_backend:
                self._backend.delete(self._session_key(key))
            elif key in self._sessions:
                del self._sessions[key]
