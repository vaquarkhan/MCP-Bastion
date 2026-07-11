"""
Auto-repave: automated response when detection thresholds are crossed in a rolling window.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

from mcp_bastion.pillars.state_backend import StateBackend

logger = logging.getLogger(__name__)


class AutoRepaveEngine:
    """Track detection counts and run configured containment actions."""

    def __init__(
        self,
        *,
        triggers: dict[str, Any],
        actions: dict[str, bool],
        backend: StateBackend | None = None,
        backend_namespace: str = "auto_repave",
        on_rotate_canary: Callable[[], None] | None = None,
        on_reset_session_scope: Callable[[], None] | None = None,
        on_kill_sessions: Callable[[], None] | None = None,
    ) -> None:
        self.triggers = triggers or {}
        self.actions = actions or {}
        self._backend = backend
        self._ns = backend_namespace
        self._on_rotate_canary = on_rotate_canary
        self._on_reset_session_scope = on_reset_session_scope
        self._on_kill_sessions = on_kill_sessions
        self._local_counts: dict[str, list[float]] = {}

    def _window_seconds(self) -> float:
        return float(self.triggers.get("window_minutes", 5)) * 60.0

    def _threshold(self, key: str) -> int:
        return int(self.triggers.get(key, 0))

    def _count_key(self, event: str) -> str:
        return f"{self._ns}:count:{event}"

    def record_detection(self, event: str = "canary_detections") -> list[str]:
        """Record one detection; return action names fired (may be empty)."""
        now = time.time()
        window = self._window_seconds()
        threshold = self._threshold(event)
        if threshold <= 0:
            return []

        if self._backend is not None:
            key = self._count_key(event)
            raw = self._backend.get_json(key) or []
            times = [float(t) for t in raw if isinstance(t, (int, float))]
            times = [t for t in times if now - t <= window]
            times.append(now)
            self._backend.set_json(key, times)
            count = len(times)
        else:
            times = self._local_counts.setdefault(event, [])
            times[:] = [t for t in times if now - t <= window]
            times.append(now)
            count = len(times)

        if count < threshold:
            return []

        fired: list[str] = []
        if self.actions.get("rotate_canary") and self._on_rotate_canary:
            self._on_rotate_canary()
            fired.append("rotate_canary")
        if self.actions.get("reset_session_scope") and self._on_reset_session_scope:
            self._on_reset_session_scope()
            fired.append("reset_session_scope")
        if self.actions.get("kill_sessions") and self._on_kill_sessions:
            self._on_kill_sessions()
            fired.append("kill_sessions")
        if fired:
            logger.warning("auto_repave fired event=%s count=%d actions=%s", event, count, fired)
            # reset counter after repave
            if self._backend is not None:
                self._backend.delete(self._count_key(event))
            else:
                self._local_counts[event] = []
        return fired
