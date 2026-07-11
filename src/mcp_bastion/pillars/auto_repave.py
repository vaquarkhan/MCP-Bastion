"""
Auto-repave: automated response when detection thresholds are crossed in a rolling window.
"""

from __future__ import annotations

import json
import logging
import threading
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
        self._lock = threading.Lock()

    def _window_seconds(self) -> float:
        return float(self.triggers.get("window_minutes", 5)) * 60.0

    def _threshold(self, key: str) -> int:
        return int(self.triggers.get(key, 0))

    def _count_key(self, event: str) -> str:
        return f"{self._ns}:count:{event}"

    def _load_times(self, key: str) -> list[float]:
        if self._backend is None:
            return list(self._local_counts.get(key, []))
        raw = self._backend.get(key)
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []
        return [float(t) for t in data if isinstance(t, (int, float))]

    def _save_times(self, key: str, times: list[float]) -> None:
        if self._backend is None:
            self._local_counts[key] = list(times)
            return
        self._backend.set(key, json.dumps(times))

    def _clear_times(self, key: str) -> None:
        if self._backend is None:
            self._local_counts[key] = []
            return
        self._backend.delete(key)

    def record_detection(self, event: str = "canary_detections") -> list[str]:
        """Record one detection; return action names fired (may be empty)."""
        now = time.time()
        window = self._window_seconds()
        threshold = self._threshold(event)
        if threshold <= 0:
            return []

        key = self._count_key(event)
        with self._lock:
            times = [t for t in self._load_times(key) if now - t <= window]
            times.append(now)
            count = len(times)
            if count < threshold:
                self._save_times(key, times)
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
                self._clear_times(key)
            else:
                self._save_times(key, times)
            return fired
