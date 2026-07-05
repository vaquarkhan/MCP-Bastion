"""In-memory session governance events for attestation export."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class GovernanceEvent:
    session_id: str
    request_id: str | None
    method: str
    tool: str | None
    pillar: str
    status: str
    cost_usd: float
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SessionGovernanceRecorder:
    """Thread-safe per-session event log for compliance attestation."""

    _lock = threading.Lock()
    _instance: SessionGovernanceRecorder | None = None

    def __init__(self, *, max_events_per_session: int = 500) -> None:
        self._max = max(10, int(max_events_per_session))
        self._sessions: dict[str, list[GovernanceEvent]] = {}

    @classmethod
    def get(cls) -> SessionGovernanceRecorder:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._instance = cls()

    def record(
        self,
        *,
        session_id: str,
        request_id: str | None,
        method: str,
        tool: str | None,
        pillar: str,
        status: str,
        cost_usd: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not session_id:
            return
        ev = GovernanceEvent(
            session_id=session_id,
            request_id=request_id,
            method=method,
            tool=tool,
            pillar=pillar,
            status=status,
            cost_usd=cost_usd,
            metadata=dict(metadata or {}),
        )
        with self._lock:
            bucket = self._sessions.setdefault(session_id, [])
            bucket.append(ev)
            if len(bucket) > self._max:
                del bucket[: len(bucket) - self._max]

    def events_for_session(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = list(self._sessions.get(session_id, []))
        return [
            {
                "session_id": e.session_id,
                "request_id": e.request_id,
                "method": e.method,
                "tool": e.tool,
                "pillar": e.pillar,
                "status": e.status,
                "cost_usd": round(e.cost_usd, 4),
                "metadata": e.metadata,
                "timestamp": e.timestamp,
            }
            for e in rows
        ]

    def session_ids(self) -> list[str]:
        with self._lock:
            return list(self._sessions.keys())
