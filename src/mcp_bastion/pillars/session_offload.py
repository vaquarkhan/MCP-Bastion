"""
Session-scoped in-memory store for offloaded tool output.

Lightweight alternative to external SQLite caches: full payloads stay in process
memory for the current session only (no disk persistence, no new dependencies).
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _OffloadEntry:
    text: str
    created_at: float
    tool_name: str | None = None


class SessionOffloadStore:
    """Thread-safe, TTL-bound session store for truncated tool responses."""

    def __init__(
        self,
        *,
        ttl_seconds: float = 3600.0,
        max_entries_per_session: int = 100,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        if max_entries_per_session < 1:
            raise ValueError("max_entries_per_session must be >= 1")
        self.ttl_seconds = ttl_seconds
        self.max_entries_per_session = max_entries_per_session
        self._sessions: dict[str, dict[str, _OffloadEntry]] = {}
        self._lock = threading.Lock()

    def _session_key(self, session_id: str | None) -> str:
        return session_id or "default"

    def _purge_expired(self, session: dict[str, _OffloadEntry], now: float) -> None:
        expired = [k for k, e in session.items() if now - e.created_at > self.ttl_seconds]
        for k in expired:
            del session[k]

    def put(
        self,
        text: str,
        *,
        session_id: str | None = None,
        tool_name: str | None = None,
    ) -> str:
        """Store text and return an opaque retrieval key."""
        key = secrets.token_hex(8)
        now = time.monotonic()
        sk = self._session_key(session_id)
        with self._lock:
            session = self._sessions.setdefault(sk, {})
            self._purge_expired(session, now)
            while len(session) >= self.max_entries_per_session:
                oldest = min(session.items(), key=lambda kv: kv[1].created_at)[0]
                del session[oldest]
            session[key] = _OffloadEntry(text=text, created_at=now, tool_name=tool_name)
        return key

    def get(self, key: str, *, session_id: str | None = None) -> str | None:
        """Return stored text for key, or None if missing/expired."""
        sk = self._session_key(session_id)
        now = time.monotonic()
        with self._lock:
            session = self._sessions.get(sk)
            if not session:
                return None
            entry = session.get(key)
            if entry is None:
                return None
            if now - entry.created_at > self.ttl_seconds:
                del session[key]
                return None
            return entry.text

    def stats(self, *, session_id: str | None = None) -> dict[str, Any]:
        """Return entry count for a session (for FinOps telemetry)."""
        sk = self._session_key(session_id)
        now = time.monotonic()
        with self._lock:
            session = self._sessions.get(sk, {})
            self._purge_expired(session, now)
            return {"entries": len(session)}
