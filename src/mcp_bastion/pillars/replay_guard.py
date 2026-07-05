"""
Replay attack prevention for MCP-Bastion.

Prevent request replay attacks via nonce and max age.
Supports pluggable StateBackend (Redis) for multi-replica deployments.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from mcp_bastion.errors import ReplayAttackError
from mcp_bastion.pillars.state_backend import MemoryStateBackend, StateBackend

logger = logging.getLogger(__name__)


class ReplayGuard:
    """
    Prevent replay attacks.

    - require_nonce: Reject requests without unique nonce
    - max_request_age_seconds: Reject requests older than this
    """

    def __init__(
        self,
        require_nonce: bool = True,
        max_request_age_seconds: float = 30.0,
        max_nonce_cache: int = 10_000,
        *,
        backend: StateBackend | None = None,
        backend_namespace: str = "replay",
    ) -> None:
        if max_request_age_seconds < 0:
            raise ValueError("max_request_age_seconds must be >= 0")
        if max_nonce_cache < 1:
            raise ValueError("max_nonce_cache must be >= 1")
        self.require_nonce = require_nonce
        self.max_request_age_seconds = max_request_age_seconds
        self._max_nonce_cache = max_nonce_cache
        self._backend = backend or MemoryStateBackend()
        self._backend_namespace = backend_namespace
        self._uses_shared_backend = backend is not None
        self._seen_nonces: dict[str, float] = {}
        self._lock = threading.Lock()

    def _nonce_key(self, nonce: str) -> str:
        return f"{self._backend_namespace}:{nonce}"

    def _get_nonce(self, message: Any) -> str | None:
        """Extract nonce from message params or metadata."""
        if hasattr(message, "root"):
            msg = message.root
        else:
            msg = message
        if isinstance(msg, dict):
            params = msg.get("params") or msg.get("result") or msg
            if isinstance(params, dict):
                return params.get("nonce")
        return None

    def _get_timestamp(self, message: Any) -> float | None:
        """Extract timestamp from message (epoch seconds)."""
        if hasattr(message, "root"):
            msg = message.root
        else:
            msg = message
        if isinstance(msg, dict):
            params = msg.get("params") or msg.get("result") or msg
            if isinstance(params, dict) and "timestamp" in params:
                try:
                    return float(params["timestamp"])
                except (TypeError, ValueError):
                    pass
        return None

    def check(self, message: Any) -> None:
        """
        Check for replay. Raises ReplayAttackError if detected.
        """
        now = time.time()

        if self.require_nonce:
            nonce = self._get_nonce(message)
            if not nonce:
                logger.warning("replay_guard blocked missing_nonce")
                raise ReplayAttackError("Request must include nonce")

            nonce_str = str(nonce)
            ttl = max(1.0, self.max_request_age_seconds or 30.0)
            if self._uses_shared_backend:
                if not self._backend.set_nx(self._nonce_key(nonce_str), "1", ttl_seconds=ttl):
                    logger.warning("replay_guard blocked duplicate_nonce")
                    raise ReplayAttackError("Duplicate nonce: replay detected")
            else:
                with self._lock:
                    if nonce_str in self._seen_nonces:
                        logger.warning("replay_guard blocked duplicate_nonce")
                        raise ReplayAttackError("Duplicate nonce: replay detected")
                    while len(self._seen_nonces) >= self._max_nonce_cache:
                        oldest = next(iter(self._seen_nonces))
                        del self._seen_nonces[oldest]
                    self._seen_nonces[nonce_str] = now

        if self.max_request_age_seconds > 0:
            ts = self._get_timestamp(message)
            if ts is not None:
                age = now - ts
                if age > self.max_request_age_seconds or age < -60:
                    logger.warning("replay_guard blocked stale_request age=%.1f", age)
                    raise ReplayAttackError(f"Request too old: {age:.0f}s")
