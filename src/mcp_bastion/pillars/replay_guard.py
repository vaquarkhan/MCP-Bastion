"""
Replay attack prevention for MCP-Bastion.

Prevent request replay attacks via nonce and max age.
"""

from __future__ import annotations

import logging
import threading
from typing import Any
import time
from collections import OrderedDict

from mcp_bastion.errors import ReplayAttackError

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
    ) -> None:
        if max_request_age_seconds < 0:
            raise ValueError("max_request_age_seconds must be >= 0")
        if max_nonce_cache < 1:
            raise ValueError("max_nonce_cache must be >= 1")
        self.require_nonce = require_nonce
        self.max_request_age_seconds = max_request_age_seconds
        self._seen_nonces: OrderedDict[str, float] = OrderedDict()
        self._max_nonce_cache = max_nonce_cache
        self._lock = threading.Lock()

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
            with self._lock:
                if nonce_str in self._seen_nonces:
                    logger.warning("replay_guard blocked duplicate_nonce")
                    raise ReplayAttackError("Duplicate nonce: replay detected")

                while len(self._seen_nonces) >= self._max_nonce_cache:
                    self._seen_nonces.popitem(last=False)
                self._seen_nonces[nonce_str] = now

        if self.max_request_age_seconds > 0:
            ts = self._get_timestamp(message)
            if ts is not None:
                age = now - ts
                if age > self.max_request_age_seconds or age < -60:
                    logger.warning("replay_guard blocked stale_request age=%.1f", age)
                    raise ReplayAttackError(f"Request too old: {age:.0f}s")
