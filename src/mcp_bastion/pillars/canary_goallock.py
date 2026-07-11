"""
GoalLock-style exfiltration canary: inject a session token into context and block
outbound tool arguments that echo it back (proof of context exfiltration).
"""

from __future__ import annotations

import json
import logging
import secrets
import uuid
from typing import Any

from mcp_bastion.errors import CanaryExfiltrationError
from mcp_bastion.pillars.state_backend import StateBackend

logger = logging.getLogger(__name__)

_CANARY_BACKEND_KEY = "canary:active"


def generate_canary(*, prefix: str = "BASTION-CANARY-") -> str:
    return f"{prefix}{uuid.uuid4().hex}"


class CanaryGoalLock:
    """Detect canary token leakage in outbound tool-call arguments."""

    def __init__(
        self,
        *,
        token_prefix: str = "BASTION-CANARY-",
        rotate_on_detection: bool = True,
        backend: StateBackend | None = None,
        backend_namespace: str = "canary",
    ) -> None:
        self.token_prefix = token_prefix
        self.rotate_on_detection = rotate_on_detection
        self._backend = backend
        self._ns = backend_namespace
        self._local_token = generate_canary(prefix=token_prefix)

    def _backend_key(self) -> str:
        return f"{self._ns}:{_CANARY_BACKEND_KEY}"

    def active_token(self) -> str:
        if self._backend is not None:
            stored = self._backend.get(self._backend_key())
            if stored:
                return str(stored)
        return self._local_token

    def set_active_token(self, token: str) -> None:
        self._local_token = token
        if self._backend is not None:
            self._backend.set(self._backend_key(), token)

    def rotate_canary(self) -> str:
        token = generate_canary(prefix=self.token_prefix)
        self.set_active_token(token)
        logger.info("canary rotated new_prefix=%s", self.token_prefix)
        return token

    def context_snippet(self) -> str:
        """Text to embed in prompts/tool context so the model may leak it on exfil."""
        return f"[Bastion runtime canary: {self.active_token()}]"

    def check_outbound_arguments(self, arguments: Any) -> None:
        """Scan serialized tool arguments for the active canary."""
        token = self.active_token()
        if not token:
            return
        try:
            blob = json.dumps(arguments, default=str) if not isinstance(arguments, str) else arguments
        except (TypeError, ValueError):
            blob = str(arguments)
        if token in blob:
            logger.warning("canary exfiltration detected token=%s", token[:24])
            if self.rotate_on_detection:
                self.rotate_canary()
            raise CanaryExfiltrationError(
                "Request blocked: runtime canary detected in tool arguments (possible context exfiltration)"
            )

    def on_detection_event(self) -> str:
        """Return new token after detection (for auto-repave integration)."""
        return self.rotate_canary()
