"""
Agent stability monitor - detect repetitive tool-output loops (infinite agentic loops).

Uses a sliding window of normalized observation fingerprints stored in the
pluggable StateBackend so detection works across stateless, load-balanced requests
when keyed by explicit state handles.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from mcp_bastion.pillars.semantic_cache import _jaccard_similarity, _normalize
from mcp_bastion.pillars.state_backend import MemoryStateBackend, StateBackend

logger = logging.getLogger(__name__)

CIRCUIT_BREAKER_HINT = (
    "Bastion stability monitor: you have received nearly identical tool results "
    "multiple times in a row. Stop retrying the same action; change strategy or "
    "ask for clarification."
)


@dataclass(frozen=True)
class StabilityCheckResult:
    repetitive: bool
    similarity: float
    window_size: int
    repeats: int


class AgentStabilityMonitor:
    """
    Sliding-window similarity monitor for tool observations.

    When consecutive outputs exceed ``similarity_threshold``, the monitor flags a
    repetitive loop. Middleware may inject a circuit-breaker hint or block.
    """

    def __init__(
        self,
        *,
        window_size: int = 5,
        repeat_threshold: int = 3,
        similarity_threshold: float = 0.92,
        backend: StateBackend | None = None,
        backend_namespace: str = "agent_stability",
        ttl_seconds: float = 3600.0,
    ) -> None:
        if window_size < 2:
            raise ValueError("window_size must be >= 2")
        if repeat_threshold < 2:
            raise ValueError("repeat_threshold must be >= 2")
        if not 0.0 < similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be in (0, 1]")
        self.window_size = window_size
        self.repeat_threshold = repeat_threshold
        self.similarity_threshold = similarity_threshold
        self._backend = backend or MemoryStateBackend()
        self._namespace = backend_namespace
        self._ttl_seconds = ttl_seconds

    def _key(self, scope: str) -> str:
        digest = hashlib.sha256(scope.encode()).hexdigest()[:24]
        return f"{self._namespace}:{digest}"

    def _load_window(self, scope: str) -> list[str]:
        raw = self._backend.get_json(self._key(scope))
        if not raw:
            return []
        items = raw.get("observations")
        if not isinstance(items, list):
            return []
        return [str(x) for x in items if isinstance(x, str)][-self.window_size :]

    def _save_window(self, scope: str, window: list[str]) -> None:
        trimmed = window[-self.window_size :]
        self._backend.set_json(
            self._key(scope),
            {"observations": trimmed},
            ttl_seconds=self._ttl_seconds,
        )

    def check_and_record(self, scope: str, observation_text: str) -> StabilityCheckResult:
        """
        Record observation and return whether the window shows a repetitive loop.
        """
        norm_new = _normalize(observation_text)
        if not norm_new:
            return StabilityCheckResult(repetitive=False, similarity=0.0, window_size=0, repeats=0)

        window = self._load_window(scope)
        repeats = 0
        max_sim = 0.0

        for prior_norm in window:
            if prior_norm == norm_new:
                repeats += 1
                max_sim = 1.0
                continue
            sim = _jaccard_similarity(norm_new, prior_norm)
            max_sim = max(max_sim, sim)
            if sim >= self.similarity_threshold:
                repeats += 1

        window.append(norm_new[:512])
        self._save_window(scope, window)

        repetitive = repeats >= self.repeat_threshold - 1 and max_sim >= self.similarity_threshold
        if repetitive:
            logger.warning(
                "agent_stability repetitive loop scope=%s repeats=%d similarity=%.2f",
                scope[:48],
                repeats,
                max_sim,
            )

        return StabilityCheckResult(
            repetitive=repetitive,
            similarity=max_sim,
            window_size=len(window),
            repeats=repeats,
        )

    @staticmethod
    def inject_hint_into_result(result: Any, hint: str = CIRCUIT_BREAKER_HINT) -> Any:
        """Append stability hint to MCP tool result content."""
        if not isinstance(result, dict):
            return result
        content = result.get("content")
        if isinstance(content, list):
            new_content = list(content)
            new_content.append({"type": "text", "text": hint})
            return {**result, "content": new_content}
        if "result" in result and isinstance(result["result"], dict):
            inner = AgentStabilityMonitor.inject_hint_into_result(result["result"], hint)
            return {**result, "result": inner}
        return {**result, "content": [{"type": "text", "text": hint}]}
