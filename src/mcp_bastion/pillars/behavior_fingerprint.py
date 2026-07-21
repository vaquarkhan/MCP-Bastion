"""
Per-agent behavioral fingerprinting - learn tool baselines, detect drift and rate spikes.

Opt-in via bastion.yaml ``behavior_fingerprint``. Uses pluggable StateBackend so
baselines sync across replicas when combined with ``state_backend: redis``.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from mcp_bastion.pillars.state_backend import MemoryStateBackend, StateBackend

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BehaviorCheckResult:
    anomalous: bool
    kind: str | None  # tool_drift | rate_spike
    overlap: float | None = None
    current_rate: float | None = None
    baseline_rate: float | None = None
    message: str | None = None


class BehaviorFingerprintMonitor:
    """
    Learn per-principal tool usage baselines; flag drift or call-rate spikes.

    Designed for shadow/observe deployments first: ``on_detect: warn`` stamps
    metadata without blocking unless ``on_detect: block``.
    """

    def __init__(
        self,
        *,
        learn_min_calls: int = 12,
        freeze_after_calls: int = 18,
        drift_window: int = 10,
        tool_overlap_threshold: float = 0.25,
        rate_spike_multiplier: float = 10.0,
        backend: StateBackend | None = None,
        backend_namespace: str = "behavior_fingerprint",
        ttl_seconds: float = 86400.0,
    ) -> None:
        if learn_min_calls < 2:
            raise ValueError("learn_min_calls must be >= 2")
        if not 0.0 < tool_overlap_threshold <= 1.0:
            raise ValueError("tool_overlap_threshold must be in (0, 1]")
        if rate_spike_multiplier < 2.0:
            raise ValueError("rate_spike_multiplier must be >= 2")
        self.learn_min_calls = learn_min_calls
        self.freeze_after_calls = max(freeze_after_calls, learn_min_calls)
        self.drift_window = max(drift_window, 3)
        self.tool_overlap_threshold = tool_overlap_threshold
        self.rate_spike_multiplier = rate_spike_multiplier
        self._backend = backend or MemoryStateBackend()
        self._namespace = backend_namespace
        self._ttl_seconds = ttl_seconds
        self._local_rate_window: dict[str, deque[float]] = {}

    def _key(self, scope: str, suffix: str) -> str:
        digest = hashlib.sha256(scope.encode()).hexdigest()[:20]
        return f"{self._namespace}:{digest}:{suffix}"

    def _load_state(self, scope: str) -> dict[str, Any]:
        raw = self._backend.get_json(self._key(scope, "state"))
        return raw if isinstance(raw, dict) else {}

    def _save_state(self, scope: str, state: dict[str, Any]) -> None:
        self._backend.set_json(self._key(scope, "state"), state, ttl_seconds=self._ttl_seconds)

    def check_and_record(self, scope: str, tool: str) -> BehaviorCheckResult:
        """Record a tool call and return whether behavior diverges from baseline."""
        state = self._load_state(scope)
        sequence: list[str] = list(state.get("sequence") or [])
        baseline_tools: list[str] = list(state.get("baseline_tools") or [])
        total_calls = int(state.get("total_calls") or 0) + 1
        sequence.append(tool)
        sequence = sequence[-50:]

        rate_result = self._check_rate_spike(scope, tool)
        drift_result = self._check_tool_drift(
            scope,
            tool,
            sequence=sequence,
            baseline_tools=baseline_tools,
            total_calls=total_calls,
        )

        if total_calls >= self.freeze_after_calls and not baseline_tools:
            baseline_tools = sorted(set(sequence))

        self._save_state(
            scope,
            {
                "sequence": sequence,
                "baseline_tools": baseline_tools,
                "total_calls": total_calls,
            },
        )

        if rate_result.anomalous:
            return rate_result
        if drift_result.anomalous:
            return drift_result
        return BehaviorCheckResult(anomalous=False, kind=None, overlap=drift_result.overlap)

    def _check_rate_spike(self, scope: str, tool: str) -> BehaviorCheckResult:
        now = time.time()
        rate_key = f"{scope}:{tool}"
        window = self._local_rate_window.setdefault(rate_key, deque())
        window.append(now)
        cutoff = now - 60.0
        while window and window[0] < cutoff:
            window.popleft()
        current_rate = float(len(window))

        rate_state = self._backend.get_json(self._key(scope, f"rate:{tool}"))
        baseline_rate = float((rate_state or {}).get("baseline") or 0.0)
        if baseline_rate <= 0:
            self._backend.set_json(
                self._key(scope, f"rate:{tool}"),
                {"baseline": max(1.0, current_rate)},
                ttl_seconds=self._ttl_seconds,
            )
            return BehaviorCheckResult(anomalous=False, kind=None)

        new_baseline = baseline_rate * 0.95 + current_rate * 0.05
        self._backend.set_json(
            self._key(scope, f"rate:{tool}"),
            {"baseline": new_baseline},
            ttl_seconds=self._ttl_seconds,
        )
        if baseline_rate >= 2.0 and current_rate >= baseline_rate * self.rate_spike_multiplier:
            msg = (
                f"tool {tool} call rate {current_rate:.1f}/min vs baseline {baseline_rate:.1f}/min"
            )
            logger.warning("behavior_fingerprint rate_spike scope=%s %s", scope[:48], msg)
            return BehaviorCheckResult(
                anomalous=True,
                kind="rate_spike",
                current_rate=current_rate,
                baseline_rate=baseline_rate,
                message=msg,
            )
        return BehaviorCheckResult(anomalous=False, kind=None)

    def _check_tool_drift(
        self,
        scope: str,
        tool: str,
        *,
        sequence: list[str],
        baseline_tools: list[str],
        total_calls: int,
    ) -> BehaviorCheckResult:
        if total_calls < self.learn_min_calls or not baseline_tools:
            return BehaviorCheckResult(anomalous=False, kind=None)
        if total_calls < self.freeze_after_calls + self.drift_window:
            return BehaviorCheckResult(anomalous=False, kind=None)

        window = sequence[-self.drift_window :]
        uniq = set(window)
        baseline_set = set(baseline_tools)
        overlap = len(uniq & baseline_set) / max(1, len(uniq))
        if overlap >= self.tool_overlap_threshold:
            return BehaviorCheckResult(anomalous=False, kind=None, overlap=overlap)

        msg = (
            f"recent tools diverge from baseline (overlap={overlap:.2f}, tool={tool})"
        )
        logger.warning("behavior_fingerprint tool_drift scope=%s %s", scope[:48], msg)
        return BehaviorCheckResult(
            anomalous=True,
            kind="tool_drift",
            overlap=overlap,
            message=msg,
        )
