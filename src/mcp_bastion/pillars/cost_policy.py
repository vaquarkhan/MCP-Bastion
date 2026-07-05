"""Cost-aware policy: allow/deny/route using live spend, not only hard caps."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from mcp_bastion.errors import CostPolicyApprovalRequiredError, ExpensiveChainError
from mcp_bastion.pillars.cost_tracker import CostTracker

logger = logging.getLogger(__name__)

ACTION_DEGRADE_MODEL = "degrade_model"
ACTION_FORCE_DISCOVERY_FILTER = "force_discovery_filter"
ACTION_REQUIRE_APPROVAL = "require_approval"


@dataclass
class CostPolicyRule:
    session_spend_pct_gte: float
    action: str
    target_model: str | None = None


@dataclass
class ExpensiveChainConfig:
    enabled: bool = False
    max_projected_cost_usd: float = 1.0
    tool_costs: dict[str, float] = field(default_factory=dict)
    default_tool_cost_usd: float = 0.05


class CostPolicyEngine:
    """Evaluate spend thresholds and expensive tool sequences."""

    def __init__(
        self,
        rules: list[CostPolicyRule] | None = None,
        *,
        expensive_chain: ExpensiveChainConfig | None = None,
        approval_metadata_key: str = "bastion_cost_approval",
    ) -> None:
        self.rules = sorted(rules or [], key=lambda r: r.session_spend_pct_gte)
        self.expensive_chain = expensive_chain or ExpensiveChainConfig()
        self.approval_metadata_key = approval_metadata_key
        self._session_tools: dict[str, list[str]] = {}

    @classmethod
    def from_config(cls, data: dict[str, Any] | None) -> CostPolicyEngine:
        if not data:
            return cls()
        rules: list[CostPolicyRule] = []
        for raw in data.get("rules") or []:
            if not isinstance(raw, dict):
                continue
            when = raw.get("when") or {}
            pct = when.get("session_spend_pct_gte", raw.get("session_spend_pct_gte"))
            if pct is None:
                continue
            rules.append(
                CostPolicyRule(
                    session_spend_pct_gte=float(pct),
                    action=str(raw.get("action", "")).strip(),
                    target_model=raw.get("target_model") or raw.get("target"),
                )
            )
        ec_raw = data.get("expensive_chain") or {}
        ec = ExpensiveChainConfig(
            enabled=bool(ec_raw.get("enabled", False)),
            max_projected_cost_usd=float(ec_raw.get("max_projected_cost_usd", 1.0)),
            tool_costs={str(k): float(v) for k, v in (ec_raw.get("tool_costs") or {}).items()},
            default_tool_cost_usd=float(ec_raw.get("default_tool_cost_usd", 0.05)),
        )
        return cls(
            rules=rules,
            expensive_chain=ec,
            approval_metadata_key=str(data.get("approval_metadata_key", "bastion_cost_approval")),
        )

    def session_spend_pct(
        self,
        cost_tracker: CostTracker,
        *,
        session_id: str | None,
        request_id: str | None,
        principal_id: str | None,
    ) -> tuple[float, float]:
        """Return (current_usd, pct_of_session_cap)."""
        key = cost_tracker._session_budget_key(session_id, request_id, principal_id)
        with cost_tracker._lock:
            state = cost_tracker._load_session(key)
            current = round(state.cost, 4)
        cap = cost_tracker.max_cost_per_session
        if cap <= 0:
            return current, 0.0
        return current, round(100.0 * current / cap, 2)

    def apply_rules(
        self,
        cost_tracker: CostTracker,
        metadata: dict[str, Any],
        *,
        session_id: str | None,
        request_id: str | None,
        principal_id: str | None,
    ) -> list[str]:
        """Apply matching rules to metadata; return action names fired."""
        if not self.rules:
            return []
        _current, pct = self.session_spend_pct(
            cost_tracker, session_id=session_id, request_id=request_id, principal_id=principal_id
        )
        fired: list[str] = []
        for rule in self.rules:
            if pct < rule.session_spend_pct_gte:
                continue
            if rule.action == ACTION_DEGRADE_MODEL and rule.target_model:
                metadata["_cost_policy_degrade_model"] = rule.target_model
                fired.append(f"degrade_model:{rule.target_model}")
            elif rule.action == ACTION_FORCE_DISCOVERY_FILTER:
                metadata["_cost_policy_force_discovery_filter"] = True
                fired.append("force_discovery_filter")
            elif rule.action == ACTION_REQUIRE_APPROVAL:
                if not metadata.get(self.approval_metadata_key):
                    raise CostPolicyApprovalRequiredError(
                        f"Request blocked: session spend at {pct:.1f}% of budget — "
                        f"approval required ({self.approval_metadata_key})"
                    )
                fired.append("require_approval:granted")
        if fired:
            metadata.setdefault("cost_policy_actions", []).extend(fired)
            logger.info("cost_policy fired session=%s pct=%.1f actions=%s", session_id, pct, fired)
        return fired

    def check_expensive_chain(self, session_id: str, tool_name: str, projected_call_cost: float) -> None:
        if not self.expensive_chain.enabled:
            return
        session = session_id or "default"
        history = self._session_tools.setdefault(session, [])
        projected = sum(
            self.expensive_chain.tool_costs.get(t, self.expensive_chain.default_tool_cost_usd) for t in history
        )
        projected += projected_call_cost
        if projected > self.expensive_chain.max_projected_cost_usd:
            raise ExpensiveChainError(
                f"Request blocked: projected tool-chain cost ${projected:.2f} exceeds "
                f"limit ${self.expensive_chain.max_projected_cost_usd:.2f}"
            )

    def record_tool(self, session_id: str, tool_name: str) -> None:
        session = session_id or "default"
        self._session_tools.setdefault(session, []).append(tool_name)

    def tool_projected_cost(self, tool_name: str, metadata: dict[str, Any]) -> float:
        if metadata.get("cost") is not None:
            try:
                return max(0.0, float(metadata["cost"]))
            except (TypeError, ValueError):
                pass
        return self.expensive_chain.tool_costs.get(tool_name, self.expensive_chain.default_tool_cost_usd)
