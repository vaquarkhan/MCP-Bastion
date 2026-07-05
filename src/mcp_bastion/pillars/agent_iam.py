"""
Agent Identity & Access Management (IAM) for MCP-Bastion.

Maps API tokens to agent identities and enforces per-agent tool allow/block lists
and optional rate limits — solves the Confused Deputy problem for multi-agent MCP servers.
"""

from __future__ import annotations

import fnmatch
import hmac
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

from mcp_bastion.errors import AgentAccessDeniedError, AuthenticationError
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.state_backend import StateBackend

logger = logging.getLogger(__name__)

_ENV_PATTERN = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


@dataclass(frozen=True)
class AgentPolicy:
    """Resolved policy for one agent identity."""

    agent_id: str
    token: str
    allowed_tools: frozenset[str] | None = None
    blocked_tools: frozenset[str] = field(default_factory=frozenset)
    allowed_resources: frozenset[str] | None = None
    blocked_resources: frozenset[str] = field(default_factory=frozenset)
    blocked_methods: frozenset[str] = field(default_factory=frozenset)
    rate_limiter: TokenBucketRateLimiter | None = None


def _resolve_token(raw: str) -> str:
    """Resolve token from plain text or ${ENV_VAR} placeholder."""
    if not raw:
        return ""
    m = _ENV_PATTERN.match(raw.strip())
    if m:
        return os.environ.get(m.group(1), "")
    if raw.startswith("env:"):
        return os.environ.get(raw[4:], "")
    return raw


def _parse_tool_set(values: Any) -> frozenset[str]:
    if not values:
        return frozenset()
    if isinstance(values, str):
        return frozenset({values})
    return frozenset(str(v).strip() for v in values if str(v).strip())


def parse_agent_policies(
    raw_agents: list[dict[str, Any]],
    *,
    state_backend: StateBackend | None = None,
) -> list[AgentPolicy]:
    """Build AgentPolicy list from bastion.yaml `agents` entries."""
    policies: list[AgentPolicy] = []
    for entry in raw_agents or []:
        if not isinstance(entry, dict):
            continue
        agent_id = str(entry.get("id") or entry.get("agent_id") or "").strip()
        if not agent_id:
            continue
        token = ""
        if entry.get("token_env"):
            token = os.environ.get(str(entry["token_env"]), "")
        elif entry.get("token"):
            token = _resolve_token(str(entry["token"]))
        if not token:
            logger.warning("agent_iam: skipping agent %s — token/token_env not set", agent_id)
            continue

        allowed_raw = entry.get("allowed_tools")
        allowed: frozenset[str] | None
        if allowed_raw is None:
            allowed = None
        else:
            allowed = _parse_tool_set(allowed_raw)

        blocked = _parse_tool_set(entry.get("blocked_tools"))
        allowed_res_raw = entry.get("allowed_resources")
        allowed_res: frozenset[str] | None
        if allowed_res_raw is None:
            allowed_res = None
        else:
            allowed_res = _parse_tool_set(allowed_res_raw)
        blocked_res = _parse_tool_set(entry.get("blocked_resources"))
        blocked_methods = _parse_tool_set(entry.get("blocked_methods"))

        rate_limiter: TokenBucketRateLimiter | None = None
        rl = entry.get("rate_limit") or {}
        if isinstance(rl, dict) and rl:
            max_iter = int(rl.get("max_iterations", 15))
            timeout = float(rl.get("timeout_seconds", 60))
            budget = int(rl.get("token_budget", 50_000))
            per_tool = int(rl.get("max_per_tool", 0))
            rate_limiter = TokenBucketRateLimiter(
                max_iterations=max_iter,
                timeout_seconds=timeout,
                token_budget=budget,
                max_per_tool=per_tool,
                backend=state_backend,
                backend_namespace=f"ratelimit:agent:{agent_id}",
            )

        policies.append(
            AgentPolicy(
                agent_id=agent_id,
                token=token,
                allowed_tools=allowed,
                blocked_tools=blocked,
                allowed_resources=allowed_res,
                blocked_resources=blocked_res,
                blocked_methods=blocked_methods,
                rate_limiter=rate_limiter,
            )
        )
    return policies


class AgentIAM:
    """
    Identity-aware routing: authenticate bearer tokens and enforce tool policy per agent.
    """

    def __init__(
        self,
        policies: list[AgentPolicy],
        *,
        token_metadata_key: str = "bastion_agent_token",
        require_token: bool = True,
        isolate_sessions: bool = False,
    ) -> None:
        self.token_metadata_key = token_metadata_key
        self.require_token = require_token
        self.isolate_sessions = isolate_sessions
        self._policies = policies
        self._by_id = {p.agent_id: p for p in policies}

    @property
    def agent_ids(self) -> list[str]:
        return list(self._by_id.keys())

    def authenticate(self, token: str | None) -> AgentPolicy | None:
        """Resolve token to agent policy. Raises on missing/invalid when require_token."""
        if not token or not str(token).strip():
            if self.require_token:
                raise AuthenticationError("Request blocked: agent identity token required")
            return None
        raw = str(token)
        for policy in self._policies:
            a, b = raw.encode("utf-8"), policy.token.encode("utf-8")
            if len(a) == len(b) and hmac.compare_digest(a, b):
                return policy
        raise AuthenticationError("Request blocked: unknown agent identity token")

    def check_tool(self, policy: AgentPolicy, tool_name: str) -> None:
        """Enforce allowed/blocked tool lists for the authenticated agent."""
        tool = str(tool_name or "").strip()
        if not tool:
            return
        if tool in policy.blocked_tools:
            logger.warning("agent_iam blocked agent=%s tool=%s (blocked list)", policy.agent_id, tool)
            raise AgentAccessDeniedError(
                f"Agent {policy.agent_id!r} is not permitted to call tool {tool!r} (blocked by policy)"
            )
        if policy.allowed_tools is not None and "*" not in policy.allowed_tools:
            if tool not in policy.allowed_tools:
                logger.warning("agent_iam blocked agent=%s tool=%s (not allowed)", policy.agent_id, tool)
                raise AgentAccessDeniedError(
                    f"Agent {policy.agent_id!r} is not permitted to call tool {tool!r} (not on allow list)"
                )

    def check_method(self, policy: AgentPolicy, method: str) -> None:
        """Block JSON-RPC methods for this agent (e.g. resources/write)."""
        m = str(method or "").strip()
        if not m or not policy.blocked_methods:
            return
        if m in policy.blocked_methods:
            raise AgentAccessDeniedError(
                f"Agent {policy.agent_id!r} is not permitted to invoke method {m!r}"
            )

    def check_resource(self, policy: AgentPolicy, uri: str) -> None:
        """Enforce resource URI allow/block patterns (fnmatch)."""
        u = str(uri or "").strip()
        if not u:
            return
        for pattern in policy.blocked_resources:
            if fnmatch.fnmatch(u, pattern) or fnmatch.fnmatch(u, pattern.replace("://", "://*/")):
                raise AgentAccessDeniedError(
                    f"Agent {policy.agent_id!r} is not permitted to access resource {u!r} (blocked)"
                )
        if policy.allowed_resources is not None and "*" not in policy.allowed_resources:
            if not any(fnmatch.fnmatch(u, p) for p in policy.allowed_resources):
                raise AgentAccessDeniedError(
                    f"Agent {policy.agent_id!r} is not permitted to access resource {u!r} (not allowed)"
                )

    def isolated_session_id(self, policy: AgentPolicy | None, session_id: str | None) -> str | None:
        """Namespace session keys per agent to prevent multi-agent state poisoning."""
        if not self.isolate_sessions or policy is None:
            return session_id
        base = (session_id or "default").strip()
        return f"agent:{policy.agent_id}::{base}"

    def rate_limiter_for(self, policy: AgentPolicy | None) -> TokenBucketRateLimiter | None:
        if policy is None:
            return None
        return policy.rate_limiter

    def apply_to_context(self, context: Any, policy: AgentPolicy | None) -> None:
        """Stamp agent identity on middleware context for audit / RBAC."""
        if policy is None or not hasattr(context, "metadata"):
            return
        context.metadata["agent_id"] = policy.agent_id
        context.metadata["role"] = policy.agent_id
        context.metadata["agent"] = policy.agent_id
