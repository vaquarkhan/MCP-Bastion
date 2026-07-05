"""Tests for Agent IAM pillar."""

import pytest

from mcp_bastion.errors import AgentAccessDeniedError, AuthenticationError
from mcp_bastion.pillars.agent_iam import AgentIAM, AgentPolicy, parse_agent_policies


def test_parse_agent_policies_from_env(monkeypatch):
    monkeypatch.setenv("BASTION_TOKEN_SUPPORT", "support-secret-token")
    policies = parse_agent_policies(
        [
            {
                "id": "customer_support_bot",
                "token_env": "BASTION_TOKEN_SUPPORT",
                "allowed_tools": ["search_docs", "get_ticket_status"],
                "blocked_tools": ["execute_sql", "delete_user"],
                "rate_limit": {"max_iterations": 5},
            }
        ]
    )
    assert len(policies) == 1
    assert policies[0].agent_id == "customer_support_bot"
    assert policies[0].rate_limiter is not None
    assert policies[0].rate_limiter.max_iterations == 5


def test_agent_iam_authenticate_and_allow():
    iam = AgentIAM(
        [
            AgentPolicy(
                agent_id="support",
                token="tok-support",
                allowed_tools=frozenset({"search_docs"}),
                blocked_tools=frozenset({"delete_user"}),
            )
        ]
    )
    policy = iam.authenticate("tok-support")
    iam.check_tool(policy, "search_docs")
    with pytest.raises(AgentAccessDeniedError):
        iam.check_tool(policy, "delete_user")
    with pytest.raises(AgentAccessDeniedError):
        iam.check_tool(policy, "execute_sql")


def test_agent_iam_unknown_token():
    iam = AgentIAM(
        [
            AgentPolicy(
                agent_id="support",
                token="tok-support",
                allowed_tools=None,
                blocked_tools=frozenset(),
            )
        ],
        require_token=True,
    )
    with pytest.raises(AuthenticationError):
        iam.authenticate("wrong-token")
