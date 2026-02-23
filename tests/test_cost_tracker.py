"""Tests for cost tracker pillar."""

import pytest

from mcp_bastion.errors import CostBudgetExceededError
from mcp_bastion.pillars.cost_tracker import CostTracker


def test_cost_tracker_check_passes_under_budget():
    """Check passes when under budget."""
    ct = CostTracker(max_cost_per_session=1.0)
    ct.check(session_id="s1")


def test_cost_tracker_record_and_check():
    """Record adds cost; check fails when over budget."""
    ct = CostTracker(max_cost_per_session=0.50)
    ct.record(0.30, session_id="s1")
    ct.check(session_id="s1")
    ct.record(0.25, session_id="s1")
    with pytest.raises(CostBudgetExceededError, match="exceeds limit"):
        ct.check(session_id="s1")


def test_cost_tracker_reset_session():
    """Reset clears session cost."""
    ct = CostTracker(max_cost_per_session=0.50)
    ct.record(0.40, session_id="s1")
    ct.reset_session(session_id="s1")
    ct.check(session_id="s1")


def test_cost_tracker_daily_budget_exceeded():
    """Cost tracker blocks when daily budget exceeded."""
    ct = CostTracker(max_cost_per_session=10.0, max_cost_per_day=0.50)
    ct.record(0.30, session_id="s1")
    ct.record(0.25, session_id="s1")
    with pytest.raises(Exception, match="Daily cost"):
        ct.check(session_id="s1")


def test_cost_tracker_uses_request_id_fallback():
    """Uses request_id when session_id missing."""
    ct = CostTracker(max_cost_per_session=0.50)
    ct.record(0.30, request_id="r1")
    ct.check(request_id="r1")
