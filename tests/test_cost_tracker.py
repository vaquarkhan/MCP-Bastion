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
    ct.record(0.30, session_id="s1", principal_id="anonymous:default", tenant_id="default")
    ct.record(0.25, session_id="s2", principal_id="anonymous:default", tenant_id="default")
    with pytest.raises(Exception, match="Daily cost"):
        ct.check(session_id="s3", principal_id="anonymous:default", tenant_id="default")


def test_cost_tracker_session_rotation_cannot_bypass_daily_cap():
    """Rotating session_id must not reset tenant-global daily spend."""
    ct = CostTracker(max_cost_per_session=10.0, max_cost_per_day=1.0)
    principal = "anonymous:default"
    tenant = "default"
    for i in range(10):
        ct.record(0.10, session_id=f"rotated-{i}", principal_id=principal, tenant_id=tenant)
    with pytest.raises(CostBudgetExceededError, match="Daily cost"):
        ct.check(session_id="rotated-new", principal_id=principal, tenant_id=tenant)


def test_cost_tracker_session_rotation_cannot_bypass_session_cap():
    ct = CostTracker(max_cost_per_session=0.50, max_cost_per_day=10.0)
    principal = "anonymous:default"
    for i in range(3):
        ct.record(0.20, session_id=f"s{i}", principal_id=principal, tenant_id="default")
    with pytest.raises(CostBudgetExceededError, match="Session cost"):
        ct.check(session_id="s-new", principal_id=principal, tenant_id="default")


def test_cost_tracker_uses_request_id_fallback():
    """Uses request_id when session_id missing."""
    ct = CostTracker(max_cost_per_session=0.50)
    ct.record(0.30, request_id="r1")
    ct.check(request_id="r1")


def test_cost_tracker_rejects_negative_cost():
    """Negative cost must be rejected to prevent budget bypass."""
    ct = CostTracker(max_cost_per_session=1.0)
    with pytest.raises(ValueError, match="cost"):
        ct.record(-0.5, session_id="s1")
