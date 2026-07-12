"""FinOps cost avoidance metrics from blocked requests."""

from __future__ import annotations

from mcp_bastion.pillars.metrics import MetricsStore


def test_record_blocked_tracks_token_and_usd_avoidance():
    store = MetricsStore()
    store.reset()
    store.record_blocked(
        "injection: ignore previous instructions",
        "query_llm",
        forensic_trace=[{"pillar": "prompt_guard", "status": "blocked", "detail": "injection"}],
    )
    store.record_tokens_used(10_000)
    store.record_tokens_saved(2_000, source="output_budget")
    store.record_cost(1.25, "alice")

    m = store.get_metrics()
    cr = m["cost_reduction"]
    assert cr["tokens_avoided_by_blocks"] > 0
    assert cr["estimated_usd_avoided_by_blocks"] > 0
    assert cr["tokens_would_have_used"] == (
        cr["tokens_used"] + cr["tokens_saved"] + cr["tokens_avoided_by_blocks"]
    )
    assert cr["cost_if_unblocked_usd"] >= cr["cost_actual_usd"]
    assert "injection" in (cr.get("by_block_kind") or {}) or any(
        "injection" in k for k in (cr.get("by_block_kind") or {})
    )
    assert cr["blocked_issues"]
    assert cr["blocked_issues"][0].get("estimated_tokens_avoided")
