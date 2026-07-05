"""Tests for output budget pillar."""

from mcp_bastion.pillars.output_budget import OutputBudget


def test_output_budget_skips_small_text():
    ob = OutputBudget(max_output_tokens=100, min_tokens=500)
    content = [{"type": "text", "text": "small"}]
    out, summary = ob.process_content_items(content, session_id="s1")
    assert out == content
    assert summary.applied is False


def test_output_budget_truncates_large_text():
    ob = OutputBudget(max_output_tokens=50, min_tokens=10, enable_offload=False)
    big = "word " * 500
    content = [{"type": "text", "text": big}]
    out, summary = ob.process_content_items(content)
    assert summary.applied is True
    assert summary.tokens_saved > 0
    assert "truncated" in out[0]["text"].lower() or "omitted" in out[0]["text"].lower()


def test_output_budget_offload_returns_key():
    ob = OutputBudget(max_output_tokens=50, min_tokens=10, enable_offload=True)
    big = "x" * 5000
    content = [{"type": "text", "text": big}]
    out, summary = ob.process_content_items(content, session_id="sess", tool_name="read")
    assert summary.offloaded is True
    assert summary.offload_key
    assert summary.offload_key in out[0]["text"]
    restored = ob.offload_store.get(summary.offload_key, session_id="sess")
    assert restored == big
