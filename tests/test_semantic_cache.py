"""Tests for semantic cache pillar."""

from mcp_bastion.pillars.semantic_cache import SemanticCache


def test_semantic_cache_empty_returns_none():
    """Empty cache returns None."""
    sc = SemanticCache()
    assert sc.get("tool", "hello world") is None


def test_semantic_cache_exact_match():
    """Exact query returns cached value."""
    sc = SemanticCache(similarity_threshold=0.95)
    sc.set("search", "hello world", {"result": 42})
    assert sc.get("search", "hello world") == {"result": 42}


def test_semantic_cache_similar_match():
    """Similar query returns cached value."""
    sc = SemanticCache(similarity_threshold=0.7)
    sc.set("search", "hello world foo bar", {"result": 1})
    assert sc.get("search", "hello world foo bar") == {"result": 1}
    result = sc.get("search", "hello world foo")
    assert result == {"result": 1}


def test_semantic_cache_different_tool_isolated():
    """Different tools have separate cache."""
    sc = SemanticCache()
    sc.set("tool_a", "query", {"a": 1})
    sc.set("tool_b", "query", {"b": 2})
    assert sc.get("tool_a", "query") == {"a": 1}
    assert sc.get("tool_b", "query") == {"b": 2}


def test_semantic_cache_same_query_different_tool_order_independent():
    """Hits must not leak across tools regardless of LRU order (regression)."""
    sc = SemanticCache()
    sc.set("tool_a", "query", {"a": 1})
    sc.set("tool_b", "query", {"b": 2})
    assert sc.get("tool_b", "query") == {"b": 2}
    assert sc.get("tool_a", "query") == {"a": 1}


def test_semantic_cache_jaccard_empty_strings():
    """Jaccard returns 0 for empty strings."""
    from mcp_bastion.pillars.semantic_cache import _jaccard_similarity

    assert _jaccard_similarity("", "hello") == 0.0
    assert _jaccard_similarity("hello", "") == 0.0


def test_semantic_cache_jaccard_empty_sets():
    """Jaccard returns 0 when word sets empty."""
    from mcp_bastion.pillars.semantic_cache import _jaccard_similarity

    assert _jaccard_similarity("   ", "   ") == 0.0


def test_semantic_cache_ttl_expiry():
    """Expired entries are not returned."""
    import time

    sc = SemanticCache(similarity_threshold=0.5, ttl_seconds=0.1)
    sc.set("search", "hello world", {"r": 1})
    result = sc.get("search", "hello world")
    assert result == {"r": 1}
    time.sleep(0.15)
    assert sc.get("search", "hello world") is None


def test_semantic_cache_max_entries_eviction():
    """Cache evicts when max entries reached."""
    sc = SemanticCache(max_entries=2, similarity_threshold=0.99)
    sc.set("t", "q1", {"v": 1})
    sc.set("t", "q2", {"v": 2})
    sc.set("t", "q3", {"v": 3})
    assert sc.get("t", "q1") is None
    assert sc.get("t", "q2") == {"v": 2}
    assert sc.get("t", "q3") == {"v": 3}


def test_semantic_cache_empty_query_not_cached():
    """Empty query is not cached."""
    sc = SemanticCache()
    sc.set("tool", "", {"x": 1})
    assert sc.get("tool", "") is None
