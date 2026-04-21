"""
Semantic caching for MCP-Bastion.

Cache similar queries to reduce redundant calls.
Uses simple similarity (normalized string overlap) for zero-dependency MVP.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from collections import OrderedDict
from typing import Any

logger = logging.getLogger(__name__)


def _normalize(text: str) -> str:
    """Normalize text for comparison."""
    t = re.sub(r"\s+", " ", text.lower().strip())
    return " ".join(t.split())


def _jaccard_similarity(a: str, b: str) -> float:
    """Jaccard similarity of word sets. 0-1."""
    if not a or not b:
        return 0.0
    sa, sb = set(a.split()), set(b.split())
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


class SemanticCache:
    """
    Cache with similarity lookup.

    Returns cached result if query is similar enough to a cached key.
    Zero embedding dependency: uses word-overlap similarity.
    Thread-safe; entries are scoped per tool name.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.95,
        max_entries: int = 1000,
        ttl_seconds: float = 300.0,
    ) -> None:
        if not 0.0 <= similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be between 0.0 and 1.0")
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self.similarity_threshold = similarity_threshold
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[float, str, str, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def _make_key(self, tool: str, query: str) -> str:
        return hashlib.sha256(f"{tool}:{query}".encode()).hexdigest()

    def get(self, tool: str, query: str) -> Any | None:
        """
        Return cached result if similar query exists.
        """
        norm = _normalize(query)
        if not norm:
            return None

        now = time.monotonic()
        to_remove: list[str] = []
        best_match = None
        best_score = 0.0
        best_key = None

        with self._lock:
            for key, (cached_at, cached_tool, cached_norm, value) in list(
                self._cache.items()
            ):
                if now - cached_at > self.ttl_seconds:
                    to_remove.append(key)
                    continue
                if cached_tool != tool:
                    continue
                score = _jaccard_similarity(norm, cached_norm)
                if score >= self.similarity_threshold and score > best_score:
                    best_score = score
                    best_match = value
                    best_key = key

            for k in to_remove:
                del self._cache[k]

            if best_match is not None and best_key is not None:
                self._cache.move_to_end(best_key)
                logger.debug("semantic_cache hit tool=%s similarity=%.2f", tool, best_score)
                return best_match
        return None

    def set(self, tool: str, query: str, value: Any) -> None:
        """Cache result for query."""
        norm = _normalize(query)
        if not norm:
            return

        key = self._make_key(tool, norm)
        with self._lock:
            while len(self._cache) >= self.max_entries:
                self._cache.popitem(last=False)
            self._cache[key] = (time.monotonic(), tool, norm, value)
