"""
Pluggable shared state for rate limits, replay nonces, cost budgets, and session scope.

Default: in-process memory (single replica). Production: Redis so horizontally scaled
workers share counters and replay protection.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict, defaultdict
from typing import Any

logger = logging.getLogger(__name__)


class StateBackend(ABC):
    """Minimal KV + set primitives used by Bastion pillars."""

    @abstractmethod
    def get(self, key: str) -> str | None:
        """Return stored string value or None."""

    @abstractmethod
    def set(self, key: str, value: str, *, ttl_seconds: float | None = None) -> None:
        """Store string value with optional TTL."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Remove key if present."""

    @abstractmethod
    def set_nx(self, key: str, value: str, *, ttl_seconds: float | None = None) -> bool:
        """Set only if absent. Returns True when stored, False when key already exists."""

    @abstractmethod
    def set_add(self, key: str, member: str, *, max_size: int | None = None) -> bool:
        """
        Add member to a set.

        Returns True when the add is allowed (member added or already present).
        Returns False when max_size would be exceeded by a new member.
        """

    @abstractmethod
    def set_contains(self, key: str, member: str) -> bool:
        """True if member is in the set."""

    def get_json(self, key: str) -> dict[str, Any] | None:
        raw = self.get(key)
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def set_json(self, key: str, value: dict[str, Any], *, ttl_seconds: float | None = None) -> None:
        self.set(key, json.dumps(value, separators=(",", ":")), ttl_seconds=ttl_seconds)


class MemoryStateBackend(StateBackend):
    """Process-local backend (default). Not shared across workers or pods."""

    def __init__(self) -> None:
        self._values: dict[str, tuple[str, float | None]] = {}
        self._sets: dict[str, set[str]] = defaultdict(set)
        self._lock = threading.Lock()

    def _expired(self, expires_at: float | None) -> bool:
        return expires_at is not None and time.monotonic() > expires_at

    def get(self, key: str) -> str | None:
        with self._lock:
            entry = self._values.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if self._expired(expires_at):
                del self._values[key]
                return None
            return value

    def set(self, key: str, value: str, *, ttl_seconds: float | None = None) -> None:
        expires_at = time.monotonic() + ttl_seconds if ttl_seconds else None
        with self._lock:
            self._values[key] = (value, expires_at)

    def delete(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)
            self._sets.pop(key, None)

    def set_nx(self, key: str, value: str, *, ttl_seconds: float | None = None) -> bool:
        with self._lock:
            entry = self._values.get(key)
            if entry is not None and not self._expired(entry[1]):
                return False
            expires_at = time.monotonic() + ttl_seconds if ttl_seconds else None
            self._values[key] = (value, expires_at)
            return True

    def set_add(self, key: str, member: str, *, max_size: int | None = None) -> bool:
        with self._lock:
            members = self._sets[key]
            if member in members:
                return True
            if max_size is not None and len(members) >= max_size:
                return False
            members.add(member)
            return True

    def set_contains(self, key: str, member: str) -> bool:
        with self._lock:
            return member in self._sets.get(key, set())


class RedisStateBackend(StateBackend):
    """Redis-backed shared state for multi-replica deployments."""

    def __init__(self, url: str, *, key_prefix: str = "mcp-bastion") -> None:
        try:
            import redis
        except ImportError as e:
            raise ImportError(
                "Redis state backend requires: pip install mcp-bastion-python[redis]"
            ) from e
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = key_prefix.rstrip(":")

    def _k(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    def get(self, key: str) -> str | None:
        return self._client.get(self._k(key))

    def set(self, key: str, value: str, *, ttl_seconds: float | None = None) -> None:
        full = self._k(key)
        if ttl_seconds:
            self._client.setex(full, int(max(1, ttl_seconds)), value)
        else:
            self._client.set(full, value)

    def delete(self, key: str) -> None:
        self._client.delete(self._k(key))

    def set_nx(self, key: str, value: str, *, ttl_seconds: float | None = None) -> bool:
        full = self._k(key)
        if ttl_seconds:
            return bool(self._client.set(full, value, nx=True, ex=int(max(1, ttl_seconds))))
        return bool(self._client.set(full, value, nx=True))

    def set_add(self, key: str, member: str, *, max_size: int | None = None) -> bool:
        full = self._k(key)
        if max_size is not None:
            pipe = self._client.pipeline()
            pipe.sismember(full, member)
            pipe.scard(full)
            is_member, size = pipe.execute()
            if is_member:
                return True
            if int(size) >= max_size:
                return False
        self._client.sadd(full, member)
        return True

    def set_contains(self, key: str, member: str) -> bool:
        return bool(self._client.sismember(self._k(key), member))

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            return False


def build_state_backend(
    *,
    backend: str = "memory",
    redis_url: str = "redis://127.0.0.1:6379/0",
    key_prefix: str = "mcp-bastion",
) -> StateBackend:
    """Factory for BastionConfig / bastion.yaml `state_backend` section."""
    kind = (backend or "memory").strip().lower()
    if kind in ("memory", "local", ""):
        return MemoryStateBackend()
    if kind == "redis":
        return RedisStateBackend(redis_url, key_prefix=key_prefix)
    raise ValueError(f"Unknown state_backend type: {backend!r} (expected memory or redis)")
