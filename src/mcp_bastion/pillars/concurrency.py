"""O(1) in-process concurrency admission for callers and tenants."""

from __future__ import annotations

import threading
from collections import defaultdict


class ConcurrencyLimiter:
    """Thread-safe counters; callers must release successful acquisitions."""

    def __init__(
        self,
        *,
        max_inflight_per_caller: int = 8,
        max_inflight_per_tenant: int = 32,
        admission_queue_depth: int = 0,
    ) -> None:
        self.max_inflight_per_caller = max(0, int(max_inflight_per_caller))
        self.max_inflight_per_tenant = max(0, int(max_inflight_per_tenant))
        self.admission_queue_depth = max(0, int(admission_queue_depth))
        self._callers: dict[str, int] = defaultdict(int)
        self._tenants: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    @staticmethod
    def _keys(caller_id: str | None, tenant_id: str | None) -> tuple[str, str]:
        return (str(caller_id or "").strip() or "anonymous", str(tenant_id or "").strip() or "default")

    def try_acquire(self, caller_id: str | None, tenant_id: str | None) -> str:
        """Return ``admit``, ``concurrency_limit``, or ``load_shed`` without waiting."""
        caller, tenant = self._keys(caller_id, tenant_id)
        with self._lock:
            caller_full = (
                self.max_inflight_per_caller > 0
                and self._callers[caller] >= self.max_inflight_per_caller
            )
            tenant_full = (
                self.max_inflight_per_tenant > 0
                and self._tenants[tenant] >= self.max_inflight_per_tenant
            )
            if caller_full or tenant_full:
                return "load_shed" if self.admission_queue_depth > 0 else "concurrency_limit"
            self._callers[caller] += 1
            self._tenants[tenant] += 1
            return "admit"

    def release(self, caller_id: str | None, tenant_id: str | None) -> None:
        caller, tenant = self._keys(caller_id, tenant_id)
        with self._lock:
            for mapping, key in ((self._callers, caller), (self._tenants, tenant)):
                if mapping.get(key, 0) <= 1:
                    mapping.pop(key, None)
                else:
                    mapping[key] -= 1

    def inflight(self, caller_id: str | None, tenant_id: str | None) -> tuple[int, int]:
        caller, tenant = self._keys(caller_id, tenant_id)
        with self._lock:
            return self._callers.get(caller, 0), self._tenants.get(tenant, 0)
