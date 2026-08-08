"""
Tamper-evident audit log hash chain.

Each entry's digest binds to the previous entry's digest so retroactive edits
invalidate the chain. Optional periodic anchors can be pushed to webhooks
or immutable storage (S3 Object Lock, etc.) out of band.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

GENESIS_PREV = "0" * 64


def canonical_audit_payload(payload: dict[str, Any]) -> str:
    """Stable JSON for hashing (excludes chain fields)."""
    skip = frozenset({"audit_prev_hash", "audit_entry_hash", "audit_chain_index", "audit_anchor"})
    filtered = {k: v for k, v in sorted(payload.items()) if k not in skip}
    return json.dumps(filtered, sort_keys=True, default=str, separators=(",", ":"))


def entry_digest(prev_hash: str, canonical_body: str) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"|")
    h.update(canonical_body.encode("utf-8"))
    return h.hexdigest()


@dataclass
class ChainLink:
    index: int
    prev_hash: str
    entry_hash: str
    timestamp: str
    tool: str = ""
    action: str = ""


class AuditHashChain:
    """Thread-safe append-only hash chain for audit / forensic entries."""

    _lock = threading.Lock()
    _instance: AuditHashChain | None = None

    def __init__(self, *, anchor_every: int = 0) -> None:
        self._prev_hash = GENESIS_PREV
        self._index = -1
        self._anchor_every = max(0, int(anchor_every))
        self._recent_links: list[ChainLink] = []
        self._anchors: list[dict[str, Any]] = []
        self._max_recent = 100

    @classmethod
    def get(cls) -> AuditHashChain:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def configure(cls, *, anchor_every: int = 0) -> None:
        with cls._lock:
            cls._instance = cls(anchor_every=anchor_every)

    def reset(self) -> None:
        with self._lock:
            self._prev_hash = GENESIS_PREV
            self._index = -1
            self._recent_links.clear()
            self._anchors.clear()

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Mutates payload in place with chain fields; returns payload."""
        canonical = canonical_audit_payload(payload)
        with self._lock:
            self._index += 1
            idx = self._index
            prev = self._prev_hash
            digest = entry_digest(prev, canonical)
            self._prev_hash = digest
            link = ChainLink(
                index=idx,
                prev_hash=prev,
                entry_hash=digest,
                timestamp=datetime.now(timezone.utc).isoformat(),
                tool=str(payload.get("tool") or "")[:120],
                action=str(payload.get("action") or "")[:40],
            )
            self._recent_links.append(link)
            if len(self._recent_links) > self._max_recent:
                self._recent_links = self._recent_links[-self._max_recent :]
            anchor: dict[str, Any] | None = None
            if self._anchor_every > 0 and (idx + 1) % self._anchor_every == 0:
                anchor = {
                    "chain_index": idx,
                    "head_hash": digest,
                    "timestamp": link.timestamp,
                }
                self._anchors.append(anchor)
                if len(self._anchors) > 50:
                    self._anchors = self._anchors[-50:]
                payload["audit_anchor"] = anchor
        payload["audit_chain_index"] = idx
        payload["audit_prev_hash"] = prev
        payload["audit_entry_hash"] = digest
        return payload

    def head(self) -> dict[str, Any]:
        with self._lock:
            return {
                "chain_length": self._index + 1,
                "head_hash": self._prev_hash,
                "genesis_prev": GENESIS_PREV,
            }

    def verify_recent(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Verify a list of entries each includes correct prev_hash linkage."""
        prev = GENESIS_PREV
        errors: list[dict[str, Any]] = []
        for i, e in enumerate(entries):
            ph = e.get("audit_prev_hash")
            if ph != prev:
                errors.append({"position": i, "expected_prev": prev, "got_prev": ph})
            body = canonical_audit_payload(e)
            expected = entry_digest(str(ph or ""), body)
            eh = e.get("audit_entry_hash")
            if eh != expected:
                errors.append({"position": i, "expected_hash": expected, "got_hash": eh})
            prev = str(eh or "")
        return {"valid": len(errors) == 0, "errors": errors}

    def recent_links(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            out = self._recent_links[-max(1, limit) :]
            return [
                {
                    "index": x.index,
                    "prev_hash": x.prev_hash,
                    "entry_hash": x.entry_hash,
                    "timestamp": x.timestamp,
                    "tool": x.tool,
                    "action": x.action,
                }
                for x in out
            ]

    def anchors(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._anchors)
