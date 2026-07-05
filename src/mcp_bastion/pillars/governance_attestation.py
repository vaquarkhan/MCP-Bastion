"""Signed, exportable governance attestation per agent session."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_bastion.pillars.audit_hash_chain import AuditHashChain, canonical_audit_payload
from mcp_bastion.pillars.session_governance import SessionGovernanceRecorder


def policy_version_hash(config_path: str | Path | None) -> str:
    """SHA-256 of bastion.yaml bytes (or empty genesis)."""
    if not config_path:
        return "0" * 64
    p = Path(config_path)
    if not p.is_file():
        return "0" * 64
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build_session_attestation(
    session_id: str,
    *,
    config_path: str | Path | None = None,
    policy_hash: str | None = None,
    principal_id: str | None = None,
    tenant_id: str | None = None,
    total_cost_usd: float = 0.0,
) -> dict[str, Any]:
    """Assemble attestation payload for a session."""
    recorder = SessionGovernanceRecorder.get()
    events = recorder.events_for_session(session_id)
    blocked = [e for e in events if e.get("status") == "blocked"]
    allowed = [e for e in events if e.get("status") != "blocked"]
    pillars_fired = sorted({e.get("pillar") for e in events if e.get("pillar")})
    chain_head = AuditHashChain.get().head()
    recorded_cost = round(sum(float(e.get("cost_usd") or 0) for e in events), 4)
    return {
        "attestation_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "principal_id": principal_id,
        "tenant_id": tenant_id,
        "policy": {
            "config_path": str(config_path) if config_path else None,
            "policy_hash": policy_hash or policy_version_hash(config_path),
        },
        "audit_chain_head": chain_head,
        "summary": {
            "total_events": len(events),
            "allowed_count": len(allowed),
            "blocked_count": len(blocked),
            "pillars_fired": pillars_fired,
            "total_cost_usd": round(total_cost_usd if total_cost_usd else recorded_cost, 4),
        },
        "events": events,
        "blocked_events": blocked,
    }


def sign_attestation(payload: dict[str, Any], signing_key: str | bytes) -> str:
    """HMAC-SHA256 over canonical JSON (excludes signature fields)."""
    body = {k: v for k, v in payload.items() if k not in ("signature", "signature_algorithm")}
    canonical = canonical_audit_payload(body)
    key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def export_session_attestation(
    session_id: str,
    *,
    config_path: str | Path | None = None,
    principal_id: str | None = None,
    tenant_id: str | None = None,
    total_cost_usd: float = 0.0,
    sign: bool = False,
    signing_key_env: str = "BASTION_MANIFEST_SIGNING_KEY",
) -> dict[str, Any]:
    """Build attestation; optionally sign with HMAC key from env."""
    payload = build_session_attestation(
        session_id,
        config_path=config_path,
        principal_id=principal_id,
        tenant_id=tenant_id,
        total_cost_usd=total_cost_usd,
    )
    if sign:
        key = os.environ.get(signing_key_env, "")
        if not key:
            raise ValueError(f"Set {signing_key_env} to sign attestations")
        payload["signature_algorithm"] = "hmac-sha256"
        payload["signature"] = sign_attestation(payload, key)
    return payload
