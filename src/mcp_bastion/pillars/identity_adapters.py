"""
Bring-Your-Own-Identity (BYOI): consume gateway-stamped principals without running login.

Bastion does NOT validate OAuth flows — it trusts claims/headers your edge gateway
or SSO proxy already authenticated. Enables per-principal RBAC, caps, and attestation
without becoming an auth server.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import Any

from mcp_bastion.pillars.budget_principal import mark_authenticated_role

logger = logging.getLogger(__name__)


@dataclass
class IdentityAdapterConfig:
    enabled: bool = False
    adapter_type: str = "header"  # header | jwt_claim
    header: str = "X-Bastion-Principal"
    role_header: str = "X-Bastion-Role"
    jwt_metadata_key: str = "bastion_jwt"
    principal_claim: str = "sub"
    role_claim: str = "scope"
    tenant_claim: str | None = "tenant_id"
    tenant_metadata_key: str = "tenant_id"

    @classmethod
    def from_config(cls, data: dict[str, Any] | None) -> IdentityAdapterConfig:
        if not data:
            return cls()
        return cls(
            enabled=bool(data.get("enabled", False)),
            adapter_type=str(data.get("type", data.get("adapter_type", "header"))).strip().lower(),
            header=str(data.get("header", "X-Bastion-Principal")),
            role_header=str(data.get("role_header", "X-Bastion-Role")),
            jwt_metadata_key=str(data.get("jwt_metadata_key", "bastion_jwt")),
            principal_claim=str(data.get("principal_claim", "sub")),
            role_claim=str(data.get("role_claim", "scope")),
            tenant_claim=data.get("tenant_claim"),
            tenant_metadata_key=str(data.get("tenant_metadata_key", "tenant_id")),
        )


def _decode_jwt_payload_unverified(token: str) -> dict[str, Any]:
    """Parse JWT payload (no signature verify — gateway already authenticated)."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("invalid JWT structure")
    payload_b64 = parts[1]
    pad = "=" * (-len(payload_b64) % 4)
    raw = base64.urlsafe_b64decode(payload_b64 + pad)
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JWT payload must be object")
    return data


class IdentityAdapter:
    """Stamp authenticated principal/role/tenant on middleware context metadata."""

    def __init__(self, config: IdentityAdapterConfig | None = None) -> None:
        self.config = config or IdentityAdapterConfig()

    @classmethod
    def from_config(cls, data: dict[str, Any] | None) -> IdentityAdapter:
        return cls(IdentityAdapterConfig.from_config(data))

    def stamp(self, context: Any) -> bool:
        """Return True if a principal was stamped."""
        if not self.config.enabled:
            return False
        md = getattr(context, "metadata", None)
        if not isinstance(md, dict):
            return False
        if md.get("agent_id"):
            return True
        principal: str | None = None
        role: str | None = None
        tenant: str | None = md.get(self.config.tenant_metadata_key)

        if self.config.adapter_type == "jwt_claim":
            raw = md.get(self.config.jwt_metadata_key)
            if raw is None:
                return False
            try:
                claims = _decode_jwt_payload_unverified(str(raw))
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.warning("identity_adapter jwt parse failed: %s", e)
                return False
            principal = claims.get(self.config.principal_claim)
            role_val = claims.get(self.config.role_claim)
            if isinstance(role_val, list):
                role = ",".join(str(x) for x in role_val)
            elif role_val is not None:
                role = str(role_val)
            if self.config.tenant_claim and not tenant:
                tv = claims.get(self.config.tenant_claim)
                if tv is not None:
                    tenant = str(tv)
        else:
            principal = md.get(self.config.header) or md.get(self.config.header.lower())
            role = md.get(self.config.role_header) or md.get(self.config.role_header.lower())

        if not principal:
            return False
        md["principal_id"] = str(principal)
        md.setdefault("agent_id", str(principal))
        if role:
            md["role"] = str(role)
        if tenant:
            md["tenant_id"] = str(tenant)
        mark_authenticated_role(context, role=str(role or principal))
        logger.debug("identity_adapter stamped principal=%s role=%s", principal, role)
        return True
