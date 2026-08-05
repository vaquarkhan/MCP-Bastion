"""
Bring-Your-Own-Identity (BYOI): consume gateway-stamped principals without running login.

Bastion does NOT run OAuth authorization or login UI. It stamps principal/role/tenant from
headers or JWTs your edge already issued. Optional cryptographic verify (HS256 secret or
JWKS via PyJWT) when Bastion is the first crypto check on the path.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
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
    # Optional JWT crypto verify (still BYOI — no login server).
    verify: bool = False
    issuer: str | None = None
    audience: str | None = None
    jwks_url: str | None = None
    hmac_secret_env: str = "BASTION_JWT_HMAC_SECRET"
    leeway_seconds: float = 60.0
    # Map OAuth scopes → a single RBAC role name (first matching scope wins).
    scope_map: dict[str, str] = field(default_factory=dict)
    scope_separator: str = " "

    @classmethod
    def from_config(cls, data: dict[str, Any] | None) -> IdentityAdapterConfig:
        if not data:
            return cls()
        raw_map = data.get("scope_map") or {}
        scope_map = {
            str(k): str(v)
            for k, v in raw_map.items()
            if str(k).strip() and str(v).strip()
        } if isinstance(raw_map, dict) else {}
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
            verify=bool(data.get("verify", False)),
            issuer=(str(data["issuer"]).strip() if data.get("issuer") else None),
            audience=(str(data["audience"]).strip() if data.get("audience") else None),
            jwks_url=(str(data["jwks_url"]).strip() if data.get("jwks_url") else None),
            hmac_secret_env=str(data.get("hmac_secret_env", "BASTION_JWT_HMAC_SECRET")),
            leeway_seconds=float(data.get("leeway_seconds", 60)),
            scope_map=scope_map,
            scope_separator=str(data.get("scope_separator", " ") or " "),
        )


def _decode_jwt_payload_unverified(token: str) -> dict[str, Any]:
    """Parse JWT payload without signature verify (gateway-trust mode)."""
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


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _verify_hs256(token: str, secret: str, *, leeway: float) -> dict[str, Any]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWT structure")
    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(_b64url_decode(header_b64))
    if str(header.get("alg", "")).upper() != "HS256":
        raise ValueError(f"unsupported JWT alg for HMAC path: {header.get('alg')}")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    got = _b64url_decode(sig_b64)
    if not hmac.compare_digest(expected, got):
        raise ValueError("JWT HMAC signature mismatch")
    claims = json.loads(_b64url_decode(payload_b64))
    if not isinstance(claims, dict):
        raise ValueError("JWT payload must be object")
    now = time.time()
    exp = claims.get("exp")
    if exp is not None and now > float(exp) + leeway:
        raise ValueError("JWT expired")
    nbf = claims.get("nbf")
    if nbf is not None and now + leeway < float(nbf):
        raise ValueError("JWT not yet valid")
    return claims


def _verify_with_pyjwt(
    token: str,
    *,
    issuer: str | None,
    audience: str | None,
    jwks_url: str | None,
    hmac_secret: str | None,
    leeway: float,
) -> dict[str, Any]:
    try:
        import jwt
    except ImportError as e:
        raise RuntimeError(
            "identity_adapter.verify requires PyJWT when using JWKS/RS256. "
            "pip install 'mcp-bastion-python[oidc]' or set hmac_secret_env for HS256."
        ) from e

    options = {"require": ["exp"]}
    kwargs: dict[str, Any] = {"leeway": leeway, "options": options}
    if issuer:
        kwargs["issuer"] = issuer
    if audience:
        kwargs["audience"] = audience

    if jwks_url:
        from jwt import PyJWKClient

        client = PyJWKClient(jwks_url, cache_keys=True)
        signing_key = client.get_signing_key_from_jwt(token)
        return jwt.decode(token, signing_key.key, algorithms=["RS256", "ES256", "EdDSA"], **kwargs)

    if hmac_secret:
        return jwt.decode(token, hmac_secret, algorithms=["HS256"], **kwargs)

    raise ValueError("verify=true requires jwks_url or hmac_secret_env")


def decode_jwt_claims(token: str, config: IdentityAdapterConfig) -> dict[str, Any]:
    """Decode JWT claims; optionally verify signature and standard claims."""
    if not config.verify:
        return _decode_jwt_payload_unverified(token)

    secret = os.environ.get(config.hmac_secret_env, "") or None
    # Prefer stdlib HS256 when secret is set and no JWKS (no optional dep).
    if secret and not config.jwks_url:
        claims = _verify_hs256(token, secret, leeway=config.leeway_seconds)
    else:
        claims = _verify_with_pyjwt(
            token,
            issuer=config.issuer,
            audience=config.audience,
            jwks_url=config.jwks_url,
            hmac_secret=secret,
            leeway=config.leeway_seconds,
        )

    if config.issuer and claims.get("iss") != config.issuer:
        raise ValueError("JWT issuer mismatch")
    if config.audience:
        aud = claims.get("aud")
        if isinstance(aud, list):
            if config.audience not in [str(x) for x in aud]:
                raise ValueError("JWT audience mismatch")
        elif aud is not None and str(aud) != config.audience:
            raise ValueError("JWT audience mismatch")
    return claims


def _scopes_from_claim(role_val: Any, separator: str) -> list[str]:
    if role_val is None:
        return []
    if isinstance(role_val, list):
        return [str(x).strip() for x in role_val if str(x).strip()]
    text = str(role_val).strip()
    if not text:
        return []
    if " " in text and separator == " ":
        return [p for p in text.split() if p]
    if "," in text:
        return [p.strip() for p in text.split(",") if p.strip()]
    return [text]


def _role_from_scopes(scopes: list[str], scope_map: dict[str, str]) -> str | None:
    if not scopes:
        return None
    if scope_map:
        for scope in scopes:
            if scope in scope_map:
                return scope_map[scope]
    return scopes[0]


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
        scopes: list[str] = []

        if self.config.adapter_type == "jwt_claim":
            raw = md.get(self.config.jwt_metadata_key)
            if raw is None:
                return False
            try:
                claims = decode_jwt_claims(str(raw), self.config)
            except Exception as e:
                logger.warning("identity_adapter jwt failed: %s", e)
                return False
            principal = claims.get(self.config.principal_claim)
            role_val = claims.get(self.config.role_claim)
            scopes = _scopes_from_claim(role_val, self.config.scope_separator)
            role = _role_from_scopes(scopes, self.config.scope_map)
            if self.config.tenant_claim and not tenant:
                tv = claims.get(self.config.tenant_claim)
                if tv is not None:
                    tenant = str(tv)
            md["scopes"] = scopes
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
        logger.debug("identity_adapter stamped principal=%s role=%s scopes=%s", principal, role, scopes)
        return True
