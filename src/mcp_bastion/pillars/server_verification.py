"""
Cryptographic verification of MCP server artifacts (supply chain / typosquatting defense).

Compares on-disk file SHA-256 hashes against a signed-off manifest in bastion.yaml
before Bastion allows tool traffic.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

OnMismatch = Literal["block", "warn"]


def sha256_file(path: Path) -> str:
    """Return lowercase hex SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_manifest_bytes(files: dict[str, str]) -> bytes:
    import json

    normalized = {str(k).replace("\\", "/"): normalize_hash(v) for k, v in sorted(files.items())}
    return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(files: dict[str, str], signing_key: str | bytes) -> str:
    """HMAC-SHA256 signature over canonical manifest (Sigstore-style trust anchor optional)."""
    key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
    return hmac.new(key, canonical_manifest_bytes(files), hashlib.sha256).hexdigest()


def verify_manifest_signature(files: dict[str, str], signature: str, signing_key: str | bytes) -> bool:
    if not signature or not signing_key:
        return False
    expected = sign_manifest(files, signing_key)
    sig = str(signature).strip().lower()
    return hmac.compare_digest(expected.encode("utf-8"), sig.encode("utf-8"))


def normalize_hash(value: str) -> str:
    """Strip optional sha256: prefix and lowercase."""
    v = str(value or "").strip().lower()
    if v.startswith("sha256:"):
        return v[7:]
    return v


@dataclass
class VerificationResult:
    ok: bool
    mismatches: list[dict[str, str]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.ok:
            return "all manifest entries match"
        parts = []
        if self.missing:
            parts.append(f"{len(self.missing)} missing file(s)")
        if self.mismatches:
            parts.append(f"{len(self.mismatches)} hash mismatch(es)")
        return "; ".join(parts) or "verification failed"


class ServerVerifier:
    """
    Verify files under base_path match expected SHA-256 hashes from manifest.

    manifest: relative_path -> sha256 hex (optionally prefixed with sha256:)
    """

    def __init__(
        self,
        manifest: dict[str, str],
        *,
        base_path: str | Path = ".",
        on_mismatch: OnMismatch = "block",
        manifest_signature: str | None = None,
        signing_key: str | None = None,
    ) -> None:
        if on_mismatch not in ("block", "warn"):
            raise ValueError("on_mismatch must be block or warn")
        self.manifest = {str(k).replace("\\", "/"): normalize_hash(v) for k, v in (manifest or {}).items()}
        self.base_path = Path(base_path).resolve()
        self.on_mismatch = on_mismatch
        self.manifest_signature = manifest_signature
        self.signing_key = signing_key
        self._verified = False
        self._last_result: VerificationResult | None = None

    @property
    def last_result(self) -> VerificationResult | None:
        return self._last_result

    def verify(self, *, force: bool = False) -> VerificationResult:
        """Run verification; cache result unless force=True."""
        if self._verified and not force and self._last_result is not None:
            return self._last_result

        mismatches: list[dict[str, str]] = []
        missing: list[str] = []

        for rel, expected in self.manifest.items():
            path = (self.base_path / rel).resolve()
            try:
                path.relative_to(self.base_path)
            except ValueError:
                mismatches.append(
                    {"path": rel, "reason": "path escapes base_path", "expected": expected}
                )
                continue
            if not path.is_file():
                missing.append(rel)
                continue
            actual = sha256_file(path)
            if actual != expected:
                mismatches.append(
                    {
                        "path": rel,
                        "expected": expected,
                        "actual": actual,
                    }
                )

        ok = not mismatches and not missing
        result = VerificationResult(ok=ok, mismatches=mismatches, missing=missing)
        self._last_result = result
        self._verified = True

        if not ok:
            logger.warning(
                "server_verification failed: %s (on_mismatch=%s)",
                result.summary,
                self.on_mismatch,
            )
        else:
            logger.info("server_verification passed for %d file(s)", len(self.manifest))

        return result

    def ensure_ok(self, *, force: bool = False) -> None:
        """Verify and raise ServerVerificationError when on_mismatch=block and check fails."""
        from mcp_bastion.errors import ServerVerificationError

        if self.manifest_signature and self.signing_key:
            if not verify_manifest_signature(self.manifest, self.manifest_signature, self.signing_key):
                if self.on_mismatch == "warn":
                    logger.warning("server_verification manifest HMAC signature mismatch")
                else:
                    raise ServerVerificationError(
                        "Request blocked: MCP server manifest signature verification failed"
                    )

        result = self.verify(force=force)
        if result.ok:
            return
        if self.on_mismatch == "warn":
            return
        detail = result.summary
        if result.mismatches:
            first = result.mismatches[0]
            detail = f"{detail}; example: {first['path']} expected {first.get('expected', '?')[:16]}…"
        raise ServerVerificationError(
            f"Request blocked: MCP server checksum verification failed ({detail}). "
            "Update manifest after a trusted deploy or investigate possible supply-chain tampering."
        )


def build_manifest(paths: list[str], *, base_path: str | Path = ".") -> dict[str, str]:
    """Compute sha256 manifest for CLI / CI manifest generation."""
    base = Path(base_path).resolve()
    out: dict[str, str] = {}
    for rel in paths:
        rel_norm = str(rel).replace("\\", "/")
        path = (base / rel_norm).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Cannot hash missing file: {rel_norm}")
        out[rel_norm] = sha256_file(path)
    return out
