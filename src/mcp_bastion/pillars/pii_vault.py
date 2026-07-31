"""
Reversible PII tokenization (abstraction + hydration).

Opt-in privacy vault: replace detected PII with opaque typed tokens
``{{pii:TYPE:id}}`` so agents/LLMs never see raw values, then restore
tokens in inbound tool arguments before the MCP server executes.

Nature-preserving defaults:
- Disabled unless ``pii_vault.enabled: true`` (and ``pii.enabled: true``).
- Destructive Presidio redaction remains the default path.
- Uses existing ``StateBackend`` (memory by default; Redis optional).
- Token IDs are CSPRNG (never a hash of the plaintext) for ``token_style: typed``.
- Optional ``token_style: low_entropy`` emits ``EMAIL_ADDRESS_1`` / ``Person_A``.
"""

from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from mcp_bastion.pillars.state_backend import MemoryStateBackend, StateBackend

logger = logging.getLogger(__name__)

# Typed opaque placeholder: {{pii:EMAIL_ADDRESS:a3f9b2c1d4e5}}
TOKEN_RE = re.compile(r"\{\{pii:([A-Za-z0-9_]+):([a-f0-9]{8,32})\}\}")
TOKEN_TEMPLATE = "{{{{pii:{entity_type}:{token_id}}}}}"

# Low-entropy display forms: EMAIL_ADDRESS_1, Person_A (lookup-gated on restore).
LOW_ENTROPY_RE = re.compile(r"\b(Person_[A-Z]+|[A-Z][A-Z0-9_]*_\d+)\b")
_PERSON_TYPES = frozenset({"PERSON", "PERSON_NAME", "NAME", "NRP"})
_TOKEN_STYLES = frozenset({"typed", "low_entropy"})

# Deterministic fallbacks when Presidio is unavailable (tests / fail-soft).
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _index_to_letters(n: int) -> str:
    """1 -> A, 26 -> Z, 27 -> AA (Excel-style)."""
    if n < 1:
        n = 1
    out: list[str] = []
    while n > 0:
        n, rem = divmod(n - 1, 26)
        out.append(chr(ord("A") + rem))
    return "".join(reversed(out))


def count_vault_tokens(text: str) -> int:
    """Count typed + low-entropy vault placeholders in text (best-effort)."""
    if not text or not isinstance(text, str):
        return 0
    return len(TOKEN_RE.findall(text)) + len(LOW_ENTROPY_RE.findall(text))


@dataclass(frozen=True)
class EntitySpan:
    """A detected PII span in text (half-open [start, end))."""

    start: int
    end: int
    entity_type: str
    text: str


def normalize_entity_type(raw: str) -> str:
    """Map detector labels to vault token type segment."""
    t = (raw or "PII").strip().upper().replace("-", "_").replace(" ", "_")
    return t or "PII"


def format_token(entity_type: str, token_id: str) -> str:
    return TOKEN_TEMPLATE.format(entity_type=normalize_entity_type(entity_type), token_id=token_id)


def detect_entities_regex(text: str) -> list[EntitySpan]:
    """Fast regex entity finder (email / SSN / phone / card-ish). Overlaps resolved later."""
    if not text:
        return []
    spans: list[EntitySpan] = []
    for m in _EMAIL_RE.finditer(text):
        spans.append(EntitySpan(m.start(), m.end(), "EMAIL_ADDRESS", m.group(0)))
    for m in _SSN_RE.finditer(text):
        spans.append(EntitySpan(m.start(), m.end(), "US_SSN", m.group(0)))
    for m in _PHONE_RE.finditer(text):
        spans.append(EntitySpan(m.start(), m.end(), "PHONE_NUMBER", m.group(0)))
    for m in _CC_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19:
            spans.append(EntitySpan(m.start(), m.end(), "CREDIT_CARD", m.group(0)))
    return _dedupe_spans(spans)


def detect_entities_presidio(redactor: Any, text: str) -> list[EntitySpan]:
    """
    Use Presidio analyzer when available; fall back to regex on failure/empty.

    ``redactor`` is typically a ``PIIRedactor`` instance.
    """
    if not text or not isinstance(text, str):
        return []
    try:
        redactor._ensure_loaded()  # noqa: SLF001 - shared lazy load
        results = redactor._analyzer.analyze(  # noqa: SLF001
            text=text,
            language=getattr(redactor, "language", "en"),
            entities=getattr(redactor, "entities", None),
        )
        spans: list[EntitySpan] = []
        for r in results or []:
            start = int(getattr(r, "start", 0))
            end = int(getattr(r, "end", 0))
            if end <= start or start < 0 or end > len(text):
                continue
            et = normalize_entity_type(str(getattr(r, "entity_type", "PII")))
            spans.append(EntitySpan(start, end, et, text[start:end]))
        # Always supplement dashed SSN (Presidio miss on short strings).
        for m in _SSN_RE.finditer(text):
            spans.append(EntitySpan(m.start(), m.end(), "US_SSN", m.group(0)))
        merged = _dedupe_spans(spans)
        if merged:
            return merged
    except Exception as exc:
        logger.debug("Presidio vault detect failed, using regex: %s", exc)
    return detect_entities_regex(text)


def _dedupe_spans(spans: Iterable[EntitySpan]) -> list[EntitySpan]:
    """Prefer longer spans; drop overlaps (left-to-right by start)."""
    ordered = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    out: list[EntitySpan] = []
    cursor = -1
    for sp in ordered:
        if sp.start < cursor:
            continue
        out.append(sp)
        cursor = sp.end
    return out


class PiiVault:
    """
    Session-scoped reversible token store.

    Keys in ``StateBackend``:
    - ``pii_vault:fwd:{session}:{token}`` -> JSON ``{type, value}``
    - ``pii_vault:rev:{session}:{type}:{value}`` -> token id (stable within session)
    - ``pii_vault:seq:{session}:{type}`` -> counter (low_entropy only)
    """

    def __init__(
        self,
        backend: StateBackend | None = None,
        *,
        ttl_seconds: float = 3600.0,
        id_bytes: int = 6,
        key_prefix: str = "pii_vault",
        token_style: str = "typed",
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        if id_bytes < 4:
            raise ValueError("id_bytes must be >= 4")
        style = (token_style or "typed").strip().lower()
        if style not in _TOKEN_STYLES:
            raise ValueError(f"token_style must be one of {sorted(_TOKEN_STYLES)}")
        self.backend = backend or MemoryStateBackend()
        self.ttl_seconds = float(ttl_seconds)
        self.id_bytes = int(id_bytes)
        self.key_prefix = key_prefix
        self.token_style = style

    def _fwd_key(self, session_key: str, token_id: str) -> str:
        return f"{self.key_prefix}:fwd:{session_key}:{token_id}"

    def _rev_key(self, session_key: str, entity_type: str, value: str) -> str:
        # Value is stored only as part of Redis/memory key material for reverse lookup.
        return f"{self.key_prefix}:rev:{session_key}:{normalize_entity_type(entity_type)}:{value}"

    def _seq_key(self, session_key: str, entity_type: str) -> str:
        return f"{self.key_prefix}:seq:{session_key}:{normalize_entity_type(entity_type)}"

    def _alloc_low_entropy_label(self, session_key: str, entity_type: str) -> str:
        """Allocate EMAIL_ADDRESS_1 or Person_A within the session."""
        et = normalize_entity_type(entity_type)
        seq_key = self._seq_key(session_key, et)
        raw = self.backend.get(seq_key)
        try:
            n = int(raw) + 1 if raw is not None else 1
        except (TypeError, ValueError):
            n = 1
        self.backend.set(seq_key, str(n), ttl_seconds=self.ttl_seconds)
        if et in _PERSON_TYPES:
            return f"Person_{_index_to_letters(n)}"
        return f"{et}_{n}"

    def _display_token(self, entity_type: str, token_id: str) -> str:
        if self.token_style == "low_entropy":
            return token_id
        return format_token(entity_type, token_id)

    def mint_token(self, session_key: str, entity_type: str, value: str) -> str:
        """Return stable token for value within session (CSPRNG or low-entropy id)."""
        sk = session_key or "default"
        et = normalize_entity_type(entity_type)
        val = value if isinstance(value, str) else str(value)
        rev = self._rev_key(sk, et, val)
        existing = self.backend.get(rev)
        if existing:
            token_id = existing
        else:
            if self.token_style == "low_entropy":
                token_id = self._alloc_low_entropy_label(sk, et)
            else:
                token_id = secrets.token_hex(self.id_bytes)
            self.backend.set(rev, token_id, ttl_seconds=self.ttl_seconds)
            self.backend.set_json(
                self._fwd_key(sk, token_id),
                {"type": et, "value": val},
                ttl_seconds=self.ttl_seconds,
            )
        return self._display_token(et, token_id)

    def lookup(self, session_key: str, token_id: str) -> tuple[str, str] | None:
        """Return ``(entity_type, value)`` for token id, or None."""
        data = self.backend.get_json(self._fwd_key(session_key or "default", token_id))
        if not data:
            return None
        et = str(data.get("type") or "PII")
        val = data.get("value")
        if val is None:
            return None
        return et, str(val)

    def wipe_session(self, session_key: str) -> None:
        """Best-effort wipe: MemoryStateBackend has no scan; callers rely on TTL.

        For memory backend we cannot enumerate keys; wipe is a no-op beyond documentation.
        Redis deployments rely on TTL. Exposed for API completeness / future backends.
        """
        _ = session_key
        logger.debug("pii_vault wipe_session relies on TTL (session=%s)", session_key)

    def abstract_text(
        self,
        text: str,
        session_key: str,
        *,
        spans: list[EntitySpan] | None = None,
        detect: Callable[[str], list[EntitySpan]] | None = None,
    ) -> str:
        """Replace PII spans with vault tokens (right-to-left to preserve offsets)."""
        if not text or not isinstance(text, str):
            return text
        found = spans if spans is not None else (detect or detect_entities_regex)(text)
        if not found:
            return text
        out = text
        for sp in sorted(found, key=lambda s: s.start, reverse=True):
            token = self.mint_token(session_key, sp.entity_type, sp.text)
            out = out[: sp.start] + token + out[sp.end :]
        return out

    def restore_text(self, text: str, session_key: str) -> str:
        """Replace vault tokens with original plaintext (unknown tokens left intact)."""
        if not text or not isinstance(text, str):
            return text
        sk = session_key or "default"

        def _sub_typed(m: re.Match[str]) -> str:
            token_id = m.group(2)
            hit = self.lookup(sk, token_id)
            if hit is None:
                return m.group(0)
            return hit[1]

        out = TOKEN_RE.sub(_sub_typed, text)

        def _sub_low(m: re.Match[str]) -> str:
            label = m.group(0)
            hit = self.lookup(sk, label)
            if hit is None:
                return label
            return hit[1]

        return LOW_ENTROPY_RE.sub(_sub_low, out)

    def abstract_content_items(
        self,
        content: list[dict[str, Any]],
        session_key: str,
        *,
        detect: Callable[[str], list[EntitySpan]] | None = None,
    ) -> list[dict[str, Any]]:
        if not content:
            return content
        out: list[dict[str, Any]] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and "text" in item:
                out.append(
                    {
                        **item,
                        "text": self.abstract_text(str(item["text"]), session_key, detect=detect),
                    }
                )
            else:
                out.append(item)
        return out

    def restore_value(self, value: Any, session_key: str) -> Any:
        """Recursively restore tokens in strings / dicts / lists."""
        if isinstance(value, str):
            return self.restore_text(value, session_key)
        if isinstance(value, dict):
            return {k: self.restore_value(v, session_key) for k, v in value.items()}
        if isinstance(value, list):
            return [self.restore_value(v, session_key) for v in value]
        if isinstance(value, tuple):
            return tuple(self.restore_value(v, session_key) for v in value)
        return value


class BufferedTokenRestorer:
    """
    Streaming-safe vault restore: hold chunks that may contain a partial ``{{pii:...}}``.

    MCP Bastion's HTTP proxy mutates complete JSON-RPC response bodies; this helper is
    for SSE/chunk pipelines (Phase 3) and is fully unit-tested.
    """

    def __init__(self, vault: PiiVault, session_key: str) -> None:
        self.vault = vault
        self.session_key = session_key
        self._buf = ""

    def push(self, chunk: str) -> str:
        """Accept a chunk; return flushable prefix with complete tokens restored."""
        if not chunk:
            return ""
        self._buf += chunk
        # Find last '{{' that might still be open (no closing '}}' after it).
        last_open = self._buf.rfind("{{")
        if last_open < 0:
            out = self.vault.restore_text(self._buf, self.session_key)
            self._buf = ""
            return out
        after = self._buf[last_open:]
        if "}}" in after:
            out = self.vault.restore_text(self._buf, self.session_key)
            self._buf = ""
            return out
        # Hold from last '{{'; flush safe prefix.
        safe = self._buf[:last_open]
        self._buf = self._buf[last_open:]
        return self.vault.restore_text(safe, self.session_key) if safe else ""

    def flush(self) -> str:
        """Flush remaining buffer (end of stream)."""
        out = self.vault.restore_text(self._buf, self.session_key)
        self._buf = ""
        return out
