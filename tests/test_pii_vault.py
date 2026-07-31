"""Tests for reversible PII vault (abstraction + hydration)."""

from __future__ import annotations

import json

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.pii_redaction import PIIRedactor, _redact_dashed_ssn_patterns
from mcp_bastion.pillars.pii_vault import (
    TOKEN_RE,
    BufferedTokenRestorer,
    EntitySpan,
    PiiVault,
    detect_entities_regex,
    format_token,
    normalize_entity_type,
)
from mcp_bastion.pillars.state_backend import MemoryStateBackend


def test_normalize_and_format_token():
    assert normalize_entity_type("email-address") == "EMAIL_ADDRESS"
    tok = format_token("EMAIL_ADDRESS", "aabbccddeeff")
    assert tok == "{{pii:EMAIL_ADDRESS:aabbccddeeff}}"
    assert TOKEN_RE.fullmatch(tok)


def test_detect_entities_regex_email_ssn():
    text = "Contact alice@example.com SSN 123-45-6789"
    spans = detect_entities_regex(text)
    types = {s.entity_type for s in spans}
    assert "EMAIL_ADDRESS" in types
    assert "US_SSN" in types
    assert "alice@example.com" in text[spans[0].start : spans[0].end] or any(
        s.text == "alice@example.com" for s in spans
    )


def test_vault_abstract_and_restore_roundtrip():
    vault = PiiVault(backend=MemoryStateBackend(), ttl_seconds=60)
    session = "tenant|sess-1"
    text = "Email alice@example.com and SSN 123-45-6789 please"
    vaulted = vault.abstract_text(text, session, detect=detect_entities_regex)
    assert "alice@example.com" not in vaulted
    assert "123-45-6789" not in vaulted
    assert "{{pii:" in vaulted
    restored = vault.restore_text(vaulted, session)
    assert "alice@example.com" in restored
    assert "123-45-6789" in restored


def test_same_value_same_token_within_session():
    vault = PiiVault(backend=MemoryStateBackend())
    session = "s1"
    a = vault.mint_token(session, "EMAIL_ADDRESS", "a@b.com")
    b = vault.mint_token(session, "EMAIL_ADDRESS", "a@b.com")
    assert a == b
    other = vault.mint_token("s2", "EMAIL_ADDRESS", "a@b.com")
    # Different session must not share mapping identity necessarily (new id)
    assert "{{pii:EMAIL_ADDRESS:" in other


def test_token_id_is_not_hash_of_value():
    vault = PiiVault(backend=MemoryStateBackend())
    tok = vault.mint_token("s", "EMAIL_ADDRESS", "secret@example.com")
    assert "secret" not in tok
    assert "example" not in tok
    m = TOKEN_RE.fullmatch(tok)
    assert m
    # hex id only
    assert all(c in "0123456789abcdef" for c in m.group(2))


def test_restore_unknown_token_left_intact():
    vault = PiiVault(backend=MemoryStateBackend())
    text = "Send to {{pii:EMAIL_ADDRESS:deadbeefcafebabe}}"
    assert vault.restore_text(text, "s") == text


def test_restore_value_nested():
    vault = PiiVault(backend=MemoryStateBackend())
    session = "s"
    tok = vault.mint_token(session, "EMAIL_ADDRESS", "alice@example.com")
    payload = {"to": tok, "meta": {"cc": [tok]}, "n": 1}
    out = vault.restore_value(payload, session)
    assert out["to"] == "alice@example.com"
    assert out["meta"]["cc"][0] == "alice@example.com"
    assert out["n"] == 1


def test_abstract_content_items():
    vault = PiiVault(backend=MemoryStateBackend())
    content = [
        {"type": "text", "text": "mail bob@corp.com"},
        {"type": "image", "data": "x"},
    ]
    out = vault.abstract_content_items(content, "s", detect=detect_entities_regex)
    assert "bob@corp.com" not in out[0]["text"]
    assert out[1]["type"] == "image"


def test_buffered_restorer_handles_split_token():
    vault = PiiVault(backend=MemoryStateBackend())
    session = "s"
    tok = vault.mint_token(session, "EMAIL_ADDRESS", "alice@example.com")
    # Split mid-token
    mid = len(tok) // 2
    restorer = BufferedTokenRestorer(vault, session)
    part1 = restorer.push("Hello " + tok[:mid])
    assert "{{pii:" not in part1 or "alice@" not in part1
    part2 = restorer.push(tok[mid:] + "!")
    flush = restorer.flush()
    full = part1 + part2 + flush
    assert "alice@example.com" in full
    assert "{{pii:" not in full


def test_buffered_restorer_flush_empty():
    restorer = BufferedTokenRestorer(PiiVault(), "s")
    assert restorer.flush() == ""


def test_pii_vault_invalid_ttl():
    with pytest.raises(ValueError):
        PiiVault(ttl_seconds=0)


def test_redactor_vault_text_with_regex_detect():
    redactor = PIIRedactor()
    vault = PiiVault(backend=MemoryStateBackend())
    out = redactor.vault_text(
        "reach me at carol@example.org",
        vault,
        "s",
        detect=detect_entities_regex,
    )
    assert "carol@example.org" not in out
    assert vault.restore_text(out, "s") == "reach me at carol@example.org"


def test_destructive_redact_unchanged_when_vault_disabled():
    """Default path still uses placeholders / SSN pattern (no vault tokens)."""
    assert "<US_SSN>" in _redact_dashed_ssn_patterns("SSN 123-45-6789")


@pytest.mark.asyncio
async def test_middleware_default_destructive_not_vault():
    """Vault OFF: existing destructive path; no {{pii: tokens}}."""

    class FakePII(PIIRedactor):
        def redact_text(self, text: str) -> str:
            return text.replace("alice@example.com", "<EMAIL_ADDRESS>")

        def redact_content_items(self, content):
            return [{"type": "text", "text": self.redact_text(c["text"])} for c in content]

    mw = MCPBastionMiddleware(
        pii_redactor=FakePII(),
        enable_pii_redaction=True,
        enable_pii_vault=False,
        enable_prompt_guard=False,
        enable_rate_limit=False,
    )

    async def handler(ctx):
        return {"content": [{"type": "text", "text": "User alice@example.com"}]}

    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "echo", "arguments": {}}},
        session_id="sess-a",
        metadata={},
    )
    # Bypass full call path: exercise _redact_result_content directly
    result = {"content": [{"type": "text", "text": "User alice@example.com"}]}
    out = mw._redact_result_content(result, context=ctx)
    assert out["content"][0]["text"] == "User <EMAIL_ADDRESS>"
    assert "{{pii:" not in out["content"][0]["text"]


@pytest.mark.asyncio
async def test_middleware_vault_abstract_and_hydrate_e2e():
    vault = PiiVault(backend=MemoryStateBackend())

    class RegexPII(PIIRedactor):
        def detect_spans(self, text: str):
            return detect_entities_regex(text)

        def vault_content_items(self, content, vault, session_key, *, detect=None):
            return vault.abstract_content_items(
                content, session_key, detect=detect or detect_entities_regex
            )

    mw = MCPBastionMiddleware(
        pii_redactor=RegexPII(),
        pii_vault=vault,
        enable_pii_redaction=True,
        enable_pii_vault=True,
        enable_prompt_guard=False,
        enable_rate_limit=False,
        enable_circuit_breaker=False,
        enable_content_filter=False,
    )

    captured: dict = {}

    async def handler(ctx):
        return {"content": [{"type": "text", "text": "Contact alice@example.com ASAP"}]}

    # First call: abstract outbound
    ctx1 = MiddlewareContext(
        message={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "lookup", "arguments": {"q": "hi"}},
        },
        request_id="1",
        session_id="vault-sess",
        metadata={"tenant_id": "t1"},
    )
    out1 = await mw(ctx1, handler)
    text1 = out1["content"][0]["text"]
    assert "alice@example.com" not in text1
    assert "{{pii:" in text1

    m = TOKEN_RE.search(text1)
    assert m
    token = m.group(0)
    ctx2 = MiddlewareContext(
        message={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "send_mail", "arguments": {"to": token}},
        },
        request_id="2",
        session_id="vault-sess",
        metadata={"tenant_id": "t1"},
    )

    async def send_handler(ctx):
        params = ctx.message["params"]
        captured["hydrated"] = params["arguments"]
        return {"content": [{"type": "text", "text": "sent"}]}

    await mw(ctx2, send_handler)
    assert captured["hydrated"]["to"] == "alice@example.com"


def test_load_config_pii_vault_defaults_off(tmp_path):
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    from mcp_bastion.config import load_config

    p = tmp_path / "bastion.yaml"
    p.write_text("pii:\n  enabled: true\n", encoding="utf-8")
    cfg = load_config(str(p))
    assert cfg.pii is True
    assert cfg.pii_vault is False


def test_load_config_pii_vault_enabled(tmp_path):
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    from mcp_bastion.config import load_config, build_middleware_from_config

    p = tmp_path / "bastion.yaml"
    p.write_text(
        "audit: {enabled: false}\n"
        "pii:\n  enabled: true\npii_vault:\n  enabled: true\n  ttl_seconds: 120\n"
        "prompt_guard:\n  enabled: false\nrate_limit:\n  enabled: false\n",
        encoding="utf-8",
    )
    cfg = load_config(str(p))
    assert cfg.pii_vault is True
    assert cfg.pii_vault_ttl_seconds == 120.0
    mw = build_middleware_from_config(cfg)
    assert isinstance(mw, MCPBastionMiddleware)
    assert mw.enable_pii_vault is True
    assert mw.pii_vault is not None


def test_dedupe_overlapping_spans():
    from mcp_bastion.pillars.pii_vault import _dedupe_spans

    spans = [
        EntitySpan(0, 5, "A", "hello"),
        EntitySpan(0, 2, "B", "he"),
        EntitySpan(6, 9, "C", "you"),
    ]
    out = _dedupe_spans(spans)
    assert len(out) == 2
    assert out[0].text == "hello"


def test_normalize_entity_type_empty():
    assert normalize_entity_type("") == "PII"
    assert normalize_entity_type("  ") == "PII"


def test_detect_phone_and_credit_card():
    text = "Call 415-555-0199 card 4111 1111 1111 1111"
    spans = detect_entities_regex(text)
    types = {s.entity_type for s in spans}
    assert "PHONE_NUMBER" in types
    assert "CREDIT_CARD" in types


def test_detect_entities_presidio_empty_and_fallback():
    from mcp_bastion.pillars.pii_vault import detect_entities_presidio

    assert detect_entities_presidio(object(), "") == []
    assert detect_entities_presidio(object(), None) == []  # type: ignore[arg-type]

    class Boom:
        def _ensure_loaded(self):
            raise RuntimeError("no presidio")

    spans = detect_entities_presidio(Boom(), "mail x@y.com")
    assert any(s.entity_type == "EMAIL_ADDRESS" for s in spans)


def test_detect_entities_presidio_skips_bad_offsets():
    from mcp_bastion.pillars.pii_vault import detect_entities_presidio

    class FakeResult:
        def __init__(self, start, end, entity_type="EMAIL_ADDRESS"):
            self.start = start
            self.end = end
            self.entity_type = entity_type

    class FakeAnalyzer:
        def analyze(self, **kwargs):
            return [
                FakeResult(5, 3),  # end <= start
                FakeResult(-1, 2),
                FakeResult(0, 999),  # past len
                FakeResult(0, 11, "EMAIL_ADDRESS"),
            ]

    class FakeRedactor:
        language = "en"
        entities = ["EMAIL_ADDRESS"]

        def _ensure_loaded(self):
            return None

        def __init__(self):
            self._analyzer = FakeAnalyzer()

    text = "alice@x.com"
    spans = detect_entities_presidio(FakeRedactor(), text)
    assert any(s.text == "alice@x.com" for s in spans)


def test_vault_edge_cases():
    vault = PiiVault(backend=MemoryStateBackend())
    assert vault.abstract_text("", "s") == ""
    assert vault.abstract_text(None, "s") is None  # type: ignore[arg-type]
    assert vault.restore_text("", "s") == ""
    assert vault.restore_text(None, "s") is None  # type: ignore[arg-type]
    assert vault.abstract_content_items([], "s") == []
    assert vault.restore_value(42, "s") == 42
    assert vault.restore_value(("a",), "s") == ("a",)
    vault.wipe_session("s")  # TTL no-op
    with pytest.raises(ValueError):
        PiiVault(id_bytes=2)
    # non-string value coerced
    tok = vault.mint_token("s", "CUSTOM", 12345)
    assert vault.restore_text(tok, "s") == "12345"
    # lookup miss
    assert vault.lookup("s", "00" * 6) is None
    # corrupt fwd payload
    vault.backend.set_json(vault._fwd_key("s", "abcdef12"), {"type": "X"})  # missing value
    assert vault.lookup("s", "abcdef12") is None


def test_abstract_text_with_explicit_spans():
    vault = PiiVault(backend=MemoryStateBackend())
    text = "hello world"
    spans = [EntitySpan(6, 11, "PERSON", "world")]
    out = vault.abstract_text(text, "s", spans=spans)
    assert "world" not in out
    assert vault.restore_text(out, "s") == "hello world"


def test_hydrate_tool_arguments_string_json(monkeypatch):
    vault = PiiVault(backend=MemoryStateBackend())
    tok = vault.mint_token("default|anon", "EMAIL_ADDRESS", "a@b.com")
    mw = MCPBastionMiddleware(
        pii_vault=vault,
        enable_pii_vault=True,
        enable_pii_redaction=True,
        enable_prompt_guard=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(message={}, session_id="anon", metadata={"tenant_id": "default"})
    params = {"arguments": json.dumps({"to": tok})}
    # Force restore path for JSON string args that parse to dict
    trace: list = []
    # After parse, restore_value on dict
    import json as _json

    raw = params["arguments"]
    parsed = _json.loads(raw)
    restored = vault.restore_value(parsed, mw._vault_session_key(ctx))
    assert restored["to"] == "a@b.com"
    # Direct hydrate with string non-json
    params2 = {"arguments": f"send {tok}"}
    mw._hydrate_tool_arguments(ctx, params2, trace=trace)
    assert "a@b.com" in params2["arguments"]
    assert any(t.get("pillar") == "pii_vault_hydrate" for t in trace)


def test_redactor_vault_content_and_none_vault():
    redactor = PIIRedactor()
    content = [{"type": "text", "text": "x@y.com"}, {"type": "image", "data": "z"}]
    vault = PiiVault(backend=MemoryStateBackend())
    items = redactor.vault_content_items(content, vault, "s", detect=detect_entities_regex)
    assert "x@y.com" not in items[0]["text"]
    assert items[1]["type"] == "image"
    assert redactor.vault_content_items([], vault, "s") == []
    # None vault delegates to destructive redact_content_items (empty short-circuit)
    assert redactor.vault_content_items([], None, "s") == []
    out = redactor.vault_text("hello", vault, "s", detect=lambda t: [])
    assert out == "hello"
