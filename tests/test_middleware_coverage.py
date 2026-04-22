"""Tests for full middleware coverage - internal helpers and all branches."""

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import (
    CostBudgetExceededError,
    PromptInjectionError,
    RateLimitExceededError,
    ReplayAttackError,
    SchemaValidationError,
)
from mcp_bastion.middleware import (
    MCPBastionMiddleware,
    _extract_text_from_value,
    _get_content_from_result,
    _get_params,
    _get_request_id,
    _get_tool_name_from_params,
    _is_call_tool_request,
    _is_read_resource_result,
    _set_content_in_result,
)
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.schema_validation import SchemaValidator
from mcp_bastion.pillars.semantic_cache import SemanticCache


def test_extract_text_from_value_none():
    assert _extract_text_from_value(None) == ""


def test_extract_text_from_value_str():
    assert _extract_text_from_value("hello") == "hello"


def test_extract_text_from_value_int_float_bool():
    assert _extract_text_from_value(42) == "42"
    assert _extract_text_from_value(3.14) == "3.14"
    assert _extract_text_from_value(True) == "True"


def test_extract_text_from_value_dict():
    assert _extract_text_from_value({"a": "x", "b": "y"}) == "x y"


def test_extract_text_from_value_list_tuple():
    assert _extract_text_from_value(["a", "b"]) == "a b"
    assert _extract_text_from_value(("x",)) == "x"


def test_extract_text_from_value_fallback():
    assert _extract_text_from_value(object())  # str(object())


def test_is_call_tool_request_root():
    class Msg:
        root = {"method": "tools/call"}

    assert _is_call_tool_request(Msg()) is True


def test_is_call_tool_request_method_attr():
    class Msg:
        method = "tools/call"

    assert _is_call_tool_request(Msg()) is True


def test_is_call_tool_request_dict():
    assert _is_call_tool_request({"method": "tools/call"}) is True
    assert _is_call_tool_request({"method": "other"}) is False


def test_is_read_resource_result_none():
    assert _is_read_resource_result(None) is False


def test_is_read_resource_result_contents_attr():
    class Obj:
        contents = []

    assert _is_read_resource_result(Obj()) is True


def test_is_read_resource_result_root_with_content():
    class Msg:
        root = {"result": {"contents": []}}

    assert _is_read_resource_result(Msg()) is True


def test_is_read_resource_result_dict_content():
    assert _is_read_resource_result({"result": {"content": []}}) is True


def test_is_read_resource_result_result_has_contents_attr():
    """Result object with contents attribute (not dict)."""
    class Obj:
        contents = []

    assert _is_read_resource_result({"result": Obj()}) is True


def test_get_tool_name_from_params():
    assert _get_tool_name_from_params(None) == "unknown"
    assert _get_tool_name_from_params({}) == "unknown"
    assert _get_tool_name_from_params({"name": "my_tool"}) == "my_tool"


def test_get_params_root():
    class Msg:
        root = {"params": {"x": 1}}

    assert _get_params(Msg()) == {"x": 1}


def test_get_params_dict_result():
    assert _get_params({"result": {"a": 1}}) == {"a": 1}


def test_get_params_attr():
    class Params:
        __dict__ = {"b": 2}

    class Msg:
        params = Params()

    assert _get_params(Msg()) == {"b": 2}


def test_get_request_id():
    class Msg:
        root = {"id": "req-123"}

    assert _get_request_id(Msg()) == "req-123"


def test_get_request_id_attr():
    class Msg:
        id = "req-456"

    assert _get_request_id(Msg()) == "req-456"


def test_get_request_id_empty_string():
    """Empty id returns None."""
    assert _get_request_id({"id": ""}) is None


def test_get_request_id_returns_none():
    """Message without id returns None."""
    class Msg:
        pass

    assert _get_request_id(Msg()) is None


def test_get_params_returns_none():
    """Message without params or dict returns None."""
    class Msg:
        pass

    assert _get_params(Msg()) is None


def test_get_content_from_result_none():
    assert _get_content_from_result(None) is None


def test_get_content_from_result_payload_dict_with_contents():
    """Payload dict with contents key (direct, no result wrapper)."""
    r = {"contents": [{"type": "text", "text": "a"}]}
    assert _get_content_from_result(r) == [{"type": "text", "text": "a"}]


def test_get_content_from_result_result_key():
    r = {"result": {"contents": [{"type": "text", "text": "x"}]}}
    assert _get_content_from_result(r) == [{"type": "text", "text": "x"}]


def test_get_content_from_result_content_key():
    r = {"content": [{"type": "text", "text": "y"}]}
    assert _get_content_from_result(r) == [{"type": "text", "text": "y"}]


def test_get_content_from_result_model_dump():
    class Item:
        def model_dump(self):
            return {"type": "text", "text": "z"}

    r = {"contents": [Item()]}
    out = _get_content_from_result(r)
    assert out == [{"type": "text", "text": "z"}]


def test_get_content_from_result_non_dict_item():
    r = {"contents": ["plain"]}
    out = _get_content_from_result(r)
    assert out == [{"type": "text", "text": "plain"}]


def test_get_content_from_result_payload_has_contents_attr():
    """Payload is object with .contents attribute (not dict)."""
    class Payload:
        contents = [{"type": "text", "text": "from_attr"}]
    out = _get_content_from_result(Payload())
    assert out == [{"type": "text", "text": "from_attr"}]


def test_set_content_in_result_contents_attr():
    class Payload:
        contents = []

    r = {"result": Payload()}
    _set_content_in_result(r, [{"type": "text", "text": "new"}])
    assert r["result"].contents == [{"type": "text", "text": "new"}]


def test_set_content_in_result_dict_contents_content():
    r = {"result": {"contents": [], "content": []}}
    _set_content_in_result(r, [{"x": 1}])
    assert r["result"]["contents"] == [{"x": 1}]
    assert r["result"]["content"] == [{"x": 1}]


def test_redact_result_content_no_content_returns_unchanged():
    """_redact_result_content returns result when no content to redact."""
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=True,
        enable_rate_limit=False,
    )
    result = {}
    out = mw._redact_result_content(result)
    assert out is result
    assert out == {}


@pytest.mark.asyncio
async def test_middleware_non_tool_request_passthrough():
    """Non tools/call passes through."""
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(message={"method": "ping"}, metadata={})

    async def handler(c):
        return "pong"

    result = await mw(ctx, handler)
    assert result == "pong"


@pytest.mark.asyncio
async def test_middleware_read_resource_result_redaction():
    """Read resource result triggers PII redaction."""
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_rate_limit=False,
        enable_pii_redaction=True,
    )
    ctx = MiddlewareContext(message={"method": "resources/read"}, metadata={})

    async def handler(c):
        return {"result": {"contents": [{"type": "text", "text": "hello"}]}}

    result = await mw(ctx, handler)
    assert result is not None
    assert "contents" in result.get("result", {})


@pytest.mark.asyncio
async def test_middleware_semantic_cache_json_decode_error():
    """Semantic cache handles JSON decode error in arguments."""
    sc = SemanticCache()
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        semantic_cache=sc,
        enable_semantic_cache=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": "not valid json"}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_middleware_schema_validation_non_dict_arguments():
    """Schema validation skips when arguments not dict after JSON parse."""
    sv = SchemaValidator({"x": {"a": str}})
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        schema_validator=sv,
        enable_schema_validation=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": "[]"}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_middleware_schema_validation_json_decode_error():
    """Schema validation handles JSON decode error - falls back to empty dict."""
    sv = SchemaValidator({"other": {"a": str}})
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        schema_validator=sv,
        enable_schema_validation=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": "not json"}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_middleware_rate_limit_blocked():
    """Rate limit blocks when over limit."""
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=1),
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=True,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": {}}},
        request_id="r1",
        session_id="s1",
    )

    async def handler(c):
        return {"ok": True}

    await mw(ctx, handler)
    with pytest.raises(RateLimitExceededError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_middleware_prompt_injection_blocked():
    """Prompt injection blocked when detected."""
    from unittest.mock import patch

    mw = MCPBastionMiddleware(
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        enable_prompt_guard=True,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": {"q": "malicious"}}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    with patch.object(mw.prompt_guard, "is_malicious", return_value=True):
        with pytest.raises(PromptInjectionError):
            await mw(ctx, handler)


@pytest.mark.asyncio
async def test_middleware_circuit_breaker_success():
    """Circuit breaker records success on successful call."""
    from mcp_bastion.pillars.circuit_breaker import CircuitBreaker

    cb = CircuitBreaker(failure_threshold=5)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        circuit_breaker=cb,
        enable_circuit_breaker=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "healthy", "arguments": {}}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_middleware_tool_call_pii_redaction():
    """Tool call result with content gets PII redaction."""
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        enable_prompt_guard=False,
        enable_pii_redaction=True,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "get_data", "arguments": {}}},
        request_id="r1",
    )

    async def handler(c):
        return {"result": {"contents": [{"type": "text", "text": "User SSN 123-45-6789"}]}}

    result = await mw(ctx, handler)
    assert result is not None
    assert "contents" in result.get("result", {})
    text = result["result"]["contents"][0].get("text", "")
    assert "123-45-6789" not in text, "SSN should be redacted (Presidio and/or dashed-SSN fallback)"


@pytest.mark.asyncio
async def test_middleware_content_filter_json_decode_error():
    """Content filter handles JSON decode error."""
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        enable_content_filter=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": "{invalid"}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_middleware_prompt_guard_json_decode_error():
    """Prompt guard handles JSON decode error."""
    mw = MCPBastionMiddleware(
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        enable_prompt_guard=True,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": "{bad"}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_middleware_semantic_cache_hit_skips_handler():
    """Semantic cache hit returns cached without calling handler."""
    sc = SemanticCache()
    sc.set("search", "hello", {"cached": True})
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        semantic_cache=sc,
        enable_semantic_cache=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "search", "arguments": {"q": "hello"}}},
        request_id="r1",
    )
    called = []

    async def handler(c):
        called.append(1)
        return {"fresh": True}

    result = await mw(ctx, handler)
    assert result == {"cached": True}
    assert len(called) == 0


@pytest.mark.asyncio
async def test_middleware_cost_tracker_records_from_metadata():
    """Cost tracker records cost from context.metadata."""
    ct = CostTracker(max_cost_per_session=1.0)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        cost_tracker=ct,
        enable_cost_tracker=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": {}}},
        request_id="r1",
        session_id="s1",
        metadata={},
    )

    async def handler(c):
        c.metadata["cost"] = 0.25
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_middleware_get_content_from_result_no_contents():
    """Result without contents returns None."""
    assert _get_content_from_result({"result": {}}) is None
    assert _get_content_from_result({"result": {"x": 1}}) is None


def test_middleware_get_content_items_not_list():
    """Result with non-list items returns None."""
    assert _get_content_from_result({"contents": "not a list"}) is None
