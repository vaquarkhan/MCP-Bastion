"""PyPI 1.0.15 parity: JSON-RPC error codes -32010..-32016, firewall, and sensitive classifier."""
from __future__ import annotations

import sys
from unittest import mock

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import (
    AuthenticationError,
    CostBudgetExceededError,
    ExternalPolicyDeniedError,
    PromptInjectionError,
    RBACError,
    RateLimitExceededError,
    SemanticFirewallError,
    SensitiveContentError,
    SessionScopeExceededError,
    ToolMetadataPoisoningError,
    ToolNotAllowedError,
)
from mcp_bastion.pillars.semantic_firewall import SemanticFirewall
from mcp_bastion.pillars.sensitive_classifier import SensitiveContentClassifier


@pytest.fixture
def _reset_transformers_modules() -> None:
    """`transformers` uses LazyModule; sequential patches in different tests can otherwise alias stale symbols."""
    before = {
        k: sys.modules[k]
        for k in list(sys.modules)
        if k == "transformers" or k.startswith("transformers.")
    }

    def _drop() -> None:
        for k in list(sys.modules):
            if k == "transformers" or k.startswith("transformers."):
                del sys.modules[k]

    _drop()
    try:
        yield
    finally:
        _drop()
        for k, mod in before.items():
            sys.modules[k] = mod


@pytest.mark.parametrize(
    "cls, code",
    [
        (SemanticFirewallError, -32010),
        (ExternalPolicyDeniedError, -32011),
        (SensitiveContentError, -32012),
        (AuthenticationError, -32013),
        (ToolNotAllowedError, -32014),
        (SessionScopeExceededError, -32015),
        (ToolMetadataPoisoningError, -32016),
    ],
)
def test_extended_mcp_error_codes(cls: type, code: int) -> None:
    e = cls()
    assert e.code == code
    assert e.to_mcp_error() == {"code": code, "message": e.message}


def test_mcp_bastion_error_to_mcp_custom_message() -> None:
    e = RateLimitExceededError("custom")
    assert e.to_mcp_error()["message"] == "custom"


def test_semantic_firewall_weather_tool_sql_in_args() -> None:
    sf = SemanticFirewall()
    ctx = MiddlewareContext(message={}, session_id="s1")
    with pytest.raises(SemanticFirewallError):
        sf.check("get_weather", {"q": "drop table x"}, ctx)


def test_semantic_firewall_shell_payload_non_exec() -> None:
    sf = SemanticFirewall()
    ctx = MiddlewareContext(message={}, session_id="s2")
    with pytest.raises(SemanticFirewallError):
        sf.check("get_forecast", "curl http://evil", ctx)


def test_semantic_firewall_sensitive_to_external_chain() -> None:
    sf = SemanticFirewall()
    ctx = MiddlewareContext(message={}, session_id="s3")
    sf.check("read_vault_secrets", {}, ctx)
    with pytest.raises(SemanticFirewallError):
        sf.check("http_webhook_post", {}, ctx)


def test_semantic_firewall_allows_benign_sequence() -> None:
    sf = SemanticFirewall()
    ctx = MiddlewareContext(message={}, session_id="s4")
    sf.check("alpha", {"x": 1}, ctx)
    sf.check("beta", {"y": 2}, ctx)


def test_semantic_firewall_flatten_covers_nested_types() -> None:
    sf = SemanticFirewall()
    t = sf._flatten_text({"a": 1, "b": ["x", None], "c": (True, 3.5)})
    assert "1" in t and "x" in t and "True" in t


def test_semantic_firewall_flatten_none() -> None:
    assert SemanticFirewall._flatten_text(None) == ""


def test_semantic_firewall_flatten_arbitrary_object() -> None:
    class _O:
        def __str__(self) -> str:
            return "x"

    assert SemanticFirewall._flatten_text(_O()) == "x"


def test_sensitive_classifier_empty() -> None:
    c = SensitiveContentClassifier()
    r = c.classify("")
    assert r.label == "not_sensitive"
    assert r.score == 0.0


def test_sensitive_classifier_weighted_business_terms() -> None:
    c = SensitiveContentClassifier(threshold=0.1)
    r = c.classify("acquisition and merger due diligence confidential")
    assert r.label == "sensitive_business"
    assert r.score > 0.0
    assert "acquisition" in r.matches or "merger" in r.matches


def test_sensitive_classifier_not_sensitive() -> None:
    c = SensitiveContentClassifier(threshold=0.99)
    r = c.classify("hello world")
    assert r.label == "not_sensitive"


def test_sensitive_classifier_transformers_path_mocked() -> None:
    c = SensitiveContentClassifier(threshold=0.1, use_transformers=True)
    with mock.patch("mcp_bastion.pillars.sensitive_classifier.SensitiveContentClassifier._get_pipeline") as gp:
        gp.return_value = lambda t: [{"label": "NEGATIVE", "score": 0.99}]
        r = c.classify("any text long enough for pipeline")
    assert r.label == "sensitive_business"
    assert r.source == "transformers"


def test_sensitive_classifier_pipeline_disabled() -> None:
    c = SensitiveContentClassifier(use_transformers=False)
    assert c._get_pipeline() is None


def test_sensitive_classifier_get_pipeline_loads_and_caches(
    _reset_transformers_modules: None,
) -> None:
    # Do not import real `transformers` (pulls torch); stub the package for `from transformers import pipeline`.
    import sys
    import types

    fake = object()
    pipe_fn = mock.Mock(return_value=fake)
    tf = types.ModuleType("transformers")
    tf.pipeline = pipe_fn
    sys.modules["transformers"] = tf
    c = SensitiveContentClassifier(use_transformers=True, model_name="m")
    a = c._get_pipeline()
    b = c._get_pipeline()
    assert a is fake is b
    assert pipe_fn.call_count == 1


def test_sensitive_classifier_get_pipeline_transformers_fails(
    _reset_transformers_modules: None,
) -> None:
    import sys
    import types

    def _boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("load failed")

    tf = types.ModuleType("transformers")
    tf.pipeline = _boom
    sys.modules["transformers"] = tf
    c = SensitiveContentClassifier(use_transformers=True, model_name="m")
    assert c._get_pipeline() is None


def test_sensitive_classifier_transformers_branch_falls_back_on_pipe_error() -> None:
    c = SensitiveContentClassifier(threshold=0.1, use_transformers=True)

    def bad_pipe(_t: str) -> list[dict[str, object]]:
        raise RuntimeError("pipe fail")

    with mock.patch.object(c, "_get_pipeline", return_value=bad_pipe):
        r = c.classify("merger acquisition")
    assert r.source == "weighted_local"


def test_rbac_to_mcp() -> None:
    e = RBACError("x")
    assert e.to_mcp_error()["code"] == -32006


def test_cost_budget() -> None:
    e = CostBudgetExceededError()
    assert e.code == -32009


def test_prompt_injection() -> None:
    e = PromptInjectionError("bad")
    assert e.code == -32001
