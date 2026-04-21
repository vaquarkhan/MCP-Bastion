"""Tests for model-based sensitive content classifier."""

from unittest import mock

from mcp_bastion.pillars.sensitive_classifier import SensitiveContentClassifier


def test_sensitive_classifier_empty_text():
    c = SensitiveContentClassifier()
    r = c.classify("   ")
    assert r.label == "not_sensitive"
    assert r.source == "empty"


def test_sensitive_classifier_transformers_path_negative_label():
    c = SensitiveContentClassifier(threshold=0.1, use_transformers=True)

    class FakePipe:
        def __call__(self, text):
            return [{"label": "NEGATIVE", "score": 0.99}]

    with mock.patch.object(c, "_get_pipeline", return_value=FakePipe()):
        r = c.classify("anything long enough")
    assert r.label == "sensitive_business"
    assert r.source == "transformers"


def test_sensitive_classifier_transformers_exception_falls_back_to_weights():
    c = SensitiveContentClassifier(threshold=0.2, use_transformers=True)

    class BadPipe:
        def __call__(self, text):
            raise RuntimeError("model fail")

    with mock.patch.object(c, "_get_pipeline", return_value=BadPipe()):
        r = c.classify("Confidential merger plans")
    assert r.label == "sensitive_business"


def test_sensitive_classifier_get_pipeline_import_failure_returns_none():
    c = SensitiveContentClassifier(use_transformers=True)
    real_import = __import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "transformers" or (isinstance(name, str) and name.startswith("transformers")):
            raise ImportError("no transformers")
        return real_import(name, globals, locals, fromlist, level)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        assert c._get_pipeline() is None


def test_sensitive_classifier_flags_sensitive_text():
    c = SensitiveContentClassifier(threshold=0.2)
    pred = c.classify("Confidential merger and acquisition plans with due diligence notes")
    assert pred.label == "sensitive_business"
    assert pred.score >= 0.2


def test_sensitive_classifier_allows_benign_text():
    c = SensitiveContentClassifier(threshold=0.6)
    pred = c.classify("What is the weather in Seattle tomorrow?")
    assert pred.label == "not_sensitive"
