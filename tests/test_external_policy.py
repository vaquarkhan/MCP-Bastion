"""Tests for optional OPA/Cedar policy evaluation."""

import subprocess
from unittest import mock

from mcp_bastion.pillars.external_policy import ExternalPolicyConfig, ExternalPolicyEvaluator, normalize_engine


def test_normalize_engine():
    assert normalize_engine(None) == "none"
    assert normalize_engine("OPA") == "opa"
    assert normalize_engine("bogus") == "none"


def test_evaluate_none_always_allows():
    ev = ExternalPolicyEvaluator(ExternalPolicyConfig())
    ok, reason = ev.evaluate({"tool": "x"})
    assert ok is True
    assert reason is None


def test_evaluate_unknown_engine_falls_through():
    ev = ExternalPolicyEvaluator(ExternalPolicyConfig(engine="none"))
    ev._cfg = mock.Mock(engine="weird")  # type: ignore[attr-defined]
    ok, reason = ev.evaluate({"x": 1})
    assert ok is True


def test_from_env_reads_vars(monkeypatch):
    monkeypatch.setenv("BASTION_POLICY_ENGINE", "opa")
    monkeypatch.setenv("BASTION_OPA_BINARY", "opa-bin")
    monkeypatch.setenv("BASTION_OPA_POLICY_DIR", "/policies")
    monkeypatch.setenv("BASTION_OPA_QUERY", "data.x.allow")
    monkeypatch.setenv("BASTION_CEDAR_BINARY", "cedar-bin")
    monkeypatch.setenv("BASTION_CEDAR_POLICIES_DIR", "/cedar")
    monkeypatch.setenv("BASTION_CEDAR_SCHEMA", "/schema.cedarschema")
    ev = ExternalPolicyEvaluator.from_env()
    assert ev._cfg.engine == "opa"
    assert ev._cfg.opa_binary == "opa-bin"
    assert ev._cfg.opa_policy_dir == "/policies"
    assert ev._cfg.opa_query == "data.x.allow"
    assert ev._cfg.cedar_binary == "cedar-bin"
    assert ev._cfg.cedar_policies_dir == "/cedar"
    assert ev._cfg.cedar_schema_path == "/schema.cedarschema"


def test_opa_skips_when_policy_dir_missing(tmp_path):
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="opa",
            opa_policy_dir=str(tmp_path / "nope"),
            opa_binary="opa",
            fail_closed=False,
        )
    )
    ok, reason = ev.evaluate({"tool": "x"})
    assert ok is True and reason is None


def test_opa_skips_when_policy_dir_not_a_directory(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="opa",
            opa_policy_dir=str(f),
            opa_binary="opa",
            fail_closed=False,
        )
    )
    ok, reason = ev.evaluate({"tool": "x"})
    assert ok is True and reason is None


def test_opa_denied_on_false_stdout(tmp_path):
    policies = tmp_path / "policies"
    policies.mkdir()
    inp = {"tool": "x"}
    fake = mock.Mock(
        returncode=0,
        stdout="false",
        stderr="",
    )
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(engine="opa", opa_policy_dir=str(policies), opa_binary="opa")
    )
    with mock.patch("subprocess.run", return_value=fake):
        ok, reason = ev.evaluate(inp)
    assert ok is False
    assert reason is not None


def test_opa_allows_on_true_stdout(tmp_path):
    policies = tmp_path / "policies"
    policies.mkdir()
    fake = mock.Mock(returncode=0, stdout="true", stderr="")
    captured = {}

    def run(cmd, **kwargs):
        captured["cmd"] = cmd
        return fake

    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(engine="opa", opa_policy_dir=str(policies), opa_binary="opa")
    )
    with mock.patch("subprocess.run", side_effect=run):
        ok, reason = ev.evaluate({"a": 1})
    assert ok is True and reason is None
    assert "-f" in captured["cmd"]
    assert "raw" in captured["cmd"]
    assert "value" not in captured["cmd"]


def test_opa_nonzero_returncode_allows_with_warning(tmp_path, caplog):
    policies = tmp_path / "policies"
    policies.mkdir()
    fake = mock.Mock(returncode=1, stdout="", stderr="bad policy")
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="opa",
            opa_policy_dir=str(policies),
            opa_binary="opa",
            fail_closed=False,
        )
    )
    with caplog.at_level("WARNING"):
        with mock.patch("subprocess.run", return_value=fake):
            ok, reason = ev.evaluate({"a": 1})
    assert ok is True and reason is None


def test_opa_subprocess_timeout_allows(tmp_path, caplog):
    policies = tmp_path / "policies"
    policies.mkdir()
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="opa",
            opa_policy_dir=str(policies),
            opa_binary="opa",
            fail_closed=False,
        )
    )
    with caplog.at_level("WARNING"):
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("opa", 5)):
            ok, reason = ev.evaluate({"a": 1})
    assert ok is True


def test_opa_file_not_found_allows(tmp_path, caplog):
    policies = tmp_path / "policies"
    policies.mkdir()
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="opa",
            opa_policy_dir=str(policies),
            opa_binary="opa",
            fail_closed=False,
        )
    )
    with caplog.at_level("WARNING"):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("opa")):
            ok, reason = ev.evaluate({"a": 1})
    assert ok is True


def test_cedar_skips_when_policies_dir_missing(tmp_path):
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="cedar",
            cedar_policies_dir=str(tmp_path / "missing"),
            fail_closed=False,
        )
    )
    ok, reason = ev.evaluate({"x": 1})
    assert ok is True and reason is None


def test_cedar_denies_when_only_deny_in_output(tmp_path):
    pol = tmp_path / "policies"
    pol.mkdir()
    fake = mock.Mock(returncode=0, stdout="DECISION DENY\n", stderr="")
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(engine="cedar", cedar_policies_dir=str(pol), cedar_binary="cedar")
    )
    with mock.patch("subprocess.run", return_value=fake):
        ok, reason = ev.evaluate({"ctx": 1})
    assert ok is False
    assert "denied" in (reason or "").lower()


def test_cedar_allows_when_permit_present(tmp_path):
    pol = tmp_path / "policies"
    pol.mkdir()
    fake = mock.Mock(returncode=0, stdout="DENY but PERMIT wins\n", stderr="")
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(engine="cedar", cedar_policies_dir=str(pol), cedar_binary="cedar")
    )
    with mock.patch("subprocess.run", return_value=fake):
        ok, reason = ev.evaluate({"ctx": 1})
    assert ok is True


def test_cedar_adds_schema_flag_when_file_exists(tmp_path):
    pol = tmp_path / "policies"
    pol.mkdir()
    schema = tmp_path / "schema.json"
    schema.write_text("{}", encoding="utf-8")
    captured = {}

    def run(cmd, **kwargs):
        captured["cmd"] = cmd
        return mock.Mock(returncode=0, stdout="PERMIT\n", stderr="")

    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="cedar",
            cedar_policies_dir=str(pol),
            cedar_binary="cedar",
            cedar_schema_path=str(schema),
        )
    )
    with mock.patch("subprocess.run", side_effect=run):
        ev.evaluate({"a": 1})
    assert "--schema" in captured["cmd"]
    assert str(schema) in captured["cmd"]
    assert "authorize" in captured["cmd"]
    assert "evaluate" not in captured["cmd"]
    assert "--request-json" in captured["cmd"]


def test_cedar_nonzero_returncode_allows(tmp_path, caplog):
    pol = tmp_path / "policies"
    pol.mkdir()
    fake = mock.Mock(returncode=2, stdout="", stderr="cedar err")
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="cedar",
            cedar_policies_dir=str(pol),
            cedar_binary="cedar",
            fail_closed=False,
        )
    )
    with caplog.at_level("WARNING"):
        with mock.patch("subprocess.run", return_value=fake):
            ok, reason = ev.evaluate({"a": 1})
    assert ok is True


def test_opa_fail_closed_when_policy_dir_missing(tmp_path):
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="opa",
            opa_policy_dir=str(tmp_path / "nope"),
            opa_binary="opa",
            fail_closed=True,
        )
    )
    ok, reason = ev.evaluate({"tool": "x"})
    assert ok is False
    assert reason is not None
    assert "external_policy" in reason


def test_opa_fail_closed_on_nonzero_returncode(tmp_path):
    policies = tmp_path / "policies"
    policies.mkdir()
    fake = mock.Mock(returncode=1, stdout="", stderr="bad policy")
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(engine="opa", opa_policy_dir=str(policies), opa_binary="opa", fail_closed=True)
    )
    with mock.patch("subprocess.run", return_value=fake):
        ok, reason = ev.evaluate({"a": 1})
    assert ok is False
    assert "OPA eval failed" in (reason or "")


def test_opa_fail_closed_on_timeout(tmp_path):
    policies = tmp_path / "policies"
    policies.mkdir()
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(engine="opa", opa_policy_dir=str(policies), opa_binary="opa", fail_closed=True)
    )
    with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("opa", 5)):
        ok, reason = ev.evaluate({"a": 1})
    assert ok is False
    assert "timed out" in (reason or "").lower()


def test_cedar_fail_closed_when_policies_dir_missing(tmp_path):
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="cedar",
            cedar_policies_dir=str(tmp_path / "missing"),
            fail_closed=True,
        )
    )
    ok, reason = ev.evaluate({"x": 1})
    assert ok is False
    assert reason is not None


def test_cedar_oserror_allows(tmp_path, caplog):
    pol = tmp_path / "policies"
    pol.mkdir()
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="cedar",
            cedar_policies_dir=str(pol),
            cedar_binary="cedar",
            fail_closed=False,
        )
    )
    with caplog.at_level("WARNING"):
        with mock.patch("subprocess.run", side_effect=OSError("nope")):
            ok, reason = ev.evaluate({"a": 1})
    assert ok is True


def test_from_env_reads_fail_closed(monkeypatch):
    monkeypatch.setenv("BASTION_POLICY_ENGINE", "none")
    monkeypatch.setenv("BASTION_POLICY_FAIL_CLOSED", "true")
    ev = ExternalPolicyEvaluator.from_env()
    assert ev._cfg.fail_closed is True


def test_opa_real_binary_smoke(tmp_path):
    """Run real `opa eval -f raw` when opa is on PATH (skips otherwise)."""
    import shutil

    opa = shutil.which("opa")
    if not opa:
        import pytest

        pytest.skip("opa binary not on PATH")

    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "bastion.rego").write_text(
        'package bastion\n\ndefault allow := false\n\nallow if {\n  input.role == "admin"\n}\n',
        encoding="utf-8",
    )
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="opa",
            opa_binary=opa,
            opa_policy_dir=str(policies),
            opa_query="data.bastion.allow",
            fail_closed=True,
        )
    )
    ok, reason = ev.evaluate({"role": "admin"})
    assert ok is True, reason
    ok2, reason2 = ev.evaluate({"role": "guest"})
    assert ok2 is False
    assert reason2 is not None
