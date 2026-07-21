"""Tests for server checksum verification."""

from pathlib import Path

import pytest

from mcp_bastion.errors import ServerVerificationError
from mcp_bastion.pillars.server_verification import ServerVerifier, build_manifest, sha256_file


def test_sha256_file_and_manifest(tmp_path):
    f = tmp_path / "server.py"
    f.write_text("print('hello')\n", encoding="utf-8")
    digest = sha256_file(f)
    manifest = build_manifest(["server.py"], base_path=tmp_path)
    assert manifest["server.py"] == digest


def test_server_verifier_detects_tamper(tmp_path):
    f = tmp_path / "server.py"
    f.write_text("v1\n", encoding="utf-8")
    good = sha256_file(f)
    verifier = ServerVerifier({"server.py": good}, base_path=tmp_path, on_mismatch="block")
    assert verifier.verify().ok is True

    f.write_text("v2-tampered\n", encoding="utf-8")
    assert verifier.verify(force=True).ok is False
    with pytest.raises(ServerVerificationError):
        verifier.ensure_ok()


def test_server_verifier_rechecks_when_forced(tmp_path):
    f = tmp_path / "server.py"
    f.write_text("v1\n", encoding="utf-8")
    good = sha256_file(f)
    verifier = ServerVerifier({"server.py": good}, base_path=tmp_path, on_mismatch="block")
    verifier.ensure_ok()
    f.write_text("v2-tampered\n", encoding="utf-8")
    verifier.ensure_ok()  # cached - still passes
    with pytest.raises(ServerVerificationError):
        verifier.ensure_ok(force=True)


def test_server_verifier_warn_mode_allows(tmp_path):
    f = tmp_path / "server.py"
    f.write_text("v1\n", encoding="utf-8")
    verifier = ServerVerifier({"server.py": "0" * 64}, base_path=tmp_path, on_mismatch="warn")
    verifier.ensure_ok()  # does not raise
