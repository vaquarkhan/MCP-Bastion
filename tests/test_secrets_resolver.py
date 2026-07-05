"""Tests for pluggable secrets resolver."""

import sys
import types
from unittest import mock

import pytest

from mcp_bastion.pillars.secrets_resolver import (
    AwsSecretsResolver,
    EnvSecretsResolver,
    GcpSecretsResolver,
    SecretsConfig,
    SecretsResolver,
    VaultSecretsResolver,
)


def test_env_secrets_resolver(monkeypatch):
    monkeypatch.setenv("BASTION_TEST_SECRET", "s3cr3t")
    r = EnvSecretsResolver()
    assert r.resolve("env:BASTION_TEST_SECRET") == "s3cr3t"
    assert r.resolve("BASTION_TEST_SECRET") == "s3cr3t"


def test_env_secrets_missing_raises():
    r = EnvSecretsResolver()
    with pytest.raises(KeyError, match="not found"):
        r.resolve("env:DEFINITELY_MISSING_XYZ")


def test_secrets_resolver_from_config_defaults_env():
    r = SecretsResolver.from_config(SecretsConfig())
    assert isinstance(r, EnvSecretsResolver)


def test_secrets_resolver_unknown_provider_falls_back_to_env():
    r = SecretsResolver.from_config(SecretsConfig(provider="unknown-vault"))
    assert isinstance(r, EnvSecretsResolver)


def test_vault_resolver_import_error():
    r = VaultSecretsResolver(SecretsConfig())
    import builtins

    real_import = builtins.__import__

    def _block_hvac(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "hvac" or (fromlist and "hvac" in fromlist):
            raise ImportError("no hvac")
        return real_import(name, globals, locals, fromlist, level)

    with mock.patch("builtins.__import__", side_effect=_block_hvac):
        with pytest.raises(RuntimeError, match="vault"):
            r.resolve("my-secret")


def test_vault_resolver_reads_secret():
    fake_client = mock.Mock()
    fake_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"token": "vault-value"}}
    }
    fake_hvac = mock.Mock()
    fake_hvac.Client.return_value = fake_client
    with mock.patch.dict(sys.modules, {"hvac": fake_hvac}):
        r = VaultSecretsResolver(SecretsConfig(vault_path_prefix="secret/"))
        assert r.resolve("my-key") == "vault-value"


def test_vault_resolver_empty_raises():
    fake_client = mock.Mock()
    fake_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {}}}
    fake_hvac = mock.Mock()
    fake_hvac.Client.return_value = fake_client
    with mock.patch.dict(sys.modules, {"hvac": fake_hvac}):
        r = VaultSecretsResolver(SecretsConfig())
        with pytest.raises(KeyError, match="empty"):
            r.resolve("missing")


def test_aws_resolver_reads_secret():
    fake_client = mock.Mock()
    fake_client.get_secret_value.return_value = {"SecretString": "aws-secret"}
    fake_boto3 = mock.Mock()
    fake_boto3.client.return_value = fake_client
    with mock.patch.dict(sys.modules, {"boto3": fake_boto3}):
        r = AwsSecretsResolver(SecretsConfig(aws_region="us-east-1"))
        assert r.resolve("prod/api-key") == "aws-secret"


def test_aws_resolver_import_error():
    r = AwsSecretsResolver(SecretsConfig())
    import builtins

    real_import = builtins.__import__

    def _block_boto3(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, globals, locals, fromlist, level)

    with mock.patch("builtins.__import__", side_effect=_block_boto3):
        with pytest.raises(RuntimeError, match="boto3"):
            r.resolve("x")


def test_gcp_resolver_reads_secret(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "my-proj")
    decoded = "gcp-secret"

    class Resp:
        class Payload:
            @staticmethod
            def decode(_enc: str) -> str:
                return decoded

            data = type("Data", (), {"decode": decode})()

        payload = Payload()

    class Client:
        def access_secret_version(self, request: dict) -> Resp:
            assert "projects/my-proj/secrets/api-key" in request["name"]
            return Resp()

    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = Client  # type: ignore[attr-defined]
    fake_cloud = types.ModuleType("google.cloud")
    fake_cloud.secretmanager = fake_sm  # type: ignore[attr-defined]
    fake_google = types.ModuleType("google")
    fake_google.cloud = fake_cloud  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google", fake_google)
    monkeypatch.setitem(sys.modules, "google.cloud", fake_cloud)
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)

    r = GcpSecretsResolver(SecretsConfig(gcp_project="my-proj"))
    assert r.resolve("api-key") == decoded
