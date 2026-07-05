"""Tests for pluggable secrets resolver."""

import os

import pytest

from mcp_bastion.pillars.secrets_resolver import EnvSecretsResolver, SecretsConfig, SecretsResolver


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
