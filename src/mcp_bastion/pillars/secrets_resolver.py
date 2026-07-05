"""
Pluggable secrets resolver — BYO vault without Bastion storing credentials.

Reference secrets in bastion.yaml; resolve at runtime from env, Vault, AWS SM, etc.
Default provider is ``env`` (stdlib only). Cloud vaults ship as optional extras.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SecretsConfig:
    provider: str = "env"
    vault_path_prefix: str = "secret/mcp-bastion/"
    aws_region: str | None = None
    gcp_project: str | None = None

    @classmethod
    def from_config(cls, data: dict[str, Any] | None) -> SecretsConfig:
        if not data:
            return cls()
        return cls(
            provider=str(data.get("provider", "env")).strip().lower(),
            vault_path_prefix=str(data.get("vault_path_prefix", "secret/mcp-bastion/")),
            aws_region=data.get("aws_region"),
            gcp_project=data.get("gcp_project"),
        )


class SecretsResolver(ABC):
    @abstractmethod
    def resolve(self, ref: str) -> str:
        """Resolve secret reference to plaintext value."""

    @classmethod
    def from_config(cls, config: SecretsConfig) -> SecretsResolver:
        provider = config.provider
        if provider == "env":
            return EnvSecretsResolver()
        if provider in ("vault", "hashicorp_vault"):
            return VaultSecretsResolver(config)
        if provider in ("aws_sm", "aws", "aws_secrets_manager"):
            return AwsSecretsResolver(config)
        if provider in ("gcp_sm", "gcp", "gcp_secret_manager"):
            return GcpSecretsResolver(config)
        logger.warning("unknown secrets provider %r — falling back to env", provider)
        return EnvSecretsResolver()


class EnvSecretsResolver(SecretsResolver):
    """Resolve ``env:VAR_NAME`` or bare VAR_NAME from os.environ."""

    def resolve(self, ref: str) -> str:
        key = ref[4:] if ref.startswith("env:") else ref
        val = os.environ.get(key, "")
        if not val:
            raise KeyError(f"Secret not found in environment: {key}")
        return val


class VaultSecretsResolver(SecretsResolver):
    """HashiCorp Vault — requires optional ``hvac`` and ``VAULT_ADDR`` / ``VAULT_TOKEN``."""

    def __init__(self, config: SecretsConfig) -> None:
        self.config = config

    def resolve(self, ref: str) -> str:
        try:
            import hvac  # type: ignore[import-untyped]
        except ImportError as e:
            raise RuntimeError("pip install mcp-bastion-python[vault] for HashiCorp Vault") from e
        client = hvac.Client()
        path = ref if ref.startswith(self.config.vault_path_prefix) else f"{self.config.vault_path_prefix}{ref}"
        secret = client.secrets.kv.v2.read_secret_version(path=path)
        data = secret.get("data", {}).get("data", {})
        if not data:
            raise KeyError(f"empty vault secret at {path}")
        return str(next(iter(data.values())))


class AwsSecretsResolver(SecretsResolver):
    """AWS Secrets Manager — requires ``boto3``."""

    def __init__(self, config: SecretsConfig) -> None:
        self.config = config

    def resolve(self, ref: str) -> str:
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError as e:
            raise RuntimeError("pip install boto3 for AWS Secrets Manager") from e
        client = boto3.client("secretsmanager", region_name=self.config.aws_region)
        resp = client.get_secret_value(SecretId=ref)
        return str(resp.get("SecretString") or "")


class GcpSecretsResolver(SecretsResolver):
    """GCP Secret Manager — requires ``google-cloud-secret-manager``."""

    def __init__(self, config: SecretsConfig) -> None:
        self.config = config

    def resolve(self, ref: str) -> str:
        try:
            from google.cloud import secretmanager  # type: ignore[import-untyped]
        except ImportError as e:
            raise RuntimeError("pip install google-cloud-secret-manager for GCP SM") from e
        client = secretmanager.SecretManagerServiceClient()
        project = self.config.gcp_project or os.environ.get("GCP_PROJECT", "")
        name = f"projects/{project}/secrets/{ref}/versions/latest"
        resp = client.access_secret_version(request={"name": name})
        return resp.payload.data.decode("utf-8")
