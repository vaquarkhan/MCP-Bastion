"""
Optional external policy engines: Open Policy Agent (Rego) or AWS Cedar (CLI).

Falls back to disabled if binaries or policy paths are missing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Literal

logger = logging.getLogger(__name__)

EngineType = Literal["none", "opa", "cedar"]


def normalize_engine(value: str | None) -> EngineType:
    x = (value or "none").lower().strip()
    if x in ("none", "opa", "cedar"):
        return x  # type: ignore[return-value]
    return "none"


@dataclass
class ExternalPolicyConfig:
    engine: EngineType = "none"
    opa_binary: str = "opa"
    opa_policy_dir: str | None = None  # directory passed as -d
    opa_query: str = "data.bastion.allow"
    cedar_binary: str = "cedar"
    cedar_policies_dir: str | None = None
    cedar_schema_path: str | None = None


class ExternalPolicyEvaluator:
    """Evaluate MCP request context via OPA or Cedar when configured."""

    def __init__(self, cfg: ExternalPolicyConfig) -> None:
        self._cfg = cfg

    @staticmethod
    def from_env() -> ExternalPolicyEvaluator:
        eng = normalize_engine(os.environ.get("BASTION_POLICY_ENGINE", "none"))
        return ExternalPolicyEvaluator(
            ExternalPolicyConfig(
                engine=eng,
                opa_binary=os.environ.get("BASTION_OPA_BINARY", "opa"),
                opa_policy_dir=os.environ.get("BASTION_OPA_POLICY_DIR"),
                opa_query=os.environ.get("BASTION_OPA_QUERY", "data.bastion.allow"),
                cedar_binary=os.environ.get("BASTION_CEDAR_BINARY", "cedar"),
                cedar_policies_dir=os.environ.get("BASTION_CEDAR_POLICIES_DIR"),
                cedar_schema_path=os.environ.get("BASTION_CEDAR_SCHEMA"),
            )
        )

    def evaluate(self, input_obj: dict[str, Any]) -> tuple[bool, str | None]:
        if self._cfg.engine == "none":
            return True, None
        if self._cfg.engine == "opa":
            return self._eval_opa(input_obj)
        if self._cfg.engine == "cedar":
            return self._eval_cedar(input_obj)
        return True, None

    def _eval_opa(self, input_obj: dict[str, Any]) -> tuple[bool, str | None]:
        opa = shutil.which(self._cfg.opa_binary) or self._cfg.opa_binary
        policy_dir = self._cfg.opa_policy_dir
        if not policy_dir or not os.path.isdir(policy_dir):
            logger.debug("OPA policy dir missing; skipping external policy")
            return True, None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(input_obj, f)
                in_path = f.name
            try:
                proc = subprocess.run(
                    [
                        opa,
                        "eval",
                        "-f",
                        "value",
                        "-d",
                        policy_dir,
                        "-i",
                        in_path,
                        self._cfg.opa_query,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            finally:
                try:
                    os.unlink(in_path)
                except OSError:
                    pass
            if proc.returncode != 0:
                logger.warning("OPA eval failed: %s", proc.stderr or proc.stdout)
                return True, None
            out = proc.stdout.strip().lower()
            allowed = out in ("true", "1", "yes")
            return allowed, None if allowed else "external_policy: OPA denied"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("OPA eval error: %s", e)
            return True, None

    def _eval_cedar(self, input_obj: dict[str, Any]) -> tuple[bool, str | None]:
        """Cedar CLI evaluation (optional); requires cedar binary and policy dir."""
        cedar = shutil.which(self._cfg.cedar_binary) or self._cfg.cedar_binary
        pol_dir = self._cfg.cedar_policies_dir
        if not pol_dir or not os.path.isdir(pol_dir):
            logger.debug("Cedar policies dir missing; skipping")
            return True, None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump({"context": input_obj}, f)
                in_path = f.name
            try:
                cmd = [cedar, "evaluate", "--policies", pol_dir, "--request", in_path]
                if self._cfg.cedar_schema_path and os.path.isfile(self._cfg.cedar_schema_path):
                    cmd.extend(["--schema", self._cfg.cedar_schema_path])
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            finally:
                try:
                    os.unlink(in_path)
                except OSError:
                    pass
            if proc.returncode != 0:
                logger.warning("Cedar evaluate failed: %s", proc.stderr or proc.stdout)
                return True, None
            # Heuristic: look for DENY / PERMIT in output
            combined = (proc.stdout + proc.stderr).upper()
            if "DENY" in combined and "PERMIT" not in combined:
                return False, "external_policy: Cedar denied"
            return True, None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("Cedar eval error: %s", e)
            return True, None
