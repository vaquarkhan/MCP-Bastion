"""
Optional external policy engines: Open Policy Agent (Rego) or AWS Cedar (CLI).

When fail_closed is true (default), missing binaries or policy paths return DENY.
When fail_closed is false, engine errors or misconfiguration fail open (ALLOW).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)

EngineType = Literal["none", "opa", "cedar"]

# Cedar CLI exits 0 for ALLOW and typically 2 for DENY; decide from stdout first.
_CEDAR_ACTION = 'Action::"invoke"'


def normalize_engine(value: str | None) -> EngineType:
    x = (value or "none").lower().strip()
    if x in ("none", "opa", "cedar"):
        return x  # type: ignore[return-value]
    return "none"


def _cedar_escape_id(raw: Any) -> str:
    """Escape a value for use inside a Cedar entity UID string literal."""
    s = str(raw if raw is not None else "anonymous")
    s = "".join(ch if ch.isprintable() and ch not in "\n\r\t" else "_" for ch in s)
    return s.replace("\\", "\\\\").replace('"', '\\"') or "anonymous"


def _cedar_uid(type_name: str, entity_id: str) -> str:
    return f'{type_name}::"{entity_id}"'


@dataclass
class ExternalPolicyConfig:
    engine: EngineType = "none"
    opa_binary: str = "opa"
    opa_policy_dir: str | None = None  # directory passed as -d
    opa_query: str = "data.bastion.allow"
    cedar_binary: str = "cedar"
    cedar_policies_dir: str | None = None
    cedar_schema_path: str | None = None
    cedar_entities_path: str | None = None
    fail_closed: bool = True


class ExternalPolicyEvaluator:
    """Evaluate MCP request context via OPA or Cedar when configured."""

    def __init__(self, cfg: ExternalPolicyConfig) -> None:
        self._cfg = cfg

    @staticmethod
    def from_env() -> ExternalPolicyEvaluator:
        eng = normalize_engine(os.environ.get("BASTION_POLICY_ENGINE", "none"))
        fail_closed = os.environ.get("BASTION_POLICY_FAIL_CLOSED", "").lower() in ("1", "true", "yes")
        return ExternalPolicyEvaluator(
            ExternalPolicyConfig(
                engine=eng,
                opa_binary=os.environ.get("BASTION_OPA_BINARY", "opa"),
                opa_policy_dir=os.environ.get("BASTION_OPA_POLICY_DIR"),
                opa_query=os.environ.get("BASTION_OPA_QUERY", "data.bastion.allow"),
                cedar_binary=os.environ.get("BASTION_CEDAR_BINARY", "cedar"),
                cedar_policies_dir=os.environ.get("BASTION_CEDAR_POLICIES_DIR"),
                cedar_schema_path=os.environ.get("BASTION_CEDAR_SCHEMA"),
                cedar_entities_path=os.environ.get("BASTION_CEDAR_ENTITIES"),
                fail_closed=fail_closed,
            )
        )

    def _on_unavailable(self, detail: str) -> tuple[bool, str | None]:
        msg = f"external_policy: {detail}"
        if self._cfg.fail_closed:
            logger.warning("%s (fail_closed=True, denying request)", detail)
            return False, msg
        logger.debug("%s; skipping external policy (fail_open)", detail)
        return True, None

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
            return self._on_unavailable("OPA policy dir missing or not a directory")
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(input_obj, f)
                in_path = f.name
            try:
                # OPA 1.x accepts: json|values|bindings|pretty|source|raw|discard
                # Use "raw" for a bare true/false line (not the invalid singular "value").
                proc = subprocess.run(
                    [
                        opa,
                        "eval",
                        "-f",
                        "raw",
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
                detail = (proc.stderr or proc.stdout or "OPA eval failed").strip()
                return self._on_unavailable(f"OPA eval failed: {detail}")
            out = proc.stdout.strip().lower()
            allowed = out in ("true", "1", "yes")
            return allowed, None if allowed else "external_policy: OPA denied"
        except subprocess.TimeoutExpired:
            return self._on_unavailable("OPA eval timed out")
        except FileNotFoundError:
            return self._on_unavailable(f"OPA binary not found: {self._cfg.opa_binary!r}")
        except OSError as e:
            return self._on_unavailable(f"OPA eval error: {e}")

    @staticmethod
    def _load_cedar_entities(path: str | None) -> list[dict[str, Any]]:
        if not path or not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [e for e in data if isinstance(e, dict)]
        if isinstance(data, dict) and isinstance(data.get("entities"), list):
            return [e for e in data["entities"] if isinstance(e, dict)]
        return []

    @staticmethod
    def _entity_key(entity: dict[str, Any]) -> tuple[str, str] | None:
        uid = entity.get("uid")
        if isinstance(uid, dict):
            t, i = uid.get("type"), uid.get("id")
            if isinstance(t, str) and isinstance(i, str):
                return t, i
        return None

    @classmethod
    def _merge_request_entities(
        cls,
        base: list[dict[str, Any]],
        *,
        principal_id: str,
        tool_id: str,
    ) -> list[dict[str, Any]]:
        needed = [
            {"uid": {"type": "User", "id": principal_id}, "attrs": {}, "parents": []},
            {"uid": {"type": "Action", "id": "invoke"}, "attrs": {}, "parents": []},
            {"uid": {"type": "Tool", "id": tool_id}, "attrs": {}, "parents": []},
        ]
        existing = {cls._entity_key(e) for e in base}
        existing.discard(None)
        out = list(base)
        for ent in needed:
            key = cls._entity_key(ent)
            if key not in existing:
                out.append(ent)
                existing.add(key)
        return out

    def _resolve_cedar_policies_file(self, pol_path: Path) -> tuple[str, str | None]:
        """Return (policies_file, temp_to_delete_or_None). Cedar CLI requires a file, not a dir."""
        if pol_path.is_file():
            return str(pol_path), None
        cedar_files = sorted(pol_path.glob("*.cedar"))
        if not cedar_files:
            raise FileNotFoundError(f"no *.cedar files in {pol_path}")
        if len(cedar_files) == 1:
            return str(cedar_files[0]), None
        combined = tempfile.NamedTemporaryFile("w", suffix=".cedar", delete=False, encoding="utf-8")
        try:
            for cf in cedar_files:
                combined.write(cf.read_text(encoding="utf-8"))
                combined.write("\n")
        finally:
            combined.close()
        return combined.name, combined.name

    def _eval_cedar(self, input_obj: dict[str, Any]) -> tuple[bool, str | None]:
        """Cedar CLI authorize with --policies, --entities, and principal/action/resource."""
        cedar = shutil.which(self._cfg.cedar_binary) or self._cfg.cedar_binary
        pol_raw = self._cfg.cedar_policies_dir
        if not pol_raw:
            return self._on_unavailable("Cedar policies dir missing or not a directory")
        pol_path = Path(pol_raw)
        if not pol_path.exists() or not (pol_path.is_dir() or pol_path.is_file()):
            return self._on_unavailable("Cedar policies dir missing or not a directory")

        tool_id = _cedar_escape_id(input_obj.get("tool") or "unknown")
        principal_id = _cedar_escape_id(
            input_obj.get("principal") or input_obj.get("session_id") or "anonymous"
        )
        principal = _cedar_uid("User", principal_id)
        resource = _cedar_uid("Tool", tool_id)

        entities_src = self._cfg.cedar_entities_path
        if not entities_src and pol_path.is_dir():
            candidate = pol_path / "entities.json"
            if candidate.is_file():
                entities_src = str(candidate)
        try:
            entities = self._merge_request_entities(
                self._load_cedar_entities(entities_src),
                principal_id=principal_id,
                tool_id=tool_id,
            )
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
            return self._on_unavailable(f"Cedar entities invalid: {e}")

        policies_tmp: str | None = None
        entities_tmp: str | None = None
        try:
            try:
                policies_file, policies_tmp = self._resolve_cedar_policies_file(pol_path)
            except FileNotFoundError as e:
                return self._on_unavailable(str(e))

            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as ef:
                json.dump(entities, ef)
                entities_tmp = ef.name

            cmd = [
                cedar,
                "authorize",
                "--policies",
                policies_file,
                "--entities",
                entities_tmp,
                "--principal",
                principal,
                "--action",
                _CEDAR_ACTION,
                "--resource",
                resource,
            ]
            if self._cfg.cedar_schema_path and os.path.isfile(self._cfg.cedar_schema_path):
                cmd.extend(["--schema", self._cfg.cedar_schema_path])

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            # Decision is in stdout; DENY often uses exit code 2 — do not treat as engine failure.
            decision = (proc.stdout or "").strip().upper()
            if "ALLOW" in decision:
                return True, None
            if "DENY" in decision:
                return False, "external_policy: Cedar denied"
            detail = (proc.stderr or proc.stdout or "Cedar authorize failed").strip()
            if proc.returncode != 0:
                return self._on_unavailable(f"Cedar authorize failed: {detail}")
            return self._on_unavailable(f"Cedar authorize returned unrecognized output: {proc.stdout!r}")
        except subprocess.TimeoutExpired:
            return self._on_unavailable("Cedar authorize timed out")
        except FileNotFoundError:
            return self._on_unavailable(f"Cedar binary not found: {self._cfg.cedar_binary!r}")
        except OSError as e:
            return self._on_unavailable(f"Cedar authorize error: {e}")
        finally:
            for path in (policies_tmp, entities_tmp):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
