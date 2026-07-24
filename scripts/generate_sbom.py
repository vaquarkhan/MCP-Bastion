#!/usr/bin/env python3
"""Generate a CycloneDX SBOM from pyproject.toml (stdlib only).

CRA / OpenSSF supply-chain transparency helper. Does not modify runtime
middleware, add package dependencies, or change publish semantics.

Usage:
  python scripts/generate_sbom.py
  python scripts/generate_sbom.py --pyproject pyproject.toml --output bom.json
  python scripts/generate_sbom.py --npm packages/core/package.json --output bom-npm.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


_DEP_NAME_RE = re.compile(
    r"""^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)""",
    re.VERBOSE,
)
_DEP_SPEC_RE = re.compile(
    r"""^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(?P<spec>[<>=!~].+)?$""",
)


def parse_pep508_name(req: str) -> str:
    """Return the distribution name from a PEP 508 requirement string."""
    text = (req or "").strip()
    if not text or text.startswith("#"):
        raise ValueError(f"empty dependency: {req!r}")
    # Strip environment markers and extras for naming: pkg[extra]>=1; python_version<"3.12"
    base = text.split(";", 1)[0].strip()
    base = re.sub(r"\[[^\]]*\]", "", base).strip()
    m = _DEP_NAME_RE.match(base)
    if not m:
        raise ValueError(f"cannot parse dependency name: {req!r}")
    return m.group("name")


def parse_pep508_spec(req: str) -> str | None:
    """Return version specifier text if present (best-effort)."""
    text = (req or "").strip().split(";", 1)[0].strip()
    text = re.sub(r"\[[^\]]*\]", "", text).strip()
    m = _DEP_SPEC_RE.match(text)
    if not m:
        return None
    spec = (m.group("spec") or "").strip()
    return spec or None


def _purl_pypi(name: str, version: str | None = None) -> str:
    n = name.lower().replace("_", "-")
    if version:
        return f"pkg:pypi/{n}@{version}"
    return f"pkg:pypi/{n}"


def _purl_npm(name: str, version: str | None = None) -> str:
    # Scoped packages: @scope/name -> pkg:npm/%40scope/name@version
    if name.startswith("@"):
        encoded = name.replace("@", "%40", 1)
        if version:
            return f"pkg:npm/{encoded}@{version}"
        return f"pkg:npm/{encoded}"
    if version:
        return f"pkg:npm/{name}@{version}"
    return f"pkg:npm/{name}"


def load_pyproject(path: Path) -> dict[str, Any]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"invalid pyproject: {path}")
    return data


def build_cyclonedx_from_pyproject(
    pyproject: dict[str, Any],
    *,
    tool_version: str = "1.0.0",
    serial: str | None = None,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 JSON document from a parsed pyproject.toml."""
    project = pyproject.get("project") or {}
    name = str(project.get("name") or "unknown")
    version = str(project.get("version") or "0.0.0")
    deps = list(project.get("dependencies") or [])

    ts = timestamp or datetime.now(timezone.utc)
    serial_number = serial or f"urn:uuid:{uuid.uuid4()}"
    root_ref = _purl_pypi(name, version)

    components: list[dict[str, Any]] = []
    dep_refs: list[str] = []
    for raw in deps:
        if not isinstance(raw, str):
            continue
        try:
            dep_name = parse_pep508_name(raw)
        except ValueError:
            continue
        spec = parse_pep508_spec(raw)
        ref = _purl_pypi(dep_name)
        dep_refs.append(ref)
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": ref,
            "name": dep_name,
            "purl": ref,
        }
        if spec:
            comp["properties"] = [{"name": "cdx:pip:requirement", "value": raw.strip()}]
        components.append(comp)

    # De-dupe by bom-ref while preserving order
    seen: set[str] = set()
    unique_components: list[dict[str, Any]] = []
    unique_refs: list[str] = []
    for c, ref in zip(components, dep_refs):
        if ref in seen:
            continue
        seen.add(ref)
        unique_components.append(c)
        unique_refs.append(ref)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "MCP-Bastion",
                    "name": "generate_sbom",
                    "version": tool_version,
                }
            ],
            "component": {
                "type": "library",
                "bom-ref": root_ref,
                "name": name,
                "version": version,
                "purl": root_ref,
            },
        },
        "components": unique_components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": unique_refs},
            *[{"ref": r, "dependsOn": []} for r in unique_refs],
        ],
    }


def build_cyclonedx_from_package_json(
    package: dict[str, Any],
    *,
    tool_version: str = "1.0.0",
    serial: str | None = None,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 JSON document from package.json dependencies."""
    name = str(package.get("name") or "unknown")
    version = str(package.get("version") or "0.0.0")
    deps = dict(package.get("dependencies") or {})

    ts = timestamp or datetime.now(timezone.utc)
    serial_number = serial or f"urn:uuid:{uuid.uuid4()}"
    root_ref = _purl_npm(name, version)

    components: list[dict[str, Any]] = []
    dep_refs: list[str] = []
    for dep_name, dep_ver in deps.items():
        ref = _purl_npm(str(dep_name))
        dep_refs.append(ref)
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": str(dep_name),
                "version": str(dep_ver),
                "purl": ref,
                "properties": [{"name": "cdx:npm:requirement", "value": str(dep_ver)}],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "MCP-Bastion",
                    "name": "generate_sbom",
                    "version": tool_version,
                }
            ],
            "component": {
                "type": "library",
                "bom-ref": root_ref,
                "name": name,
                "version": version,
                "purl": root_ref,
            },
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": dep_refs},
            *[{"ref": r, "dependsOn": []} for r in dep_refs],
        ],
    }


def write_bom(doc: dict[str, Any], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return output


def validate_bom_shape(doc: dict[str, Any]) -> list[str]:
    """Return a list of validation errors (empty if OK)."""
    errors: list[str] = []
    if doc.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be CycloneDX")
    if not str(doc.get("specVersion", "")).startswith("1."):
        errors.append("specVersion must be 1.x")
    meta = doc.get("metadata") or {}
    if not isinstance(meta, dict) or "component" not in meta:
        errors.append("metadata.component required")
    if not isinstance(doc.get("components"), list):
        errors.append("components must be a list")
    if not isinstance(doc.get("dependencies"), list):
        errors.append("dependencies must be a list")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate CycloneDX SBOM for MCP-Bastion")
    parser.add_argument(
        "--pyproject",
        type=Path,
        default=None,
        help="Path to pyproject.toml (default: repo root)",
    )
    parser.add_argument(
        "--npm",
        type=Path,
        default=None,
        help="Optional package.json path (generates npm SBOM instead of Python)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("bom.json"),
        help="Output CycloneDX JSON path (default: bom.json)",
    )
    parser.add_argument(
        "--serial",
        default=None,
        help="Optional fixed serialNumber (urn:uuid:...) for deterministic tests",
    )
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    try:
        if args.npm is not None:
            pkg_path = args.npm if args.npm.is_absolute() else root / args.npm
            package = json.loads(pkg_path.read_text(encoding="utf-8"))
            doc = build_cyclonedx_from_package_json(package, serial=args.serial)
        else:
            if args.pyproject is None:
                pp = root / "pyproject.toml"
            elif args.pyproject.is_absolute():
                pp = args.pyproject
            else:
                candid = Path.cwd() / args.pyproject
                pp = candid if candid.is_file() else (root / args.pyproject)
            pyproject = load_pyproject(pp)
            doc = build_cyclonedx_from_pyproject(pyproject, serial=args.serial)

        errs = validate_bom_shape(doc)
        if errs:
            for e in errs:
                print(f"error: {e}", file=sys.stderr)
            return 2

        out = args.output if args.output.is_absolute() else Path.cwd() / args.output
        write_bom(doc, out)
        print(f"Wrote CycloneDX SBOM: {out}")
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"generate_sbom failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
