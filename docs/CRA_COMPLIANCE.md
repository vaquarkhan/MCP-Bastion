# CRA compliance posture (MCP-Bastion)

How MCP-Bastion supports **European Cyber Resilience Act (CRA)** / OpenSSF "minimum viable documentation" for open-source stewards - **without** changing the zero-infra middleware nature of the product.

> Scope: Bastion is **security middleware / a library**, not a finished consumer PDE. Downstream manufacturers that ship MCP servers into the EU market remain responsible for CE marking and full Technical Documentation. Bastion supplies **machine-readable supply-chain signals** and **runtime Annex I-aligned controls** they can inherit.

## What is already in place

| CRA theme | Bastion capability |
|-----------|-------------------|
| Security by design (Annex I) | Local PromptGuard, PII redaction, RBAC, rate/cost limits, schema validation, behavioral fingerprinting (opt-in) |
| Machine-readable evidence | OpenTelemetry, Prometheus, audit JSONL, `mcp-bastion attest export`, dashboard compliance report |
| Vulnerability handling | Root [SECURITY.md](../SECURITY.md) + GitHub Private Security Advisories |
| Release provenance | PyPI OIDC Trusted Publishing, npm `--provenance` ([SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)) |
| **SBOM** | CycloneDX via `scripts/generate_sbom.py` on release workflows (artifacts `bom.json` / `bom-npm.json`) |

## Diagram

![CRA / SBOM release flow](../images/mcp-bastion-cra-sbom.svg)

## Article 14 (reporting)

See the **European Cyber Resilience Act (CRA) Compliance & Article 14 Reporting** section in [SECURITY.md](../SECURITY.md). Critical actively exploited issues are coordinated by maintainers toward the ENISA Single Reporting Platform (SRP) when applicable.

## Generate an SBOM locally

```bash
# Python wheel / library SBOM (declared deps from pyproject.toml)
python scripts/generate_sbom.py --output bom.json

# TypeScript package SBOM
python scripts/generate_sbom.py --npm packages/core/package.json --output bom-npm.json
```

No new runtime dependency is added to `mcp-bastion-python`. CI uploads the JSON as a GitHub Actions artifact on publish workflows (fail-safe: SBOM failure does not block PyPI/Docker publish).

## Tutorial

Step-by-step: [CRA_SBOM_TUTORIAL.md](CRA_SBOM_TUTORIAL.md)

## Non-goals (preserve project nature)

- No changes to PromptGuard, Presidio, rate limiters, or JSON-RPC interception paths for "CRA features"
- No mandatory CE-marking UI or Annex I auto-mapper over `bastion.yaml` (manufacturer documentation)
- No new required PyPI dependencies for SBOM generation

## Related

- [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) - release provenance
- [SECURITY.md](SECURITY.md) - OWASP mitigations
- [../SECURITY.md](../SECURITY.md) - vulnerability disclosure policy
- [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md) - attestation moat
