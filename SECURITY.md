# Security Policy

MCP-Bastion is security middleware for Model Context Protocol (MCP) servers. We take vulnerability reports seriously and ask that you disclose them privately before opening a public issue or pull request.

## Supported versions

Security fixes are applied to the **latest release** (**3.3.0** on [PyPI](https://pypi.org/project/mcp-bastion-python/3.3.0/) and [GHCR Docker `v3.3.0`](https://github.com/vaquarkhan/MCP-Bastion/pkgs/container/mcp-bastion-proxy); npm `@mcp-bastion/core` after bootstrap - see [docs/PUBLISHING_NPM_AND_REGISTRY.md](docs/PUBLISHING_NPM_AND_REGISTRY.md)). Upgrade to the current tag (see [CHANGELOG.md](CHANGELOG.md)) when a fix is announced.

| Version | Supported |
|---------|-----------|
| Latest release (`main` / current tag) | Yes |
| Older releases | Best effort; upgrade recommended |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use one of these private channels:

1. **GitHub Private Security Advisory (preferred)**  -  [Report a vulnerability](https://github.com/vaquarkhan/MCP-Bastion/security/advisories/new) on this repository. GitHub keeps the report private until we publish a coordinated advisory.
2. **Repository maintainer**  -  If you cannot use GitHub advisories, contact the maintainer via the profile linked from [github.com/vaquarkhan](https://github.com/vaquarkhan) and include **“MCP-Bastion security”** in the subject or message.

Include as much detail as you can: affected version, reproduction steps, impact, and any proof-of-concept. We aim to acknowledge reports within **5 business days** and will work with you on disclosure timing.

## European Cyber Resilience Act (CRA) Compliance & Article 14 Reporting

MCP-Bastion maintainers treat CRA **Article 14** (actively exploited vulnerability reporting) as an operational obligation for software already in the market. This section is OpenSSF-style **minimum viable documentation** for an open-source steward; it does **not** claim CE marking for downstream Products with Digital Elements that embed Bastion.

| Topic | Policy |
|-------|--------|
| **Acknowledgement SLA** | Initial response within **48 hours** for private advisory / maintainer reports (triage may continue beyond acknowledgement). |
| **Supported channel** | [GitHub Private Security Advisory](https://github.com/vaquarkhan/MCP-Bastion/security/advisories/new) (preferred). Optional direct contact: `[SECURITY_CONTACT_EMAIL]` (maintainers populate; do not invent addresses). |
| **Critical escalation** | Issues with **CVSS >= 9.0**, confirmed **middleware bypasses** (e.g. RBAC / PromptGuard / PII path), or **known active exploitation** are escalated by maintainers for coordination with the **ENISA Single Reporting Platform (SRP)** and relevant national CSIRTs when CRA reporting duties apply. |
| **Timeline awareness** | Article 14 reporting obligations apply from **11 September 2026** (including products already on the market under CRA transitional rules). Full CRA conformity assessment timing for manufacturers: **11 December 2027**. |

### Supply chain transparency

Release workflows attach **CycloneDX** Software Bills of Materials:

- `bom.json` - Python package declared dependencies from `pyproject.toml`
- `bom-npm.json` - `@mcp-bastion/core` dependencies from `packages/core/package.json`

Generate locally with `python scripts/generate_sbom.py` (see [docs/CRA_SBOM_TUTORIAL.md](docs/CRA_SBOM_TUTORIAL.md)). Artifacts are uploaded from `publish-mcp.yml` and `publish-docker.yml` (fail-safe; publish is never blocked by SBOM failure). Overview: [docs/CRA_COMPLIANCE.md](docs/CRA_COMPLIANCE.md).

## What to expect

- Confirmation of receipt and initial triage
- A fix or mitigation plan on a supported release line
- Credit in the advisory or release notes (unless you prefer to remain anonymous)
- For CRA-relevant criticals: maintainer-led ENISA / CSIRT coordination as required

## Product security documentation

For OWASP-relevant controls, production hardening, dependency notes, and supply-chain provenance, see:

- [docs/SECURITY.md](docs/SECURITY.md) - mitigations and operational guidance
- [docs/SECURITY_OBSERVABILITY.md](docs/SECURITY_OBSERVABILITY.md) - OWASP MCP Top 10, SIEM / fleet rollout
- [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) - CI, provenance, and release boundaries
- [docs/CRA_COMPLIANCE.md](docs/CRA_COMPLIANCE.md) - CRA / OpenSSF posture and SBOM
