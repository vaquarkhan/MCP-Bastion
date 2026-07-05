# Security Policy

MCP-Bastion is security middleware for Model Context Protocol (MCP) servers. We take vulnerability reports seriously and ask that you disclose them privately before opening a public issue or pull request.

## Supported versions

Security fixes are applied to the **latest release** on [PyPI](https://pypi.org/project/mcp-bastion-python/) and [npm](https://www.npmjs.com/package/@mcp-bastion/core). Upgrade to the current tag (see [CHANGELOG.md](CHANGELOG.md)) when a fix is announced.

| Version | Supported |
|---------|-----------|
| Latest release (`main` / current tag) | Yes |
| Older releases | Best effort; upgrade recommended |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use one of these private channels:

1. **GitHub Private Security Advisory (preferred)** — [Report a vulnerability](https://github.com/vaquarkhan/MCP-Bastion/security/advisories/new) on this repository. GitHub keeps the report private until we publish a coordinated advisory.
2. **Repository maintainer** — If you cannot use GitHub advisories, contact the maintainer via the profile linked from [github.com/vaquarkhan](https://github.com/vaquarkhan) and include **“MCP-Bastion security”** in the subject or message.

Include as much detail as you can: affected version, reproduction steps, impact, and any proof-of-concept. We aim to acknowledge reports within **5 business days** and will work with you on disclosure timing.

## What to expect

- Confirmation of receipt and initial triage
- A fix or mitigation plan on a supported release line
- Credit in the advisory or release notes (unless you prefer to remain anonymous)

## Product security documentation

For OWASP-relevant controls, production hardening, dependency notes, and supply-chain provenance, see:

- [docs/SECURITY.md](docs/SECURITY.md) — mitigations and operational guidance
- [docs/SECURITY_OBSERVABILITY.md](docs/SECURITY_OBSERVABILITY.md) — OWASP MCP Top 10, SIEM / fleet rollout
- [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) — CI, provenance, and release boundaries
