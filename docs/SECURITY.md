# Security and OWASP

## How MCP-Bastion Addresses Security (OWASP-Relevant)

MCP-Bastion mitigates several categories that align with OWASP Top 10 and LLM-specific risks:

| Risk / OWASP-relevant | MCP-Bastion mitigation |
|-----------------------|-------------------------|
| **A03:2021 – Injection** | Prompt injection defense via Meta PromptGuard; content filter blocks path/code injection and suspicious patterns. |
| **Sensitive data exposure** | PII redaction (Presidio) for SSN, email, phone, etc. before data reaches LLM or clients. |
| **A04:2021 – Insecure design / resource exhaustion** | Rate limiting (iterations, timeout, token budget), circuit breaker, cost tracker to prevent denial-of-wallet and runaway agents. |
| **A01:2021 – Broken access control** | RBAC pillar for tool-level permissions by role. |
| **Replay / integrity** | Replay guard (nonce) to block duplicate requests. |
| **Input validation** | Schema validation for tool inputs; audit logging for who/what/when. |

**Layer with platform security:** terminate **TLS** at your load balancer or API gateway, authenticate callers with your **identity provider** (API keys, OAuth/OIDC, mTLS—whatever your platform standard is), and run MCP-Bastion on the MCP tool path **inside** a least-privilege service account. That pairing is how teams run MCP-Bastion in **production** today.

---

## Production readiness and defense in depth

MCP-Bastion is intended for **production** when operated like other security-sensitive components:

- **Policy as trusted configuration** — treat `bastion.yaml` like code: version it, review changes, and run **`mcp-bastion validate`** in CI ([examples/ci/README.md](examples/ci/README.md)).
- **Alert destinations you trust** — point Slack and HTTP webhooks at endpoints **you** control or have approved for egress.
- **Dependencies and builds** — keep packages updated; Python releases are built in GitHub Actions with **high test coverage** on the core package; see [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) for publish and provenance details.
- **Monitoring** — use the dashboard, **`/api/metrics`**, **Prometheus**, and optional **OpenTelemetry** so blocks and policy hits are visible to your SOC.

The middleware runs **in-process with your MCP server**, using the same deployment unit and monitoring you already use for that service—so policy upgrades ship with your normal release process.

---

## Dependency Vulnerabilities (npm)

`npm audit` in `packages/core` may report **moderate** issues in **devDependencies** (e.g. esbuild/vite/vitest). These affect only build and test tooling, not the published runtime (`@mcp-bastion/core` depends only on `@modelcontextprotocol/sdk` at runtime).

**To review and fix:**

```bash
cd packages/core
npm audit
npm audit fix          # Apply non-breaking fixes
# npm audit fix --force # Only if you accept breaking upgrades (e.g. vite 7)
```

**To address all (may require major upgrades):**

```bash
cd packages/core
npm audit fix --force
npm run build
npm run test
```

If you pin or upgrade `vite` / `vitest` to patched versions when available, re-run `npm audit` to confirm.

---

## Supply chain and release provenance

Releases are automated in GitHub Actions; **npm** uses **`npm publish --provenance`** and **PyPI** uses **OIDC Trusted Publishing**. See [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) for a concise map of workflows, provenance, and scope boundaries—useful for security questionnaires and release notes.

## Reporting Vulnerabilities

If you find a security issue in MCP-Bastion, **do not open a public GitHub issue**.

Report privately via:

- **[GitHub Private Security Advisory](https://github.com/vaquarkhan/MCP-Bastion/security/advisories/new)** (preferred), or
- The maintainer contact described in the root **[SECURITY.md](../SECURITY.md)** policy.

We aim to acknowledge reports within **5 business days**.
