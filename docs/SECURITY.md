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

The project does **not** implement authentication or transport-layer security (TLS); secure the transport (HTTPS, mTLS) and identity (e.g. API keys, OAuth) in your deployment.

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

## Reporting Vulnerabilities

If you find a security issue in MCP-Bastion, please report it privately (e.g. GitHub Security Advisories or a contact listed in the repository) rather than opening a public issue.
