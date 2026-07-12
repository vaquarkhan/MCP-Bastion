"""
PMD/Sonar-style issue guides for scan + runtime findings.

Bundled locally (zero-infra): no cloud calls. External URLs are optional
references the user may open in a browser.
"""

from __future__ import annotations

from typing import Any

from mcp_bastion.taxonomy import (
    ASI_TITLES,
    LLM_TITLES,
    MCP_TITLES,
    TAXONOMY,
    tags_for_check,
)

# Framework-level cards (OWASP ASI / MCP / LLM).
FRAMEWORK_GUIDES: dict[str, dict[str, Any]] = {
    "ASI01": {
        "summary": "Attackers hijack agent goals via injected instructions in tools, prompts, or retrieved content.",
        "why": "A goal hijack turns a helpful agent into an attacker-controlled operator without changing your code.",
        "fix": [
            "Enable prompt_guard and semantic_firewall on tools/call and prompts/get.",
            "Prefer allowlists for high-risk tools; never expose shell/admin tools to untrusted agents.",
            "Run mcp-bastion scan for injection_heuristic / hidden_unicode findings before deploy.",
        ],
        "bastion": ["prompt_guard", "semantic_firewall", "content_filter", "agent_iam"],
        "refs": [
            {
                "title": "OWASP Top 10 for Agentic Applications — ASI01",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "ASI02": {
        "summary": "Agents misuse tools or parameters beyond intended scope (over-broad schemas, optional dangerous args).",
        "why": "Weak tool contracts enable path traversal, code execution, or data exfil through 'legitimate' tool calls.",
        "fix": [
            "Tighten inputSchema: required fields, enums, maxLength, pattern constraints.",
            "Enable schema_validation and argument_guards in bastion.yaml.",
            "Use agent_iam allowed_tools / blocked_tools per agent identity.",
        ],
        "bastion": ["schema_validation", "argument_guards", "agent_iam", "rbac", "content_filter"],
        "refs": [
            {
                "title": "OWASP Agentic Top 10 — ASI02 Tool Misuse",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "ASI03": {
        "summary": "Privilege abuse / confused deputy: a low-priv agent reaches admin tools via shared MCP identity.",
        "why": "Without per-agent IAM, every client inherits the server's full tool surface.",
        "fix": [
            "Enable agent_iam with distinct tokens and per-agent allow/deny tool lists.",
            "Remove standing credentials from client mcp.json (mcp-bastion audit).",
            "Require authenticated identity for RBAC.",
        ],
        "bastion": ["agent_iam", "rbac", "edge_auth"],
        "refs": [
            {
                "title": "OWASP Agentic Top 10 — ASI03 Identity and Privilege Abuse",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "ASI04": {
        "summary": "Supply-chain risk: poisoned tools, typoquat servers, fingerprint drift, unsigned artifacts.",
        "why": "MCP servers are often pulled from registries; drift or lookalike names bypass human review.",
        "fix": [
            "Enable server_verification with a signed manifest of trusted checksums.",
            "Enable tool_metadata_fingerprint / tool_metadata_guard.",
            "Run mcp-bastion scan for homoglyph / empty_description / fingerprint_drift.",
        ],
        "bastion": ["server_verification", "tool_metadata_fingerprint", "tool_metadata_guard"],
        "refs": [
            {
                "title": "OWASP Agentic Top 10 — ASI04 Supply Chain",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "ASI05": {
        "summary": "Unexpected code execution via shell launchers, eval-like tools, or unconstrained paths.",
        "why": "One unsafe tool turns the MCP host into a remote code execution surface.",
        "fix": [
            "Block shell/filesystem tools for non-admin agents; enable content_filter path/code rules.",
            "Prefer sandboxed runtimes; deny risky_arg_optional patterns in scan.",
            "Use stdio_guard when spawning MCP over stdio.",
        ],
        "bastion": ["content_filter", "stdio_guard", "argument_guards", "agent_iam"],
        "refs": [
            {
                "title": "OWASP Agentic Top 10 — ASI05 Unexpected Code Execution",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "ASI06": {
        "summary": "Memory/context poisoning: malicious content persists across turns and steers later actions.",
        "why": "Poisoned context survives after the original request and is hard to attribute.",
        "fix": [
            "Enable PII redaction and semantic_firewall on responses.",
            "Limit session tool scope; rotate canaries on detection.",
            "Scan/redact retrieved documents before they enter agent memory.",
        ],
        "bastion": ["pii", "semantic_firewall", "canary_goallock", "sensitive_classifier"],
        "refs": [
            {
                "title": "OWASP Agentic Top 10 — ASI06 Memory and Context Poisoning",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "ASI07": {
        "summary": "Insecure inter-agent communication: missing auth, replay, or transport hardening.",
        "why": "Browser-origin or cross-host calls can forge agent actions against loopback MCP servers.",
        "fix": [
            "Enable transport_hardening (loopback + Origin checks).",
            "Enable replay_guard and edge_auth where applicable.",
            "Isolate agent sessions with agent_iam.isolate_sessions.",
        ],
        "bastion": ["transport_hardening", "replay_guard", "edge_auth", "agent_iam"],
        "refs": [
            {
                "title": "OWASP Agentic Top 10 — ASI07 Inter-Agent Communication",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "ASI08": {
        "summary": "Cascading failures from rate storms, retries, or upstream outages amplified by agents.",
        "why": "Autonomous retries can DoS your own backends and burn token budget.",
        "fix": [
            "Enable rate_limit and circuit_breaker with sensible budgets.",
            "Cap cost_tracker session/day spend.",
            "Tune auto_repave thresholds for containment.",
        ],
        "bastion": ["rate_limit", "circuit_breaker", "cost_tracker", "auto_repave"],
        "refs": [
            {
                "title": "OWASP Agentic Top 10 — ASI08 Cascading Failures",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "ASI09": {
        "summary": "Human-agent trust exploitation: social engineering through agent UI or canary leakage.",
        "why": "Users over-trust agent output; canaries detect silent exfil of privileged context.",
        "fix": [
            "Enable canary_goallock; rotate on detection.",
            "Audit high-risk tools; require human confirmation for destructive actions outside Bastion.",
        ],
        "bastion": ["canary_goallock", "audit", "prompt_guard"],
        "refs": [
            {
                "title": "OWASP Agentic Top 10 — ASI09 Human-Agent Trust",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "ASI10": {
        "summary": "Rogue agents: unauthorized or over-privileged agents operating outside policy.",
        "why": "Shadow agents or stolen tokens expand blast radius across the MCP surface.",
        "fix": [
            "Require agent_iam tokens; deny unknown agents.",
            "Use tool_allowlist and session_max_unique_tools.",
            "Monitor denied-by-agent on the dashboard.",
        ],
        "bastion": ["agent_iam", "tool_allowlist", "auto_repave"],
        "refs": [
            {
                "title": "OWASP Agentic Top 10 — ASI10 Rogue Agents",
                "url": "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/",
            }
        ],
    },
    "LLM01": {
        "summary": "Prompt injection: untrusted text overrides system/developer intent.",
        "why": "Classic LLM Top 10 entry; still the #1 agent breakout technique.",
        "fix": ["Enable prompt_guard", "Sanitize tool outputs before re-prompting", "Prefer structured tool I/O over free text"],
        "bastion": ["prompt_guard", "semantic_firewall"],
        "refs": [{"title": "OWASP LLM Top 10 — LLM01", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"}],
    },
    "LLM02": {
        "summary": "Sensitive information disclosure via model outputs or tool responses.",
        "why": "PII and secrets in context become training/leak surfaces.",
        "fix": ["Enable pii redaction", "secrets.redact_patterns", "response_scan where needed"],
        "bastion": ["pii", "secrets"],
        "refs": [{"title": "OWASP LLM Top 10 — LLM02", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"}],
    },
    "LLM03": {
        "summary": "Supply-chain weaknesses in models, plugins, or MCP packages.",
        "fix": ["server_verification", "osv-scan in CI", "pin versions"],
        "bastion": ["server_verification"],
        "refs": [{"title": "OWASP LLM Top 10 — LLM03", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"}],
    },
    "LLM06": {
        "summary": "Excessive agency: model granted tools beyond the task.",
        "fix": ["agent_iam allowlists", "rbac", "discovery_filter"],
        "bastion": ["agent_iam", "rbac", "discovery_filter"],
        "refs": [{"title": "OWASP LLM Top 10 — LLM06", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"}],
    },
    "LLM10": {
        "summary": "Unbounded consumption: token/cost/rate exhaustion.",
        "fix": ["rate_limit", "cost_tracker", "output_budget"],
        "bastion": ["rate_limit", "cost_tracker", "output_budget"],
        "refs": [{"title": "OWASP LLM Top 10 — LLM10", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"}],
    },
    "MCP01": {
        "summary": "Token/secret exposure through MCP configs or tool outputs.",
        "fix": ["Remove standing secrets from mcp.json", "pii + secret redaction", "mcp-bastion audit"],
        "bastion": ["pii", "secrets"],
        "refs": [{"title": "OWASP MCP Top 10", "url": "https://owasp.org/www-project-mcp-top-10/"}],
    },
    "MCP02": {
        "summary": "Filesystem / privilege abuse via MCP tools.",
        "fix": ["content_filter path rules", "agent_iam", "filesystem guard examples"],
        "bastion": ["content_filter", "agent_iam"],
        "refs": [{"title": "OWASP MCP Top 10", "url": "https://owasp.org/www-project-mcp-top-10/"}],
    },
    "MCP03": {
        "summary": "Tool poisoning / shadow tools (lookalike names, empty descriptions).",
        "fix": ["mcp-bastion scan homoglyph/empty_description", "tool_metadata_guard"],
        "bastion": ["tool_metadata_guard", "tool_metadata_fingerprint"],
        "refs": [{"title": "OWASP MCP Top 10", "url": "https://owasp.org/www-project-mcp-top-10/"}],
    },
    "MCP05": {
        "summary": "Unsafe tool execution surface (weak schemas, shell launchers).",
        "fix": ["schema_validation", "argument_guards", "scan weak_schema / shell_launcher"],
        "bastion": ["schema_validation", "argument_guards", "content_filter"],
        "refs": [{"title": "OWASP MCP Top 10", "url": "https://owasp.org/www-project-mcp-top-10/"}],
    },
    "MCP06": {
        "summary": "Over-permissioned tool grants to agents or skills.",
        "fix": ["Narrow allowed_tools", "skill scan over_broad_grant", "agent_iam"],
        "bastion": ["agent_iam", "rbac"],
        "refs": [{"title": "OWASP MCP Top 10", "url": "https://owasp.org/www-project-mcp-top-10/"}],
    },
    "MCP09": {
        "summary": "Shadow / untracked MCP servers in client configs.",
        "fix": ["mcp-bastion audit", "inventory configs", "governance beacon (optional)"],
        "bastion": ["audit"],
        "refs": [{"title": "OWASP MCP Top 10", "url": "https://owasp.org/www-project-mcp-top-10/"}],
    },
    "MCP10": {
        "summary": "Insufficient monitoring / audit gap.",
        "fix": ["Enable audit JSONL", "dashboard + Prometheus", "alert webhooks"],
        "bastion": ["audit", "alerts"],
        "refs": [{"title": "OWASP MCP Top 10", "url": "https://owasp.org/www-project-mcp-top-10/"}],
    },
}

# Per-check rule cards (PMD-style rule documentation).
CHECK_GUIDES: dict[str, dict[str, Any]] = {
    "injection_heuristic": {
        "name": "Prompt / tool injection heuristic",
        "summary": "Tool description or args match known jailbreak / instruction-override patterns.",
        "fix": [
            "Rewrite tool descriptions to be imperative and narrow; remove 'ignore previous' style text.",
            "Enable prompt_guard.enabled in bastion.yaml.",
            "Re-run: mcp-bastion scan tools.json --format json -o .bastion/scan/catalog.json",
        ],
        "severity_hint": "high",
    },
    "homoglyph": {
        "name": "Homoglyph / lookalike tool name",
        "summary": "Two tools differ only by visually confusable Unicode characters (poisoning risk).",
        "fix": [
            "Rename tools to ASCII-safe unique names.",
            "Enable tool_metadata_guard / fingerprint checks.",
        ],
        "severity_hint": "high",
    },
    "unbounded_string": {
        "name": "Unbounded string argument",
        "summary": "String args lack maxLength — agents can pass megabyte payloads.",
        "fix": [
            "Add maxLength (and pattern where possible) to inputSchema properties.",
            "Enable output_budget / rate_limit to contain blast radius.",
        ],
        "severity_hint": "medium",
    },
    "weak_schema": {
        "name": "Weak or missing schema constraints",
        "summary": "Schema is too permissive for a sensitive tool.",
        "fix": [
            "Require fields; use enums; avoid free-form objects for paths/commands.",
            "Enable schema_validation with explicit schemas for high-risk tools.",
        ],
        "severity_hint": "medium",
    },
    "missing_input_schema": {
        "name": "Missing inputSchema",
        "summary": "Tool advertises no input contract — runtime cannot validate.",
        "fix": ["Publish a JSON Schema inputSchema for every tool.", "Fail CI if scan grade worse than B."],
        "severity_hint": "high",
    },
    "invalid_input_schema": {
        "name": "Invalid inputSchema",
        "summary": "Declared schema is not valid JSON Schema.",
        "fix": ["Validate schema with a JSON Schema linter before publish."],
        "severity_hint": "high",
    },
    "unconstrained_numeric": {
        "name": "Unconstrained numeric argument",
        "summary": "Numbers lack minimum/maximum — enables resource exhaustion.",
        "fix": ["Add minimum/maximum (and multipleOf if needed).", "Pair with rate_limit token budgets."],
        "severity_hint": "medium",
    },
    "risky_arg_optional": {
        "name": "Risky optional argument",
        "summary": "Dangerous parameters (cmd, path, url, code) are optional — easy to smuggle.",
        "fix": ["Make risky args required with strict patterns, or remove them.", "Enable argument_guards."],
        "severity_hint": "high",
    },
    "content_filter": {
        "name": "Content-filter pattern hit (static)",
        "summary": "Catalog text matches path/code/secret heuristics.",
        "fix": ["Remove embedded secrets/paths from descriptions.", "Enable content_filter at runtime."],
        "severity_hint": "medium",
    },
    "fingerprint_drift": {
        "name": "Tool catalog fingerprint drift",
        "summary": "Catalog changed vs baseline fingerprint — possible supply-chain change.",
        "fix": ["Diff tools against last approved catalog.", "Update signed baseline only after review."],
        "severity_hint": "high",
    },
    "hidden_unicode": {
        "name": "Hidden Unicode in metadata",
        "summary": "Zero-width or bidi controls in tool text can hide instructions.",
        "fix": ["Strip non-printable Unicode from names/descriptions.", "Re-scan until clean."],
        "severity_hint": "high",
    },
    "empty_description": {
        "name": "Empty tool description",
        "summary": "Missing description reduces reviewability and aids shadow tools.",
        "fix": ["Add a clear one-line purpose for every tool."],
        "severity_hint": "low",
    },
    "skill_over_broad_grant": {
        "name": "Skill over-broad grant",
        "summary": "Skill grants * or overly wide tool access.",
        "fix": ["Enumerate exact tools the skill needs.", "Re-run mcp-bastion scan --skills."],
        "severity_hint": "high",
    },
    "skill_credential_ref": {
        "name": "Skill credential reference",
        "summary": "Skill file references secrets/API keys.",
        "fix": ["Move secrets to env refs resolved at runtime; never commit raw keys."],
        "severity_hint": "critical",
    },
    "standing_credential": {
        "name": "Standing credential in MCP client config",
        "summary": "Hard-coded API key/token in mcp.json (or similar).",
        "fix": [
            "Replace with ${ENV_VAR} / env: refs.",
            "Rotate the exposed credential immediately.",
            "mcp-bastion audit --format json -o .bastion/scan/risk-audit.json",
        ],
        "severity_hint": "critical",
    },
    "credential_env_ref": {
        "name": "Credential via env reference",
        "summary": "Config points at a secret-bearing env var — review scope.",
        "fix": ["Ensure env is injected only in trusted runtimes; prefer short-lived tokens."],
        "severity_hint": "medium",
    },
    "standing_env_secret": {
        "name": "Standing env secret smell",
        "summary": "Env block looks like a long-lived secret.",
        "fix": ["Use a secrets manager adapter; avoid .env in production images."],
        "severity_hint": "high",
    },
    "over_permissioned_tools": {
        "name": "Over-permissioned tools",
        "summary": "Client can reach admin/destructive tools.",
        "fix": ["Split servers by role; enable agent_iam allowlists."],
        "severity_hint": "high",
    },
    "broad_tool_surface": {
        "name": "Broad tool surface",
        "summary": "Large tool count increases attack surface for agents.",
        "fix": ["Enable discovery_filter + tool_allowlist.", "Split low-risk vs high-risk MCP servers."],
        "severity_hint": "medium",
    },
    "shell_launcher": {
        "name": "Shell launcher server",
        "summary": "Client config launches a shell/exec style MCP server.",
        "fix": ["Remove shell MCP from default agents; gate behind break-glass IAM."],
        "severity_hint": "critical",
    },
    "filesystem_server": {
        "name": "Filesystem MCP server",
        "summary": "Filesystem server can read/write host paths.",
        "fix": ["Constrain roots; enable content_filter path denylist; see examples/bastion-filesystem-guards.yaml."],
        "severity_hint": "high",
    },
    "no_mcp_configs": {
        "name": "No MCP configs found",
        "summary": "Audit found no client MCP configs under the search roots.",
        "fix": ["Point audit at the repo that contains .cursor/mcp.json or equivalent."],
        "severity_hint": "info",
    },
}


def guide_for_framework_id(fid: str) -> dict[str, Any] | None:
    fid = (fid or "").strip().upper()
    base = FRAMEWORK_GUIDES.get(fid)
    if not base:
        # Title-only fallback for ids we list but have not fully documented yet.
        title = ASI_TITLES.get(fid) or MCP_TITLES.get(fid) or LLM_TITLES.get(fid)
        if not title:
            return None
        return {
            "id": fid,
            "title": title,
            "summary": f"Framework category {fid}: {title}.",
            "why": "Mapped from Bastion taxonomy; enable related pillars and re-scan.",
            "fix": ["Review bastion.yaml controls for this category.", "See docs/TAXONOMY.md"],
            "bastion": [],
            "refs": [],
        }
    title = ASI_TITLES.get(fid) or MCP_TITLES.get(fid) or LLM_TITLES.get(fid) or fid
    out = {"id": fid, "title": title, **base}
    return out


def guide_for_check(check: str) -> dict[str, Any] | None:
    check = (check or "").strip()
    if not check:
        return None
    tags = tags_for_check(check)
    base = CHECK_GUIDES.get(check)
    frameworks = []
    for key in ("asi", "mcp", "llm"):
        for fid in tags.get(key) or []:
            g = guide_for_framework_id(str(fid))
            if g:
                frameworks.append(
                    {
                        "id": g["id"],
                        "title": g.get("title"),
                        "summary": g.get("summary"),
                        "fix": g.get("fix") or [],
                        "refs": g.get("refs") or [],
                        "bastion": g.get("bastion") or [],
                    }
                )
    if not base and not frameworks:
        return {
            "check": check,
            "name": check,
            "summary": "No bundled guide for this check yet.",
            "fix": ["See docs/TAXONOMY.md and enable related bastion.yaml pillars."],
            "taxonomy": tags,
            "frameworks": [],
            "refs": [],
            "bastion": [],
        }
    name = (base or {}).get("name") or check
    summary = (base or {}).get("summary") or f"Finding check `{check}`."
    fix = list((base or {}).get("fix") or [])
    bastion: list[str] = []
    refs: list[dict[str, str]] = []
    for fw in frameworks:
        for b in fw.get("bastion") or []:
            if b not in bastion:
                bastion.append(b)
        for r in fw.get("refs") or []:
            if r not in refs:
                refs.append(r)
        for step in fw.get("fix") or []:
            if step not in fix:
                fix.append(step)
    return {
        "check": check,
        "name": name,
        "summary": summary,
        "why": (base or {}).get("why")
        or (frameworks[0].get("summary") if frameworks else None),
        "fix": fix,
        "severity_hint": (base or {}).get("severity_hint"),
        "taxonomy": tags or dict(TAXONOMY.get(check) or {}),
        "frameworks": frameworks,
        "bastion": bastion,
        "refs": refs,
        "style": "pmd-rule-card",
    }


def enrich_finding_with_guide(finding: dict[str, Any]) -> dict[str, Any]:
    """Attach taxonomy + PMD-style guide to a finding (non-mutating)."""
    out = dict(finding)
    check = str(out.get("check") or "")
    tags = tags_for_check(check)
    if tags and "taxonomy" not in out:
        out["taxonomy"] = tags
    guide = guide_for_check(check)
    if guide:
        out["guide"] = guide
    return out


def list_all_check_guides() -> list[dict[str, Any]]:
    return [guide_for_check(c) for c in sorted(set(TAXONOMY) | set(CHECK_GUIDES)) if guide_for_check(c)]
