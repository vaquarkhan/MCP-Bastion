"""
Finding taxonomy: map scan/audit checks to LLM / MCP / ASI frameworks.

ASI IDs and titles verified against OWASP GenAI Security Project announcement
(https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/):

  ASI01 Agent Goal Hijack
  ASI02 Tool Misuse and Exploitation
  ASI03 Identity and Privilege Abuse
  ASI04 Agentic Supply Chain Vulnerabilities
  ASI05 Unexpected Code Execution
  ASI06 Memory and Context Poisoning
  ASI07 Insecure Inter-Agent Communication
  ASI08 Cascading Failures
  ASI09 Human-Agent Trust Exploitation
  ASI10 Rogue Agents

MCP0x labels align with this repo's published MCP Top 10 table in README.
LLM0x align with OWASP LLM Top 10 naming used elsewhere in docs.
"""

from __future__ import annotations

from typing import Any

# Complete map for every check id emitted by static_scan / skill_scan / risk_audit.
TAXONOMY: dict[str, dict[str, list[str]]] = {
    # static_scan
    "injection_heuristic": {"llm": ["LLM01"], "mcp": ["MCP05"], "asi": ["ASI01"]},
    "homoglyph": {"mcp": ["MCP03"], "asi": ["ASI04"]},
    "shadow_tool": {"mcp": ["MCP03"], "asi": ["ASI04"]},
    "unbounded_string": {"mcp": ["MCP05"], "asi": ["ASI02", "ASI05"]},
    "weak_schema": {"mcp": ["MCP05"], "asi": ["ASI02"]},
    "missing_input_schema": {"mcp": ["MCP05"], "asi": ["ASI02"]},
    "invalid_input_schema": {"mcp": ["MCP05"], "asi": ["ASI02"]},
    "unconstrained_numeric": {"mcp": ["MCP05"], "asi": ["ASI02"]},
    "risky_arg_optional": {"mcp": ["MCP05"], "asi": ["ASI02"]},
    "content_filter": {"llm": ["LLM02"], "mcp": ["MCP01"], "asi": ["ASI05"]},
    "fingerprint_drift": {"mcp": ["MCP04"], "asi": ["ASI04"]},
    "hidden_unicode": {"mcp": ["MCP05"], "asi": ["ASI01"]},
    "empty_description": {"mcp": ["MCP03"], "asi": ["ASI04"]},
    # skill_scan
    "skill_over_broad_grant": {"mcp": ["MCP06"], "asi": ["ASI02", "ASI03"]},
    "skill_credential_ref": {"mcp": ["MCP01"], "asi": ["ASI03"]},
    "skill_name_mismatch": {"mcp": ["MCP03"], "asi": ["ASI04"]},
    "skill_read_error": {"mcp": ["MCP08"], "asi": ["ASI04"]},
    # risk_audit
    "standing_credential": {"mcp": ["MCP01"], "asi": ["ASI03"]},
    "credential_env_ref": {"mcp": ["MCP01"], "asi": ["ASI03"]},
    "standing_env_secret": {"mcp": ["MCP01"], "asi": ["ASI03"]},
    "over_permissioned_tools": {"mcp": ["MCP06"], "asi": ["ASI02", "ASI03"]},
    "broad_tool_surface": {"mcp": ["MCP06"], "asi": ["ASI02"]},
    "shell_launcher": {"mcp": ["MCP05"], "asi": ["ASI05"]},
    "filesystem_server": {"mcp": ["MCP02"], "asi": ["ASI02"]},
    "no_mcp_configs": {"mcp": ["MCP09"], "asi": ["ASI04"]},
    "config_parse_error": {"mcp": ["MCP08"], "asi": ["ASI04"]},
    "empty_servers": {"mcp": ["MCP09"], "asi": ["ASI04"]},
}

ASI_TITLES: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# OWASP LLM Top 10 (labels used in docs / scan taxonomy).
LLM_TITLES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# OWASP MCP Top 10 (aligns with README control table).
MCP_TITLES: dict[str, str] = {
    "MCP01": "Token / Secret Exposure",
    "MCP02": "Privilege / Filesystem Abuse",
    "MCP03": "Tool Poisoning / Shadow Tools",
    "MCP04": "Metadata / Fingerprint Drift",
    "MCP05": "Unsafe Tool Execution Surface",
    "MCP06": "Over-Permissioned Tool Grants",
    "MCP07": "Context / Session Confusion",
    "MCP08": "Insecure Configuration / Parse Failures",
    "MCP09": "Shadow / Untracked MCP Servers",
    "MCP10": "Insufficient Monitoring / Audit Gap",
}


def tags_for_check(check: str) -> dict[str, list[str]]:
    return dict(TAXONOMY.get(check, {}))


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Attach taxonomy tags + PMD-style guide to a finding dict (non-mutating copy)."""
    out = dict(finding)
    tags = tags_for_check(str(finding.get("check") or ""))
    if tags:
        out["taxonomy"] = tags
    try:
        from mcp_bastion.issue_guides import guide_for_check

        guide = guide_for_check(str(finding.get("check") or ""))
        if guide:
            out["guide"] = guide
    except Exception:
        pass
    return out
