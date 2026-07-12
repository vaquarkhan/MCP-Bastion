# Finding taxonomy (LLM / MCP / ASI)

Maps Bastion scan and audit **check ids** to framework tags. Used in JSON reports (`taxonomy` field) and compliance `report --framework asi`.

ASI01-ASI10 titles are taken from the OWASP GenAI Security Project announcement for the Top 10 for Agentic Applications 2026:

https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/

| ID | Title |
|----|-------|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse and Exploitation |
| ASI03 | Identity and Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution |
| ASI06 | Memory and Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

Source of truth for the check map: `src/mcp_bastion/taxonomy.py`.

```bash
mcp-bastion scan tools.json --format json   # findings include taxonomy.asi / .mcp / .llm
mcp-bastion report --framework asi --audit .bastion/audit.jsonl
```
