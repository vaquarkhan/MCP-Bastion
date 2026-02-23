"""
Mistral + MCP-Bastion Example

Use with Mistral Agents SDK (MCPClientSTDIO).
Config: docs/LLM_INTEGRATION.md
"""

import runpy
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "src"))
runpy.run_path(str(root / "examples" / "llm_server.py"), run_name="__main__")
