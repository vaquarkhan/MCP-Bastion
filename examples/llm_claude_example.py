"""
Claude + MCP-Bastion Example
Author: Viquar Khan

Use with Claude Desktop, Claude Code, or API.
Config: docs/LLM_INTEGRATION.md
"""

import runpy
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "src"))
runpy.run_path(str(root / "examples" / "llm_server.py"), run_name="__main__")
