"""
Grok (xAI) + MCP-Bastion Example
Author: Viquar Khan

Grok only supports remote MCP (HTTP/SSE). This starts the HTTP server.
Use with xAI SDK: mcp(server_url="http://localhost:8000/mcp")
Config: docs/LLM_INTEGRATION.md
"""

import runpy
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "src"))
if "--http" not in sys.argv:
    sys.argv = [sys.argv[0], "--http", "8000"] + sys.argv[1:]
runpy.run_path(str(root / "examples" / "llm_server.py"), run_name="__main__")
