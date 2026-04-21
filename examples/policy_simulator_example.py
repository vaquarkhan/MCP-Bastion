"""
Policy shadow simulator: replay forensic-style events against a candidate policy.

Uses simulate_policy() from mcp_bastion.policy_simulator (same engine as the
dashboard POST /api/policy/simulate). Tune overrides to see would_block counts
and regressions before changing production bastion.yaml.

Run:

  PYTHONPATH=src python examples/policy_simulator_example.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(root, "src"))


async def main() -> None:
    from mcp_bastion.policy_simulator import simulate_policy

    events = [
        {
            "request_id": "r1",
            "session_id": "s1",
            "action": "ALLOWED",
            "replay_payload": {
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "../../etc/passwd"},
                }
            },
        },
        {
            "request_id": "r2",
            "session_id": "s1",
            "action": "ALLOWED",
            "replay_payload": {
                "params": {"name": "add", "arguments": {"a": 1, "b": 2}},
            },
        },
    ]

    result = await simulate_policy(
        events,
        overrides={
            "prompt_guard": {"enabled": False},
            "content_filter": {"enabled": True},
        },
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
