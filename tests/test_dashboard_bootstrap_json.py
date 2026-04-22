"""Dashboard HTML embeds a JSON metrics snapshot (no fetch required for first paint)."""

import asyncio
import json
import re
import sys
from pathlib import Path

import httpx
import pytest

_root = Path(__file__).resolve().parents[1]
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root / "src"))


@pytest.mark.asyncio
async def test_root_embeds_nonzero_demo_metrics_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_BASTION_DEMO", raising=False)
    from dashboard.app import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/")
    assert r.status_code == 200
    assert 'id="mcp-bastion-bootstrap-json"' in r.text
    m = re.search(
        r'<script type="application/json" id="mcp-bastion-bootstrap-json">(.+?)</script>',
        r.text,
        re.DOTALL,
    )
    assert m, "embedded metrics script missing"
    d = json.loads(m.group(1))
    assert int(d.get("requests_total") or 0) > 0
    assert int(d.get("blocked_total") or 0) > 0


def test_metrics_json_for_html_embed_escapes_lt() -> None:
    from dashboard.app import _metrics_json_for_html_embed

    out = _metrics_json_for_html_embed({"reason": "<script>bad</script>"})
    assert "<script>" not in out
    roundtrip = json.loads(out)
    assert roundtrip["reason"] == "<script>bad</script>"
