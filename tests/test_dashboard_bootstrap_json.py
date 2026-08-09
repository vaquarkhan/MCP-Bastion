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
    sys.path.insert(0, str(_root))


@pytest.mark.asyncio
async def test_root_embeds_nonzero_demo_metrics_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_BASTION_DEMO", "1")
    monkeypatch.setenv("MCP_BASTION_DEMO_LIVE", "0")
    from dashboard import app as dash_mod

    dash_mod._dashboard_defaults_applied = True
    dash_mod._demo_seed_applied = False
    from dashboard.app import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/")
    assert r.status_code == 200
    assert 'id="mcp-bastion-bootstrap-json"' in r.text
    assert 'id="kpiReq"' in r.text
    assert 'id="demoModeToggle"' in r.text
    m = re.search(
        r'<script type="application/json" id="mcp-bastion-bootstrap-json">(.+?)</script>',
        r.text,
        re.DOTALL,
    )
    assert m, "embedded metrics script missing"
    d = json.loads(m.group(1))
    assert int(d.get("requests_total") or 0) > 0
    assert int(d.get("blocked_total") or 0) > 0


@pytest.mark.asyncio
async def test_root_live_mode_can_be_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_BASTION_DEMO", "0")
    monkeypatch.setenv("MCP_BASTION_DEMO_LIVE", "0")
    from dashboard import app as dash_mod
    from mcp_bastion.pillars.metrics import MetricsStore

    dash_mod._dashboard_defaults_applied = True
    dash_mod._demo_seed_applied = False
    MetricsStore.get().reset()
    from dashboard.app import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/")
        mode = await c.get("/api/demo-mode")
    assert r.status_code == 200
    assert mode.status_code == 200
    body = mode.json()
    assert body.get("demo") is False
    assert body.get("mode") == "live"


@pytest.mark.asyncio
async def test_demo_mode_toggle_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_BASTION_DEMO", "0")
    monkeypatch.setenv("MCP_BASTION_DEMO_LIVE", "0")
    from dashboard import app as dash_mod
    from mcp_bastion.pillars.metrics import MetricsStore

    dash_mod._dashboard_defaults_applied = True
    dash_mod._demo_seed_applied = False
    MetricsStore.get().reset()
    from dashboard.app import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        off = await c.get("/api/metrics")
        assert int(off.json().get("requests_total") or 0) == 0
        on = await c.post("/api/demo-mode", json={"demo": True})
        assert on.status_code == 200
        assert on.json().get("demo") is True
        seeded = await c.get("/api/metrics")
        assert int(seeded.json().get("requests_total") or 0) > 0
        back = await c.post("/api/demo-mode", json={"demo": False})
        assert back.json().get("demo") is False
        cleared = await c.get("/api/metrics")
        assert int(cleared.json().get("requests_total") or 0) == 0


def test_metrics_json_for_html_embed_escapes_lt() -> None:
    from dashboard.app import _metrics_json_for_html_embed

    out = _metrics_json_for_html_embed({"reason": "<script>bad</script>"})
    assert "<script>" not in out
    roundtrip = json.loads(out)
    assert roundtrip["reason"] == "<script>bad</script>"
