"""Load and apply bundled demo traffic scenarios (validation / tour only)."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp_bastion.pillars.metrics import MetricsStore

if TYPE_CHECKING:
    from mcp_bastion.config import BastionConfig

_SCENARIOS_PATH = Path(__file__).resolve().parent / "data" / "demo_traffic_scenarios.json"


def scenarios_path() -> Path:
    return _SCENARIOS_PATH


def load_demo_traffic_scenarios() -> dict[str, Any]:
    path = _SCENARIOS_PATH
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def seed_from_scenarios(
    rng: random.Random | None = None,
    *,
    config: BastionConfig | None = None,
) -> dict[str, Any]:
    """Seed MetricsStore from demo_traffic_scenarios.json (fallback to classic seed)."""
    from mcp_bastion.config import BastionConfig, load_config
    from mcp_bastion.demo_dashboard_metrics import (
        _demo_kind_allowed,
        _demo_tool,
        _inject_demo_time_series,
        seed_metrics,
    )
    from mcp_bastion.pillars.audit_hash_chain import AuditHashChain

    rng = rng or random.Random(42)
    cfg = config if config is not None else load_config()
    if not isinstance(cfg, BastionConfig):
        cfg = load_config()

    data = load_demo_traffic_scenarios()
    batches = (data.get("seed_batches") or {}) if data else {}
    blocks = list(batches.get("blocks") or [])
    tools_raw = list(batches.get("allowed_tools") or [])

    if not blocks or not tools_raw:
        seed_metrics(rng, config=cfg)
        return {"source": "fallback_seed_metrics", "path": str(_SCENARIOS_PATH)}

    store = MetricsStore.get()
    store.reset()
    tenant = (cfg.multi_tenant_default_tenant or "default").strip() or "default"
    demo_tools = tuple(_demo_tool(t) for t in tools_raw)

    for _ in range(380):
        store.record_request(rng.choice(demo_tools), tenant=tenant)

    nblk = 0
    for item in blocks:
        reason = str(item.get("reason") or "")
        tool = str(item.get("tool") or "unknown")
        kind = MetricsStore._normalize_reason_kind(reason)
        if not _demo_kind_allowed(cfg, kind):
            continue
        for _ in range(rng.randint(4, 12)):
            nblk += 1
            agent = "support-bot" if "Agent '" in reason else ""
            store.record_blocked(
                reason,
                _demo_tool(tool),
                tenant_id=tenant,
                agent_id=agent,
                trace_id=f"trc-demo-{nblk:04d}",
                request_id=f"req-demo-{nblk:04d}",
                forensic_trace=[
                    {"pillar": "audit_log", "status": "allowed", "detail": "request accepted"},
                    {
                        "pillar": kind if kind != "other" else "policy",
                        "status": "blocked",
                        "detail": reason[:200],
                    },
                ],
            )

    if cfg.pii:
        store.record_pii_entities(
            {
                "EMAIL_ADDRESS": 48,
                "PERSON": 36,
                "PHONE_NUMBER": 22,
                "CREDIT_CARD": 8,
                "US_SSN": 5,
            }
        )
    if cfg.cost_tracker:
        store.record_cost(12.4, "demo", {"llm_provider": "openai", "llm_model": "gpt-4o"}, tenant=tenant)
    store.record_tokens_used(1_250_000)
    store.record_tokens_saved(180_000, source="output_budget", provider="openai", model="gpt-4o-mini")

    for _ in range(400):
        store.record_latency_ms(rng.uniform(4.0, 40.0))

    every = int(getattr(cfg, "audit_hash_chain_anchor_every", 0) or 0)
    AuditHashChain.configure(anchor_every=every or 5)
    chain = AuditHashChain.get()
    for i in range(8):
        chain.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "tool": demo_tools[i % len(demo_tools)],
                "action": "BLOCKED" if i % 3 == 0 else "ALLOWED",
                "reason": "demo_traffic_scenarios",
                "tenant_id": "demo",
                "index_hint": i,
            }
        )

    _inject_demo_time_series(store, rng)
    store._metrics.window_start = (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
    store.add_alert("demo", "Demo traffic scenarios loaded — synthetic data for testing only", "warning")

    return {
        "source": "demo_traffic_scenarios.json",
        "path": str(_SCENARIOS_PATH),
        "block_catalog": len(blocks),
        "blocked_seeded": nblk,
    }
