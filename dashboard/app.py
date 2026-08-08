"""
MCP-Bastion real-time dashboard and metrics API.

Run: PYTHONPATH=src python dashboard/app.py
Serves: http://localhost:7000/ (dashboard), http://localhost:7000/api/metrics (JSON)

Demo data (non-zero charts without a separate MCP server) - on by default for local runs:
  python dashboard/app.py
  mcp-bastion dashboard
  Opt out: MCP_BASTION_DEMO=0 or mcp-bastion dashboard --no-demo

Optional continuous fake traffic (KPIs tick over time) - off by default (stable baseline).
  Enable: MCP_BASTION_DEMO_LIVE=1 or mcp-bastion dashboard --live
  Or run: python examples/dashboard_demo.py (includes live loop by default)
"""

from __future__ import annotations

import json
import logging
import os
import random
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path

logger = logging.getLogger("mcp_bastion.dashboard")

# Add src so mcp_bastion is importable
root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "src"))

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import (
        FileResponse,
        HTMLResponse,
        JSONResponse,
        PlainTextResponse,
        Response,
        StreamingResponse,
    )
    from fastapi.staticfiles import StaticFiles
except ImportError:
    logger.error("Install: pip install fastapi uvicorn")
    sys.exit(1)

from mcp_bastion.pillars.metrics import MetricsStore

_demo_seed_applied = False


def _load_demo_bastion_config() -> object:
    """Policy snapshot for demo seeding (same file as a real Bastion process: BASTION_CONFIG / bastion.yaml)."""
    try:
        from mcp_bastion.config import load_config

        cfg = load_config()
    except Exception as e:
        logger.debug("load_config for demo failed (%s); using defaults", e)
        from mcp_bastion.config import BastionConfig

        cfg = BastionConfig()
    # Demo board should show RBAC + common pillars as enabled so tiles and seed blocks match.
    if _demo_metrics_enabled():
        for attr, val in (
            ("rbac", True),
            ("prompt_guard", True),
            ("rate_limit", True),
            ("pii", True),
            ("cost_tracker", True),
            ("schema_validation", True),
            ("content_filter", True),
            ("agent_iam_enabled", True),
            ("server_verification_enabled", True),
            ("semantic_firewall", True),
            ("canary_goallock_enabled", True),
            ("audit_hash_chain_anchor_every", 5),
        ):
            try:
                setattr(cfg, attr, val)
            except Exception:
                pass
        if not getattr(cfg, "agent_iam_agents", None):
            try:
                cfg.agent_iam_agents = [
                    {
                        "id": "support-bot",
                        "allowed_tools": ["query_llm", "web_search", "read_file"],
                        "blocked_tools": ["delete_repo"],
                    }
                ]
            except Exception:
                pass
    return cfg


def _governance_config_snapshot() -> dict:
    """Runtime governance feature flags from bastion.yaml (for dashboard status panel)."""
    cfg = _load_demo_bastion_config()
    agent_count = 0
    if getattr(cfg, "agent_iam_enabled", False):
        try:
            from mcp_bastion.pillars.agent_iam import parse_agent_policies

            agent_count = len(parse_agent_policies(getattr(cfg, "agent_iam_agents", []) or []))
        except Exception:
            agent_count = len(getattr(cfg, "agent_iam_agents", []) or [])
    manifest_entries = len(getattr(cfg, "server_verification_manifest", {}) or {})
    return {
        "features": {
            "agent_iam": {
                "enabled": bool(getattr(cfg, "agent_iam_enabled", False)),
                "agent_count": agent_count,
                "isolate_sessions": bool(getattr(cfg, "agent_iam_isolate_sessions", False)),
                "require_token": bool(getattr(cfg, "agent_iam_require_token", True)),
            },
            "server_verification": {
                "enabled": bool(getattr(cfg, "server_verification_enabled", False)),
                "manifest_entries": manifest_entries,
                "on_mismatch": getattr(cfg, "server_verification_on_mismatch", "block"),
                "signed": bool(getattr(cfg, "server_verification_manifest_signature", None)),
            },
            "transport_hardening": {
                "enabled": bool(getattr(cfg, "transport_hardening_enabled", True)),
                "block_browser_origin": bool(
                    getattr(cfg, "transport_hardening_block_browser_origin", True)
                ),
                "require_loopback": bool(getattr(cfg, "transport_hardening_require_loopback", True)),
            },
            "stdio_guard": {
                "enabled": bool(getattr(cfg, "stdio_guard_enabled", False)),
            },
            "tool_metadata_fingerprint": {
                "enabled": bool(getattr(cfg, "tool_metadata_fingerprint_enabled", False)),
            },
            # Core policy pillars (RBAC / injection / FinOps / PII) - same panel, same bastion.yaml
            "rbac": {"enabled": bool(getattr(cfg, "rbac", False))},
            "prompt_guard": {"enabled": bool(getattr(cfg, "prompt_guard", False))},
            "rate_limit": {"enabled": bool(getattr(cfg, "rate_limit", False))},
            "pii": {"enabled": bool(getattr(cfg, "pii", False))},
            "pii_vault": {
                "enabled": bool(getattr(cfg, "pii_vault", False))
                and bool(getattr(cfg, "pii", False)),
                "token_style": str(getattr(cfg, "pii_vault_token_style", "typed") or "typed"),
                "ttl_seconds": float(getattr(cfg, "pii_vault_ttl_seconds", 3600.0) or 3600.0),
            },
            "cost_tracker": {"enabled": bool(getattr(cfg, "cost_tracker", False))},
            "schema_validation": {"enabled": bool(getattr(cfg, "schema_validation", False))},
            "content_filter": {"enabled": bool(getattr(cfg, "content_filter", False))},
            "semantic_firewall": {"enabled": bool(getattr(cfg, "semantic_firewall", False))},
            "canary_goallock": {"enabled": bool(getattr(cfg, "canary_goallock_enabled", False))},
            "audit_hash_chain": {
                "enabled": True,
                "anchor_every": int(getattr(cfg, "audit_hash_chain_anchor_every", 0) or 0),
            },
        },
    }


_demo_live_stop: threading.Event | None = None
_demo_live_thread: threading.Thread | None = None


def _demo_metrics_enabled() -> bool:
    """
    Synthetic KPIs/charts seeding is ON unless explicitly turned off.

    Important: do not use os.environ.get("MCP_BASTION_DEMO", "") - when the variable is *unset*,
    that becomes "" which is not in ("1","true","yes") and would skip the seed even though we
    intend "demo on by default".
    """
    raw = os.environ.get("MCP_BASTION_DEMO")
    if raw is None:
        return True
    v = raw.strip().lower()
    if v == "":
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return v in ("1", "true", "yes", "on")


def _demo_live_enabled() -> bool:
    """Background traffic only when explicitly requested (avoids extra threads by default)."""
    if not _demo_metrics_enabled():
        return False
    v = os.environ.get("MCP_BASTION_DEMO_LIVE", "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _maybe_start_demo_live_traffic() -> None:
    global _demo_live_stop, _demo_live_thread
    if not _demo_live_enabled():
        return
    if _demo_live_thread is not None and _demo_live_thread.is_alive():
        return
    try:
        from mcp_bastion.demo_live_traffic import live_simulator
    except Exception:
        logger.exception("Could not import demo live traffic module")
        return
    _demo_live_stop = threading.Event()
    _demo_live_thread = threading.Thread(
        target=live_simulator,
        args=(_demo_live_stop, random.Random(42), _load_demo_bastion_config()),
        name="mcp-bastion-demo-live",
        daemon=True,
    )
    _demo_live_thread.start()
    logger.info("Demo live traffic thread started (set MCP_BASTION_DEMO_LIVE=0 or omit --live to disable).")


def _get_dashboard_metrics_dict() -> dict[str, object]:
    """Single source for /, /api/metrics, and HTML bootstrap (demo seed + empty re-seed)."""
    global _demo_seed_applied
    if os.environ.get("MCP_BASTION_DEMO") is None:
        os.environ["MCP_BASTION_DEMO"] = "1"
    _maybe_seed_demo_metrics()
    m = MetricsStore.get().get_metrics()
    if _demo_metrics_enabled():
        rt = int(m.get("requests_total") or 0)
        bt = int(m.get("blocked_total") or 0)
        if rt == 0 and bt == 0:
            logger.warning("Metrics store empty with demo on; forcing re-seed.")
            _demo_seed_applied = False
            _maybe_seed_demo_metrics()
            m = MetricsStore.get().get_metrics()
    return m


def _metrics_json_for_html_embed(m: dict[str, object]) -> str:
    """JSON for <script type=\"application/json\">; escape '<' so payloads cannot close the tag."""
    s = json.dumps(m, separators=(",", ":"), default=str)
    return s.replace("<", "\\u003c")


def _maybe_seed_demo_metrics() -> None:
    """Seed rich demo KPIs/charts when MCP_BASTION_DEMO=1 (bundled in mcp_bastion, works after pip install)."""
    global _demo_seed_applied
    if _demo_seed_applied:
        return
    if not _demo_metrics_enabled():
        return
    try:
        from mcp_bastion.demo_dashboard_metrics import seed_metrics

        seed_metrics(random.Random(42), config=_load_demo_bastion_config())
        _demo_seed_applied = True
        logger.info("Demo metrics seeded (MCP_BASTION_DEMO=1). Open /api/metrics to verify non-zero data.")
    except Exception:
        logger.exception("Failed to seed demo metrics (mcp_bastion.demo_dashboard_metrics)")


@asynccontextmanager
async def _dashboard_lifespan(_app: FastAPI):
    global _demo_live_stop, _demo_live_thread
    # Default demo metrics on; explicit MCP_BASTION_DEMO=0/false/no disables.
    if os.environ.get("MCP_BASTION_DEMO") is None:
        os.environ["MCP_BASTION_DEMO"] = "1"
    _maybe_seed_demo_metrics()
    _maybe_start_demo_live_traffic()
    yield
    if _demo_live_stop is not None:
        _demo_live_stop.set()
    if _demo_live_thread is not None and _demo_live_thread.is_alive():
        _demo_live_thread.join(timeout=3.0)
    _demo_live_stop = None
    _demo_live_thread = None


app = FastAPI(title="MCP-Bastion Dashboard", lifespan=_dashboard_lifespan)


# Allow cross-origin reads of metrics (proxies, Live Preview, tools on another port).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "HEAD", "OPTIONS"],
    allow_headers=["*"],
)

_static_dir = Path(__file__).resolve().parent / "static"
# Repo: MCP-Bastion/images/mcp-bastian.png (header uses this URL first; explicit route = reliable vs mount order).
_header_brand_png = root / "images" / "mcp-bastian.png"


@app.get("/images/mcp-bastian.png")
def serve_mcp_bastian_png():
    """Header banner: prefer repo `images/mcp-bastian.png`, else dashboard/static copy."""
    if _header_brand_png.is_file():
        return FileResponse(_header_brand_png, media_type="image/png")
    fallback = _static_dir / "mcp-bastian.png"
    if fallback.is_file():
        return FileResponse(fallback, media_type="image/png")
    return PlainTextResponse("Not found", status_code=404)


@app.get("/favicon.ico")
def favicon():
    """Browsers request this by default; serve branding from /static/ (200 + body). Registered before /static mount."""
    png = _static_dir / "mcp-bastian.png"
    if png.is_file():
        return FileResponse(png, media_type="image/png")
    svg = _static_dir / "mcp-bastian.svg"
    if svg.is_file():
        return FileResponse(svg, media_type="image/svg+xml")
    return PlainTextResponse("", status_code=404)


if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


# Other files under /images/ (mcp-bastian.png is handled by serve_mcp_bastian_png above).
_images_dir = root / "images"
if _images_dir.is_dir():
    app.mount("/images", StaticFiles(directory=str(_images_dir)), name="images")


@app.get("/api/metrics")
def get_metrics():
    """Return metrics JSON; ensure demo seed ran (retries if store is still empty)."""
    try:
        m = _get_dashboard_metrics_dict()
        return JSONResponse(
            m,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
            },
        )
    except Exception as e:
        logger.exception("Failed to get metrics: %s", e)
        return JSONResponse(
            {"error": "metrics_unavailable", "message": str(e)},
            status_code=500,
        )


def _dashboard_build_info() -> dict:
    here = Path(__file__).resolve()
    return {
        "service": "mcp-bastion-dashboard",
        "dashboard_app_py": str(here),
        "ui_revision": "v37-forensics-autoselect",
        "hint": "If this is missing, you are not hitting dashboard/app.py - check port and process.",
    }


@app.get("/api/health")
def health():
    try:
        return {"status": "ok", **_dashboard_build_info()}
    except Exception as e:
        logger.exception("Health check failed: %s", e)
        return JSONResponse(
            {"status": "error", "message": str(e)},
            status_code=503,
        )


@app.get("/api/governance")
def governance_status():
    """Runtime governance config snapshot (Agent IAM, server verification, transport hardening)."""
    try:
        return _governance_config_snapshot()
    except Exception as e:
        logger.exception("Failed to get governance config: %s", e)
        return JSONResponse(
            {"error": "governance_unavailable", "message": str(e)},
            status_code=500,
        )


@app.get("/api/posture")
def security_posture():
    """Pre-deploy security posture grades from local scan JSON artifacts."""
    try:
        from mcp_bastion.dashboard_local import load_posture

        return load_posture(demo=_demo_metrics_enabled())
    except Exception as e:
        logger.exception("Failed to load posture: %s", e)
        return JSONResponse({"error": "posture_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/taxonomy")
def taxonomy_heatmap(framework: str = "asi"):
    """OWASP ASI / MCP / LLM Top 10 coverage from enabled pillars + local findings/blocks."""
    try:
        from mcp_bastion.dashboard_local import load_posture, load_taxonomy_coverage

        m = _get_dashboard_metrics_dict()
        posture = load_posture(demo=_demo_metrics_enabled())
        return load_taxonomy_coverage(
            posture=posture,
            metrics=m,
            config=_load_demo_bastion_config(),
            framework=framework,
        )
    except Exception as e:
        logger.exception("Failed to load taxonomy: %s", e)
        return JSONResponse({"error": "taxonomy_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/attack-matrix")
def attack_matrix(date_from: str | None = None, date_to: str | None = None):
    """Live attack category matrix from blocks + pre-deploy finding pressure."""
    try:
        from mcp_bastion.dashboard_local import load_attack_matrix, load_posture

        return load_attack_matrix(
            metrics=_get_dashboard_metrics_dict(),
            posture=load_posture(demo=_demo_metrics_enabled()),
            date_from=date_from,
            date_to=date_to,
        )
    except Exception as e:
        logger.exception("Failed to load attack matrix: %s", e)
        return JSONResponse({"error": "attack_matrix_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/issue-guide")
def issue_guide(check: str | None = None, id: str | None = None):
    """
    PMD-style rule card: what/why/how-to-fix for a scan check or OWASP id.

    Local knowledge only (no cloud). Optional refs are documentation links.
    """
    try:
        from mcp_bastion.issue_guides import guide_for_check, guide_for_framework_id

        if check:
            g = guide_for_check(check)
            if not g:
                return JSONResponse({"error": "unknown_check", "check": check}, status_code=404)
            return g
        if id:
            g = guide_for_framework_id(id)
            if not g:
                return JSONResponse({"error": "unknown_id", "id": id}, status_code=404)
            return g
        return JSONResponse(
            {"error": "missing_param", "message": "Pass ?check=weak_schema or ?id=ASI02"},
            status_code=400,
        )
    except Exception as e:
        logger.exception("issue-guide failed: %s", e)
        return JSONResponse({"error": "guide_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/prevalidate")
def prevalidate_summary():
    """
    Sonar-like prevalidation summary from local scan artifacts (not a SonarQube server).

    Surfaces grades + finding counts for CI/dashboard gates.
    """
    try:
        from mcp_bastion.dashboard_local import load_posture
        from mcp_bastion.issue_guides import enrich_finding_with_guide

        posture = load_posture(demo=_demo_metrics_enabled())
        issues = []
        for kind, doc in (posture.get("checks") or {}).items():
            if not doc.get("present"):
                continue
            for f in doc.get("findings") or []:
                if not isinstance(f, dict):
                    continue
                enriched = enrich_finding_with_guide(f)
                issues.append(
                    {
                        "source": kind,
                        "check": enriched.get("check"),
                        "severity": enriched.get("severity"),
                        "message": enriched.get("message") or enriched.get("summary"),
                        "tool": enriched.get("tool"),
                        "taxonomy": enriched.get("taxonomy"),
                        "guide": enriched.get("guide"),
                    }
                )
        # Sort critical/high first
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        issues.sort(key=lambda x: (rank.get(str(x.get("severity") or "info").lower(), 9), str(x.get("check"))))
        return {
            "engine": "mcp-bastion-scan-suite",
            "note": (
                "Prevalidation from local mcp-bastion scan / skill / OSV / audit JSON - "
                "Sonar-style issue list without running a SonarQube server."
            ),
            "combined_grade": posture.get("combined_grade"),
            "checks": {
                k: {
                    "grade": v.get("grade"),
                    "present": v.get("present"),
                    "finding_count": v.get("finding_count"),
                    "hint": v.get("hint"),
                }
                for k, v in (posture.get("checks") or {}).items()
            },
            "issue_count": len(issues),
            "issues": issues[:200],
            "demo": bool(posture.get("demo")),
        }
    except Exception as e:
        logger.exception("prevalidate failed: %s", e)
        return JSONResponse({"error": "prevalidate_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/compliance")
def compliance_evidence():
    """Local attestation + policy hash metadata (evidence, not a certificate)."""
    try:
        from mcp_bastion.dashboard_local import load_compliance

        return load_compliance()
    except Exception as e:
        logger.exception("Failed to load compliance: %s", e)
        return JSONResponse({"error": "compliance_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/compliance/report")
def compliance_report(
    framework: str = "soc2",
    date_from: str | None = None,
    date_to: str | None = None,
    format: str = "pdf",
):
    """Generate a local compliance evidence report (PDF by default; format=md for markdown)."""
    try:
        from mcp_bastion.dashboard_local import (
            generate_compliance_report_markdown,
            generate_compliance_report_pdf,
        )

        fw = (framework or "soc2").strip().lower()
        fmt = (format or "pdf").strip().lower()
        if fmt in ("md", "markdown"):
            body = generate_compliance_report_markdown(
                framework=fw, date_from=date_from, date_to=date_to
            )
            return Response(
                content=body,
                media_type="text/markdown; charset=utf-8",
                headers={
                    "Content-Disposition": f'attachment; filename="bastion-{fw}-evidence.md"',
                },
            )
        pdf = generate_compliance_report_pdf(
            framework=fw, date_from=date_from, date_to=date_to
        )
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="bastion-{fw}-evidence.pdf"',
            },
        )
    except Exception as e:
        logger.exception("Failed to generate compliance report: %s", e)
        return JSONResponse({"error": "report_failed", "message": str(e)}, status_code=500)


@app.get("/api/compliance/bundle")
def compliance_bundle(
    framework: str = "soc2",
    date_from: str | None = None,
    date_to: str | None = None,
):
    """Zip attestation + report + bastion.yaml (local evidence bundle)."""
    try:
        from mcp_bastion.dashboard_local import build_evidence_bundle_zip

        fw = (framework or "soc2").strip().lower()
        data = build_evidence_bundle_zip(
            framework=fw, date_from=date_from, date_to=date_to
        )
        return Response(
            content=data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="bastion-evidence-{fw}.zip"',
            },
        )
    except Exception as e:
        logger.exception("Failed to build evidence bundle: %s", e)
        return JSONResponse({"error": "bundle_failed", "message": str(e)}, status_code=500)


@app.get("/api/observe")
def observe_status():
    """Observe-mode banner data (mode + would-have-blocked count)."""
    try:
        from mcp_bastion.dashboard_local import load_observe_status

        return load_observe_status(_get_dashboard_metrics_dict())
    except Exception as e:
        logger.exception("Failed to load observe status: %s", e)
        return JSONResponse({"error": "observe_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/agents")
def agent_identity_view():
    """Confused-deputy view: denied-by-agent + IAM scope map."""
    try:
        from mcp_bastion.dashboard_local import load_agent_identity_view

        return load_agent_identity_view(
            _get_dashboard_metrics_dict(),
            config=_load_demo_bastion_config(),
        )
    except Exception as e:
        logger.exception("Failed to load agent view: %s", e)
        return JSONResponse({"error": "agents_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/trends")
def audit_trends(
    days: int = 14,
    date_from: str | None = None,
    date_to: str | None = None,
):
    """Block-rate / PII trends from local audit JSONL."""
    try:
        from mcp_bastion.dashboard_local import load_trends_from_audit

        return load_trends_from_audit(
            days=max(1, min(int(days or 14), 90)),
            date_from=date_from,
            date_to=date_to,
        )
    except Exception as e:
        logger.exception("Failed to load trends: %s", e)
        return JSONResponse({"error": "trends_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/onboarding")
def onboarding_checklist():
    """Empty-state onboarding steps when no traffic/scan yet."""
    try:
        from mcp_bastion.dashboard_local import load_onboarding, load_posture

        m = _get_dashboard_metrics_dict()
        posture = load_posture(demo=False)
        return load_onboarding(m, posture)
    except Exception as e:
        logger.exception("Failed to load onboarding: %s", e)
        return JSONResponse({"error": "onboarding_unavailable", "message": str(e)}, status_code=500)


@app.get("/api/alerts/stream")
async def alerts_sse():
    """Server-Sent Events for recent alerts (canary / auto-repave / observe)."""
    import asyncio

    async def event_gen():
        last_sig = ""
        while True:
            try:
                m = MetricsStore.get().get_metrics()
                alerts = m.get("alerts") or []
                sig = json.dumps(alerts[-5:], default=str, separators=(",", ":"))
                if sig != last_sig:
                    last_sig = sig
                    # Prefer canary / auto-repave / observe for SOC-feel push
                    hot = [
                        a
                        for a in alerts
                        if isinstance(a, dict)
                        and any(
                            k in str(a.get("kind") or "").lower()
                            for k in ("canary", "repave", "observe", "exfil")
                        )
                    ]
                    payload = hot[-8:] if hot else alerts[-8:]
                    yield f"data: {json.dumps({'alerts': payload}, default=str)}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
            await asyncio.sleep(2.0)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/dashboard-meta")
def dashboard_meta():
    """Which dashboard code is running (use this if the UI looks outdated)."""
    return _dashboard_build_info()


@app.get("/meta")
def meta_short():
    """Short URL - same payload as /api/dashboard-meta (easier to type)."""
    return _dashboard_build_info()


@app.get("/metrics")
def prometheus_metrics():
    """Prometheus-style metrics for Grafana/Datadog scraping."""
    try:
        m = MetricsStore.get().get_metrics()
    except Exception as e:
        logger.exception("Failed to get metrics for Prometheus: %s", e)
        return PlainTextResponse("# metrics unavailable\n", status_code=503)
    lines = [
        "# HELP mcp_bastion_requests_total Total requests",
        "# TYPE mcp_bastion_requests_total counter",
        f"mcp_bastion_requests_total {m.get('requests_total', 0)}",
        "# HELP mcp_bastion_blocked_total Blocked requests",
        "# TYPE mcp_bastion_blocked_total counter",
        f"mcp_bastion_blocked_total {m.get('blocked_total', 0)}",
        "# HELP mcp_bastion_pii_redacted_total PII redaction count",
        "# TYPE mcp_bastion_pii_redacted_total counter",
        f"mcp_bastion_pii_redacted_total {m.get('pii_redacted_total', 0)}",
        "# HELP mcp_bastion_pii_vault_abstract_total Reversible PII vault abstract (tokenize) count",
        "# TYPE mcp_bastion_pii_vault_abstract_total counter",
        f"mcp_bastion_pii_vault_abstract_total {m.get('pii_vault_abstract_total', 0)}",
        "# HELP mcp_bastion_pii_vault_hydrate_total Reversible PII vault hydrate (restore) count",
        "# TYPE mcp_bastion_pii_vault_hydrate_total counter",
        f"mcp_bastion_pii_vault_hydrate_total {m.get('pii_vault_hydrate_total', 0)}",
        "# HELP mcp_bastion_cost_total Cost sum",
        "# TYPE mcp_bastion_cost_total gauge",
        f"mcp_bastion_cost_total {m.get('cost_total', 0)}",
        "# HELP mcp_bastion_tokens_saved_total Tokens saved by FinOps pillars",
        "# TYPE mcp_bastion_tokens_saved_total counter",
        f"mcp_bastion_tokens_saved_total {m.get('tokens_saved_total', 0)}",
        "# HELP mcp_bastion_tokens_avoided_by_blocks Estimated tokens never spent because requests were blocked",
        "# TYPE mcp_bastion_tokens_avoided_by_blocks counter",
        f"mcp_bastion_tokens_avoided_by_blocks {m.get('tokens_avoided_by_blocks', 0)}",
        "# HELP mcp_bastion_estimated_usd_saved Estimated USD saved from token reduction",
        "# TYPE mcp_bastion_estimated_usd_saved gauge",
        f"mcp_bastion_estimated_usd_saved {m.get('estimated_usd_saved', 0)}",
        "# HELP mcp_bastion_estimated_usd_avoided_by_blocks Estimated USD avoided by blocked requests",
        "# TYPE mcp_bastion_estimated_usd_avoided_by_blocks gauge",
        f"mcp_bastion_estimated_usd_avoided_by_blocks {m.get('estimated_usd_avoided_by_blocks', 0)}",
    ]
    gov = m.get("governance") or {}
    gov_blocks = gov.get("blocks") or {}
    lines.extend(
        [
            "# HELP mcp_bastion_governance_blocks_total Runtime governance blocks by kind",
            "# TYPE mcp_bastion_governance_blocks_total counter",
            f'mcp_bastion_governance_blocks_total{{kind="agent_iam"}} {gov_blocks.get("agent_iam", 0)}',
            f'mcp_bastion_governance_blocks_total{{kind="server_verification"}} {gov_blocks.get("server_verification", 0)}',
        ]
    )
    return PlainTextResponse("\n".join(lines) + "\n")


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta id="metaColorScheme" name="color-scheme" content="dark">
  <title>MCP-Bastion Dashboard</title>
  <link rel="icon" href="/static/mcp-bastian.png" type="image/png" sizes="any" />
  <script>
    (function () {
      var t = "dark";
      try {
        var s = localStorage.getItem("mcp-bastion-theme");
        if (s !== "light" && s !== "dark") s = sessionStorage.getItem("mcp-bastion-theme");
        if (s === "light" || s === "dark") t = s;
      } catch (e) {}
      document.documentElement.setAttribute("data-theme", t);
      document.documentElement.style.colorScheme = t === "light" ? "light" : "dark";
      var m = document.getElementById("metaColorScheme");
      if (m) m.setAttribute("content", t === "light" ? "light" : "dark");
      // Apply as soon as body exists (also patched again on DOMContentLoaded).
      document.addEventListener("DOMContentLoaded", function () {
        if (document.body) document.body.setAttribute("data-theme", t);
      });
    })();
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,600;0,9..40,700;1,9..40,400&family=Outfit:wght@500;600;700&display=swap" rel="stylesheet">
  <!-- Local Chart.js (same-origin); CDN fallback if /static missing -->
  <script src="/static/chart.umd.min.js" onerror="this.onerror=null;this.src='https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js'"></script>
  <style>
    :root {
      --bg0: #0c1222;
      --bg-mid: #0f172a;
      --bg1: #111827;
      --card: rgba(30, 41, 59, 0.72);
      --card-border: rgba(148, 163, 184, 0.12);
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --ok: #34d399;
      --bad: #fb7185;
      --warn: #fbbf24;
    }
    /* Explicit dark palette so toggling always matches (not only :root defaults). */
    html[data-theme="dark"] {
      color-scheme: dark;
      --bg0: #0c1222;
      --bg-mid: #0f172a;
      --bg1: #111827;
      --card: rgba(30, 41, 59, 0.72);
      --card-border: rgba(148, 163, 184, 0.12);
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --ok: #34d399;
      --bad: #fb7185;
      --warn: #fbbf24;
    }
    * { box-sizing: border-box; }
    html {
      scroll-behavior: smooth;
    }
    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
    }
    body {
      font-family: "DM Sans", system-ui, sans-serif;
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        radial-gradient(ellipse 120% 80% at 50% -30%, rgba(56, 189, 248, 0.12), transparent 50%),
        radial-gradient(ellipse 80% 50% at 100% 50%, rgba(167, 139, 250, 0.06), transparent),
        linear-gradient(165deg, var(--bg0) 0%, var(--bg-mid) 42%, var(--bg1) 100%);
      padding: 20px 20px 48px;
    }
    body::before {
      content: "";
      pointer-events: none;
      position: fixed;
      inset: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
      opacity: 0.45;
      z-index: 0;
    }
    html[data-theme="light"] body::before {
      opacity: 0.14;
    }
    .dash-shell {
      position: relative;
      z-index: 1;
      max-width: 1220px;
      margin: 0 auto;
    }
    .header-logo-wrap {
      flex-shrink: 0;
      padding: 10px 16px;
      border-radius: 16px;
      background: linear-gradient(145deg, rgba(30, 41, 59, 0.55) 0%, rgba(15, 23, 42, 0.35) 100%);
      border: 1px solid rgba(148, 163, 184, 0.18);
      box-shadow:
        0 1px 0 rgba(255, 255, 255, 0.06) inset,
        0 8px 28px rgba(0, 0, 0, 0.22),
        0 0 0 1px rgba(56, 189, 248, 0.12);
      backdrop-filter: blur(10px);
    }
    html[data-theme="light"] .header-logo-wrap {
      background: linear-gradient(145deg, rgba(255, 255, 255, 0.92) 0%, rgba(241, 245, 249, 0.75) 100%);
      border-color: rgba(100, 116, 139, 0.2);
      box-shadow:
        0 1px 0 rgba(255, 255, 255, 0.9) inset,
        0 6px 22px rgba(15, 23, 42, 0.08),
        0 0 0 1px rgba(2, 132, 199, 0.1);
    }
    .header-banner-img {
      height: 68px;
      width: auto;
      max-width: min(400px, 70vw);
      object-fit: contain;
      object-position: left center;
      display: block;
      border-radius: 10px;
    }
    @media (max-width: 600px) {
      .header-banner-img {
        height: 56px;
        max-width: min(340px, 88vw);
      }
    }
    .header-brand-text {
      min-width: 0;
    }
    .status-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px 20px;
      padding: 10px 14px;
      margin: -4px 0 20px;
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.45);
      border: 1px solid var(--card-border);
      backdrop-filter: blur(10px);
      font-size: 0.8rem;
    }
    html[data-theme="light"] .status-bar {
      background: rgba(255, 255, 255, 0.72);
    }
    .live-indicator {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 600;
      letter-spacing: 0.02em;
      font-family: "Outfit", "DM Sans", sans-serif;
    }
    .live-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #34d399;
      box-shadow: 0 0 0 3px rgba(52, 211, 153, 0.35);
      animation: pulse-dot 2s ease-in-out infinite;
    }
    @keyframes pulse-dot {
      50% { opacity: 0.65; transform: scale(0.92); }
    }
    .status-bar .sep {
      color: var(--card-border);
      user-select: none;
    }
    .kpi-summary-bar {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px 14px;
      margin: -8px 0 18px;
      padding: 14px 16px;
      border-radius: 14px;
      background: linear-gradient(135deg, rgba(56, 189, 248, 0.08), rgba(167, 139, 250, 0.06));
      border: 1px solid rgba(56, 189, 248, 0.22);
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.12);
    }
    @media (max-width: 900px) {
      .kpi-summary-bar { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 480px) {
      .kpi-summary-bar { grid-template-columns: 1fr; }
    }
    html[data-theme="light"] .kpi-summary-bar {
      background: linear-gradient(135deg, rgba(56, 189, 248, 0.1), rgba(167, 139, 250, 0.08));
    }
    .kpi-summary-bar .sum-item {
      min-width: 0;
      padding: 8px 10px;
      border-radius: 10px;
      background: rgba(15, 23, 42, 0.35);
      border: 1px solid var(--card-border);
    }
    html[data-theme="light"] .kpi-summary-bar .sum-item {
      background: rgba(255, 255, 255, 0.85);
    }
    .kpi-summary-bar .sum-item.sum-threat {
      border-color: rgba(251, 113, 133, 0.35);
      background: rgba(251, 113, 133, 0.08);
    }
    .kpi-summary-bar .sum-lab {
      display: block;
      font-size: 0.62rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--muted);
      margin-bottom: 6px;
    }
    .kpi-summary-bar .sum-val {
      font-family: "Outfit", "DM Sans", sans-serif;
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: var(--text);
      line-height: 1.25;
      word-break: break-word;
    }
    .kpi-summary-bar .sum-val.skeleton-text {
      min-height: 1.25em;
      border-radius: 6px;
      background: linear-gradient(90deg, rgba(148, 163, 184, 0.15), rgba(148, 163, 184, 0.28), rgba(148, 163, 184, 0.15));
      background-size: 200% 100%;
      animation: skeleton-shimmer 1.2s ease-in-out infinite;
      color: transparent;
    }
    @keyframes skeleton-shimmer {
      0% { background-position: 100% 0; }
      100% { background-position: -100% 0; }
    }
    body.dashboard-ready .kpi-summary-bar .sum-val.skeleton-text {
      animation: none;
      background: none;
      color: var(--text);
      min-height: unset;
    }
    .dashboard-loading {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 120px;
      margin: 0 0 16px;
      padding: 20px 18px;
      border-radius: 14px;
      border: 1px dashed rgba(56, 189, 248, 0.35);
      background: rgba(15, 23, 42, 0.25);
    }
    html[data-theme="light"] .dashboard-loading {
      background: rgba(241, 245, 249, 0.9);
    }
    body.dashboard-ready .dashboard-loading {
      display: none;
    }
    .loading-inner {
      text-align: center;
      max-width: 420px;
    }
    .loading-spinner {
      width: 36px;
      height: 36px;
      margin: 0 auto 12px;
      border: 3px solid rgba(56, 189, 248, 0.2);
      border-top-color: #38bdf8;
      border-radius: 50%;
      animation: spin-load 0.85s linear infinite;
    }
    @keyframes spin-load {
      to { transform: rotate(360deg); }
    }
    .loading-title {
      margin: 0 0 8px;
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text);
    }
    .loading-hint {
      margin: 0;
      font-size: 0.78rem;
      color: var(--muted);
      line-height: 1.5;
    }
    .loading-hint code {
      font-size: 0.72rem;
      padding: 1px 5px;
      border-radius: 4px;
      background: rgba(56, 189, 248, 0.12);
    }
    .chart-card-hint {
      font-size: 0.72rem;
      color: var(--muted);
      margin: 0 0 10px;
      padding: 8px 10px;
      border-radius: 8px;
      background: rgba(15, 23, 42, 0.3);
      border-left: 3px solid rgba(56, 189, 248, 0.5);
    }
    html[data-theme="light"] .chart-card-hint {
      background: rgba(241, 245, 249, 0.95);
    }
    .reason-cell {
      max-width: 280px;
      vertical-align: top;
    }
    .reason-expand summary {
      cursor: pointer;
      list-style: none;
      font-size: 0.78rem;
      line-height: 1.35;
      color: var(--text);
    }
    .reason-expand summary::-webkit-details-marker { display: none; }
    .reason-expand summary::before {
      content: "▸ ";
      color: var(--accent);
      font-size: 0.65rem;
    }
    .reason-expand[open] summary::before { content: "▾ "; }
    .reason-full {
      font-size: 0.72rem;
      color: var(--muted);
      white-space: pre-wrap;
      word-break: break-word;
      margin-top: 6px;
      padding: 8px 10px;
      border-radius: 8px;
      background: rgba(15, 23, 42, 0.45);
      border: 1px solid var(--card-border);
    }
    html[data-theme="light"] .reason-full {
      background: rgba(241, 245, 249, 0.95);
    }
    .tool-reasons-cell {
      max-width: 220px;
      font-size: 0.75rem;
      word-break: break-word;
    }
    .pii-legend-note {
      font-size: 0.72rem;
      color: var(--muted);
      margin: 0 0 10px;
    }
    .pii-urgent { color: #fb7185; font-weight: 600; }
    html[data-theme="light"] .pii-urgent { color: #e11d48; }
    .insight-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
      margin-bottom: 20px;
    }
    @media (max-width: 900px) { .insight-row { grid-template-columns: 1fr; } }
    .insight-card {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 16px 18px;
      backdrop-filter: blur(12px);
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.18);
    }
    html[data-theme="light"] .insight-card {
      box-shadow: 0 4px 20px rgba(15, 23, 42, 0.06);
    }
    .insight-card h3 {
      font-family: "Outfit", "DM Sans", sans-serif;
      font-size: 0.78rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin: 0 0 10px 0;
    }
    .insight-stat {
      font-family: "Outfit", "DM Sans", sans-serif;
      font-size: 1.85rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      line-height: 1.15;
      color: var(--text);
    }
    .insight-stat .unit {
      font-size: 1rem;
      font-weight: 600;
      color: var(--muted);
      margin-left: 2px;
    }
    .insight-lede {
      font-size: 0.8rem;
      color: var(--muted);
      line-height: 1.45;
      margin: 8px 0 0 0;
    }
    .kind-list {
      margin: 0;
      padding: 0;
      list-style: none;
      font-size: 0.8rem;
    }
    .kind-list li {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 6px 0;
      border-bottom: 1px solid var(--card-border);
    }
    .kind-list li:last-child { border-bottom: none; }
    .kind-list .k { color: var(--text); font-weight: 600; }
    .kind-list .v { color: var(--muted); font-variant-numeric: tabular-nums; }
    .link-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 4px;
    }
    a.link-chip {
      display: inline-flex;
      align-items: center;
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-decoration: none;
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.35);
      background: rgba(56, 189, 248, 0.08);
      transition: background 0.15s, border-color 0.15s;
    }
    a.link-chip:hover {
      background: rgba(56, 189, 248, 0.16);
      border-color: var(--accent);
    }
    html[data-theme="light"] a.link-chip {
      color: #0369a1;
      border-color: rgba(3, 105, 161, 0.35);
      background: rgba(56, 189, 248, 0.1);
    }
    .card-head {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px 16px;
      margin-bottom: 14px;
    }
    .card-head h2 {
      margin: 0;
    }
    .card-desc {
      font-size: 0.78rem;
      color: var(--muted);
      line-height: 1.4;
      max-width: 52ch;
      margin: 0;
      font-weight: 400;
      text-transform: none;
      letter-spacing: 0;
    }
    .header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }
    .header-brand {
      display: flex;
      align-items: center;
      gap: 16px;
      min-width: 0;
      flex-wrap: nowrap;
    }
    @media (max-width: 520px) {
      .header-brand { flex-wrap: wrap; }
    }
    .header h1 {
      font-size: 1.28rem;
      font-weight: 700;
      margin: 0;
      letter-spacing: -0.02em;
      color: var(--text);
    }
    html[data-theme="dark"] .header h1 {
      color: var(--text);
    }
    @supports ((-webkit-background-clip: text) or (background-clip: text)) {
      html[data-theme="dark"] .header h1 {
        background: linear-gradient(135deg, #f8fafc 0%, #94a3b8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        color: transparent;
      }
    }
    .header p { margin: 4px 0 0; font-size: 0.85rem; color: var(--muted); }
    .badge {
      background: linear-gradient(135deg, #f43f5e, #ec4899);
      color: white;
      padding: 6px 14px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      box-shadow: 0 4px 14px rgba(244, 63, 94, 0.35);
    }
    .alert-menu { position: relative; }
    .badge-btn {
      border: none;
      cursor: pointer;
      font: inherit;
      font-family: inherit;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .badge-btn .caret {
      font-size: 0.65rem;
      opacity: 0.9;
      transition: transform 0.15s ease;
    }
    .alert-menu.open .badge-btn .caret { transform: rotate(180deg); }
    .badge-btn:focus-visible {
      outline: 2px solid rgba(255, 255, 255, 0.85);
      outline-offset: 2px;
    }
    .alert-dropdown-panel {
      display: none;
      position: absolute;
      right: 0;
      top: calc(100% + 8px);
      min-width: min(380px, 92vw);
      max-width: 440px;
      max-height: 340px;
      overflow-y: auto;
      z-index: 100;
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 10px 10px 8px;
      box-shadow: 0 16px 48px rgba(0, 0, 0, 0.4);
      backdrop-filter: blur(12px);
    }
    .alert-menu.open .alert-dropdown-panel { display: block; }
    html[data-theme="light"] .alert-dropdown-panel {
      box-shadow: 0 12px 40px rgba(15, 23, 42, 0.12);
    }
    .alert-dropdown-inner .alert { margin-bottom: 8px; }
    .alert-dropdown-inner .alert:last-child { margin-bottom: 0; }
    .alert-ts {
      font-size: 0.65rem;
      color: var(--muted);
      margin-bottom: 4px;
      font-variant-numeric: tabular-nums;
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }
    .kpi {
      position: relative;
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 18px 18px 16px;
      overflow: hidden;
      backdrop-filter: blur(12px);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
    }
    .kpi::before {
      content: "";
      position: absolute;
      left: 0; top: 0; bottom: 0;
      width: 4px;
      border-radius: 14px 0 0 14px;
    }
    .kpi.req::before { background: linear-gradient(180deg, #38bdf8, #2563eb); }
    .kpi.block::before { background: linear-gradient(180deg, #fb7185, #e11d48); }
    .kpi.pii::before { background: linear-gradient(180deg, #2dd4bf, #0d9488); }
    .kpi.cost::before { background: linear-gradient(180deg, #fbbf24, #d97706); }
    .kpi h2 {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin: 0 0 6px 0;
      font-weight: 600;
    }
    .kpi .value {
      font-size: 1.65rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      font-variant-numeric: tabular-nums;
      font-family: "Outfit", "DM Sans", sans-serif;
      color: var(--text);
    }
    .kpi-foot {
      margin: 10px 0 0 0;
      font-size: 0.72rem;
      line-height: 1.35;
      color: var(--muted);
    }
    .card {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 18px;
      margin-bottom: 18px;
      backdrop-filter: blur(12px);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }
    .card h2 {
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--muted);
      margin: 0 0 14px 0;
      font-weight: 600;
      font-family: "Outfit", "DM Sans", sans-serif;
    }
    .chart-wrap { position: relative; height: 240px; width: 100%; }
    .chart-wrap.sm { height: 200px; }
    .charts-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 18px;
      margin-bottom: 18px;
    }
    @media (max-width: 1100px) { .charts-row { grid-template-columns: 1fr; } }
    .alerts {
      max-height: 220px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .alerts-prominent {
      max-height: 280px;
    }
    .alerts-insights-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
      margin-bottom: 18px;
    }
    @media (max-width: 900px) {
      .alerts-insights-row { grid-template-columns: 1fr; }
    }
    .alerts-panel-card, .insights-panel-card { margin-bottom: 0; }
    .insights-feed {
      display: flex;
      flex-direction: column;
      gap: 10px;
      max-height: 280px;
      overflow-y: auto;
    }
    .insight-item {
      border-left: 4px solid var(--accent);
      border-radius: 10px;
      padding: 10px 12px;
      font-size: 0.82rem;
      background: rgba(51, 65, 85, 0.45);
    }
    .insight-item.warning { border-left-color: var(--warn); }
    .insight-item.info { border-left-color: var(--accent); }
    html[data-theme="light"] .insight-item {
      background: rgba(241, 245, 249, 0.95);
    }
    .insight-title { font-weight: 700; margin-bottom: 4px; color: var(--text); font-family: "Outfit", "DM Sans", sans-serif; }
    .insight-detail { color: var(--muted); font-size: 0.78rem; line-height: 1.45; }
    .insights-empty { color: var(--muted); font-size: 0.85rem; margin: 0; padding: 4px 0 8px; line-height: 1.45; }
    .signal-badge {
      display: inline-block;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 0.62rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      white-space: nowrap;
    }
    .signal-hot { background: rgba(251, 113, 133, 0.22); color: #fda4af; border: 1px solid rgba(251, 113, 133, 0.4); }
    .signal-watch { background: rgba(251, 191, 36, 0.2); color: #fde68a; border: 1px solid rgba(251, 191, 36, 0.38); }
    .signal-ok { background: rgba(52, 211, 153, 0.16); color: #86efac; border: 1px solid rgba(52, 211, 153, 0.32); }
    html[data-theme="light"] .signal-hot { color: #9f1239; }
    html[data-theme="light"] .signal-watch { color: #92400e; }
    html[data-theme="light"] .signal-ok { color: #065f46; }
    .alert {
      font-size: 0.8rem;
      padding: 10px 12px;
      border-radius: 10px;
      border-left: 4px solid var(--warn);
      background: rgba(51, 65, 85, 0.6);
      color: var(--text);
    }
    .alert.critical { border-left-color: #f43f5e; }
    .dash-footer {
      text-align: center;
      margin-top: 32px;
      padding: 20px 12px 8px;
      font-size: 0.75rem;
      color: var(--muted);
      border-top: 1px solid var(--card-border);
      line-height: 1.6;
    }
    .dash-footer strong { color: #38bdf8; }
    .dash-footer .footer-links {
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 8px 14px;
    }
    .dash-footer .footer-links a {
      color: var(--muted);
      text-decoration: none;
      border-bottom: 1px solid transparent;
    }
    .dash-footer .footer-links a:hover {
      color: var(--accent);
      border-bottom-color: rgba(56, 189, 248, 0.4);
    }
    html[data-theme="light"] {
      color-scheme: light;
      --bg0: #f8fafc;
      --bg-mid: #eef2f7;
      --bg1: #e2e8f0;
      --card: rgba(255, 255, 255, 0.94);
      --card-border: rgba(100, 116, 139, 0.22);
      --text: #0f172a;
      --muted: #64748b;
      --accent: #0284c7;
      --ok: #059669;
      --bad: #e11d48;
      --warn: #d97706;
    }
    html[data-theme="light"] body,
    body[data-theme="light"] {
      background:
        radial-gradient(ellipse 120% 80% at 50% -25%, rgba(56, 189, 248, 0.1), transparent 48%),
        radial-gradient(ellipse 70% 50% at 100% 30%, rgba(167, 139, 250, 0.06), transparent),
        linear-gradient(165deg, var(--bg0) 0%, var(--bg-mid) 42%, var(--bg1) 100%);
    }
    html[data-theme="light"] .header h1 {
      color: #0f172a;
      background: none;
      -webkit-text-fill-color: unset;
    }
    @supports ((-webkit-background-clip: text) or (background-clip: text)) {
      html[data-theme="light"] .header h1 {
        background: linear-gradient(135deg, #0f172a 0%, #475569 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        color: transparent;
      }
    }
    html[data-theme="light"] .kpi {
      box-shadow: 0 4px 24px rgba(15, 23, 42, 0.06);
    }
    html[data-theme="light"] .card {
      box-shadow: 0 4px 24px rgba(15, 23, 42, 0.06);
    }
    html[data-theme="light"] .alert {
      background: rgba(241, 245, 249, 0.95);
      color: var(--text);
      border: 1px solid var(--card-border);
      border-left-width: 4px;
    }
    html[data-theme="light"] .dash-footer strong { color: #0284c7; }
    .header-right {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .theme-toggle {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--card);
      border: 1px solid var(--card-border);
      color: var(--text);
      border-radius: 10px;
      padding: 8px 14px;
      cursor: pointer;
      font-family: inherit;
      font-size: 0.85rem;
      font-weight: 600;
      box-shadow: 0 2px 12px rgba(0, 0, 0, 0.12);
    }
    .theme-toggle:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    html[data-theme="light"] .theme-toggle:hover {
      color: #0284c7;
      border-color: #38bdf8;
    }
    .latency-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      font-variant-numeric: tabular-nums;
    }
    .latency-row .lab { display: block; font-size: 0.65rem; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
    .latency-row .num { font-size: 1.25rem; font-weight: 700; }
    .burn-text { font-size: 0.95rem; line-height: 1.6; color: var(--text); }
    .burn-text .muted { color: var(--muted); font-size: 0.8rem; }
    .finops-kpis {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin: 12px 0 14px;
    }
    @media (max-width: 900px) {
      .finops-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    .finops-kpi {
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 10px 12px;
      background: rgba(15, 23, 42, 0.28);
    }
    html[data-theme="light"] .finops-kpi { background: #f8fafc; }
    .finops-kpi .fk-label {
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.02em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .finops-kpi .fk-value {
      margin-top: 4px;
      font-size: 1.15rem;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
    }
    .finops-kpi .fk-sub {
      margin-top: 2px;
      font-size: 0.72rem;
      color: var(--muted);
    }
    .finops-kpi.saved .fk-value { color: #34d399; }
    .finops-kpi.avoided .fk-value { color: #7dd3fc; }
    .finops-kpi.would .fk-value { color: #fbbf24; }
    .finops-charts {
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      gap: 12px;
      margin-bottom: 12px;
    }
    @media (max-width: 1100px) {
      .finops-charts { grid-template-columns: 1fr; }
    }
    .finops-charts .chart-wrap.sm { height: 220px; }
    span.muted { color: var(--muted); font-size: 0.85rem; }
    p.muted { color: var(--muted); }
    .pillar-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin-bottom: 18px;
    }
    .pillar {
      border: 1px solid var(--card-border);
      background: rgba(15, 23, 42, 0.24);
      border-radius: 10px;
      padding: 10px 12px;
      transition: border-color 0.2s, box-shadow 0.2s, transform 0.2s;
    }
    .pillar:hover {
      border-color: rgba(56, 189, 248, 0.28);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.12);
      transform: translateY(-1px);
    }
    html[data-theme="light"] .pillar {
      background: rgba(241, 245, 249, 0.82);
    }
    .pillar .name {
      font-size: 0.75rem;
      font-weight: 700;
      margin-bottom: 6px;
      letter-spacing: 0.01em;
    }
    .pill {
      display: inline-block;
      border-radius: 999px;
      font-size: 0.62rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 700;
      padding: 3px 8px;
      margin-bottom: 6px;
    }
    .pill.healthy { background: rgba(52, 211, 153, 0.2); color: #86efac; border: 1px solid rgba(52, 211, 153, 0.35); }
    .pill.active { background: rgba(251, 191, 36, 0.2); color: #fde68a; border: 1px solid rgba(251, 191, 36, 0.35); }
    .pill.idle { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.35); }
    html[data-theme="light"] .pill.healthy { color: #065f46; }
    html[data-theme="light"] .pill.active { color: #92400e; }
    html[data-theme="light"] .pill.idle { color: #334155; }
    .pillar .detail {
      font-size: 0.73rem;
      color: var(--muted);
      line-height: 1.35;
    }
    .pillar-governance {
      border-color: rgba(129, 140, 248, 0.35);
      background: linear-gradient(145deg, rgba(30, 27, 75, 0.45), rgba(15, 23, 42, 0.28));
    }
    html[data-theme="light"] .pillar-governance {
      background: linear-gradient(145deg, rgba(238, 242, 255, 0.95), rgba(241, 245, 249, 0.82));
      border-color: rgba(99, 102, 241, 0.28);
    }
    .pillar-section-label {
      grid-column: 1 / -1;
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin: 4px 0 0;
      font-weight: 700;
    }
    .governance-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 10px;
      margin-top: 8px;
    }
    .gov-tile {
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 10px 12px;
      background: rgba(15, 23, 42, 0.22);
    }
    html[data-theme="light"] .gov-tile {
      background: rgba(248, 250, 252, 0.9);
    }
    .gov-tile .gov-name {
      font-size: 0.72rem;
      font-weight: 700;
      margin-bottom: 4px;
    }
    .gov-tile .gov-state {
      font-size: 0.78rem;
      font-variant-numeric: tabular-nums;
    }
    .gov-tile .gov-state.on { color: #86efac; }
    .gov-tile .gov-state.off { color: var(--muted); }
    html[data-theme="light"] .gov-tile .gov-state.on { color: #047857; }
    .gov-tile .gov-meta {
      font-size: 0.68rem;
      color: var(--muted);
      margin-top: 4px;
      line-height: 1.35;
    }
    .audit-chain-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 10px;
      margin-top: 8px;
    }
    .audit-chain-hash {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.72rem;
      word-break: break-all;
      color: #a5b4fc;
    }
    html[data-theme="light"] .audit-chain-hash { color: #4338ca; }
    .audit-links-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.78rem;
      margin-top: 12px;
    }
    .audit-links-table th,
    .audit-links-table td {
      text-align: left;
      padding: 6px 8px;
      border-bottom: 1px solid var(--card-border);
      vertical-align: top;
    }
    .audit-links-table th { color: var(--muted); font-weight: 600; }
    .observe-banner {
      display: none;
      margin: 0 0 14px;
      padding: 12px 16px;
      border-radius: 10px;
      border: 1px solid rgba(251, 191, 36, 0.45);
      background: linear-gradient(90deg, rgba(251, 191, 36, 0.18), rgba(15, 23, 42, 0.35));
      color: #fde68a;
      font-weight: 700;
      letter-spacing: 0.02em;
    }
    .observe-banner.visible { display: block; }
    html[data-theme="light"] .observe-banner {
      background: linear-gradient(90deg, rgba(251, 191, 36, 0.28), rgba(255, 255, 255, 0.85));
      color: #92400e;
    }
    .observe-banner .nudge {
      font-weight: 500;
      font-size: 0.85rem;
      opacity: 0.9;
      margin-top: 4px;
    }
    .onboarding-card { display: none; }
    .onboarding-card.visible { display: block; }
    .onboard-list { margin: 8px 0 0; padding-left: 1.2rem; }
    .onboard-list li { margin: 6px 0; }
    .onboard-list li.done { color: #86efac; text-decoration: line-through; }
    html[data-theme="light"] .onboard-list li.done { color: #047857; }
    .posture-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 10px;
      margin-top: 8px;
    }
    .grade-legend {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 12px;
      align-items: center;
      margin-top: 10px;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid var(--card-border);
      background: rgba(15, 23, 42, 0.35);
      font-size: 0.78rem;
      color: var(--muted);
    }
    html[data-theme="light"] .grade-legend { background: rgba(248, 250, 252, 0.9); }
    .grade-legend .gl-title { font-weight: 700; color: var(--text, #e2e8f0); margin-right: 4px; }
    .grade-legend .gl-item strong { margin-right: 4px; }
    .grade-legend .gl-item.grade-A strong { color: #86efac; }
    .grade-legend .gl-item.grade-B strong { color: #a3e635; }
    .grade-legend .gl-item.grade-C strong { color: #fbbf24; }
    .grade-legend .gl-item.grade-D strong { color: #fb923c; }
    .grade-legend .gl-item.grade-F strong { color: #f87171; }
    html[data-theme="light"] .grade-legend .gl-item.grade-A strong { color: #047857; }
    .grade-legend .gl-note { flex-basis: 100%; font-size: 0.72rem; opacity: 0.9; }
    .grade-tile {
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 12px;
      cursor: pointer;
      background: rgba(15, 23, 42, 0.22);
      transition: border-color 0.15s ease;
    }
    .grade-tile:hover, .grade-tile:focus { border-color: #38bdf8; outline: none; }
    html[data-theme="light"] .grade-tile { background: rgba(248, 250, 252, 0.9); }
    .grade-tile .g-label { font-size: 0.72rem; font-weight: 700; color: var(--muted); }
    .grade-tile .g-letter {
      font-size: 2rem;
      font-weight: 800;
      line-height: 1.1;
      font-variant-numeric: tabular-nums;
    }
    .grade-tile .g-meta { font-size: 0.68rem; color: var(--muted); margin-top: 4px; }
    .grade-A .g-letter { color: #86efac; }
    .grade-B .g-letter { color: #a3e635; }
    .grade-C .g-letter { color: #fbbf24; }
    .grade-D .g-letter { color: #fb923c; }
    .grade-F .g-letter { color: #fb7185; }
    .grade-none .g-letter { color: var(--muted); font-size: 1.2rem; }
    html[data-theme="light"] .grade-A .g-letter { color: #047857; }
    .asi-heat {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 8px;
      margin-top: 10px;
    }
    @media (max-width: 900px) {
      .asi-heat { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    .asi-cell {
      border-radius: 8px;
      padding: 10px 8px;
      border: 1px solid var(--card-border);
      min-height: 72px;
      font-size: 0.72rem;
      text-align: left;
      color: inherit;
      cursor: pointer;
      font-family: inherit;
      width: 100%;
    }
    .asi-cell .asi-id { font-weight: 800; letter-spacing: 0.04em; }
    .asi-cell .asi-title { margin-top: 4px; color: var(--muted); line-height: 1.3; }
    .asi-covered { background: rgba(52, 211, 153, 0.16); border-color: rgba(52, 211, 153, 0.35); }
    .asi-findings { background: rgba(251, 191, 36, 0.16); border-color: rgba(251, 191, 36, 0.4); }
    .asi-unaddressed { background: rgba(100, 116, 139, 0.12); }
    .compliance-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    .spark-row { display: flex; align-items: flex-end; gap: 3px; height: 40px; margin-top: 8px; }
    .spark-bar {
      flex: 1;
      min-width: 4px;
      border-radius: 3px 3px 0 0;
      background: linear-gradient(180deg, #fb7185, #be123c);
      opacity: 0.85;
    }
    .drift-kpis {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin: 12px 0 14px;
    }
    @media (max-width: 900px) {
      .drift-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    .drift-kpi {
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 10px 12px;
      background: rgba(15, 23, 42, 0.28);
    }
    html[data-theme="light"] .drift-kpi { background: #f8fafc; }
    .drift-kpi .dk-label {
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.02em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .drift-kpi .dk-value {
      margin-top: 4px;
      font-size: 1.15rem;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
    }
    .drift-kpi .dk-sub { margin-top: 2px; font-size: 0.72rem; color: var(--muted); }
    .drift-kpi.rising .dk-value { color: #fb7185; }
    .drift-kpi.falling .dk-value { color: #34d399; }
    .drift-kpi.stable .dk-value { color: #7dd3fc; }
    .drift-charts {
      display: grid;
      grid-template-columns: 1.4fr 1fr;
      gap: 12px;
      margin-bottom: 12px;
    }
    @media (max-width: 1100px) {
      .drift-charts { grid-template-columns: 1fr; }
    }
    .drift-charts .chart-wrap.sm { height: 240px; }
    .drift-path {
      font-size: 0.72rem;
      color: var(--muted);
      margin-top: 10px;
      word-break: break-all;
    }
    .why-cell { font-size: 0.72rem; max-width: 180px; }
    .why-cell .why-pillar { font-weight: 700; color: #7dd3fc; }
    html[data-theme="light"] .why-cell .why-pillar { color: #0369a1; }
    .attack-cat-label {
      font-weight: 700;
      font-size: 0.82rem;
      color: var(--text);
      margin-bottom: 4px;
    }
    .owasp-chips { display: flex; flex-wrap: wrap; gap: 4px; margin: 4px 0 6px; }
    .owasp-chip {
      appearance: none;
      border: 1px solid rgba(125, 211, 252, 0.35);
      background: rgba(14, 165, 233, 0.12);
      color: #7dd3fc;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.02em;
      cursor: pointer;
      line-height: 1.4;
    }
    .owasp-chip:hover, .owasp-chip:focus-visible {
      background: rgba(14, 165, 233, 0.28);
      outline: none;
    }
    .owasp-chip-mcp { border-color: rgba(167, 139, 250, 0.4); background: rgba(139, 92, 246, 0.14); color: #c4b5fd; }
    .owasp-chip-asi { border-color: rgba(251, 146, 60, 0.4); background: rgba(251, 146, 60, 0.14); color: #fdba74; }
    .owasp-chip-llm { border-color: rgba(52, 211, 153, 0.4); background: rgba(16, 185, 129, 0.14); color: #6ee7b7; }
    html[data-theme="light"] .owasp-chip { color: #0369a1; border-color: #7dd3fc; background: #e0f2fe; }
    html[data-theme="light"] .owasp-chip-mcp { color: #6d28d9; border-color: #c4b5fd; background: #ede9fe; }
    html[data-theme="light"] .owasp-chip-asi { color: #c2410c; border-color: #fdba74; background: #ffedd5; }
    html[data-theme="light"] .owasp-chip-llm { color: #047857; border-color: #6ee7b7; background: #d1fae5; }
    .owasp-cell { max-width: 220px; }
    .forensics-kv .owasp-chips-dd { margin: 0; }
    .agent-scope { font-size: 0.75rem; margin-top: 8px; }
    .agent-scope dt { font-weight: 700; margin-top: 6px; }
    .agent-scope dd { margin: 2px 0 0 12px; color: var(--muted); }
    .posture-findings { margin-top: 12px; display: none; }
    .posture-findings.visible { display: block; }
    .prevalidate-box {
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid var(--card-border);
      background: rgba(15, 23, 42, 0.22);
    }
    html[data-theme="light"] .prevalidate-box { background: rgba(248, 250, 252, 0.9); }
    .prevalidate-box .pv-head {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 14px;
      align-items: baseline;
      margin-bottom: 8px;
    }
    .prevalidate-box .pv-head strong { font-size: 0.9rem; }
    .issue-guide {
      margin: 12px 0;
      padding: 12px 14px;
      border-radius: 10px;
      border: 1px solid var(--card-border);
      background: rgba(15, 23, 42, 0.35);
      font-size: 0.85rem;
      line-height: 1.45;
    }
    html[data-theme="light"] .issue-guide { background: #f1f5f9; }
    .issue-guide h4 {
      margin: 0 0 6px;
      font-size: 0.95rem;
    }
    .issue-guide .ig-why { margin: 8px 0; color: var(--muted); }
    .issue-guide ol {
      margin: 6px 0 10px;
      padding-left: 1.25rem;
    }
    .issue-guide ol li { margin: 4px 0; }
    .issue-guide .ig-knobs {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin: 8px 0;
    }
    .issue-guide .ig-knob {
      font-size: 0.72rem;
      font-family: ui-monospace, monospace;
      padding: 2px 8px;
      border-radius: 6px;
      border: 1px solid var(--card-border);
      background: rgba(125, 211, 252, 0.12);
    }
    .issue-guide .ig-refs { margin: 8px 0 0; padding-left: 1.1rem; }
    .issue-guide .ig-refs a { color: #7dd3fc; }
    html[data-theme="light"] .issue-guide .ig-refs a { color: #0369a1; }
    .issue-guide .ig-fw {
      margin-top: 10px;
      font-size: 0.78rem;
      color: var(--muted);
    }
    .date-filter-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: end;
      margin: 0 0 14px;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid var(--card-border);
      background: rgba(15, 23, 42, 0.28);
    }
    html[data-theme="light"] .date-filter-bar {
      background: rgba(248, 250, 252, 0.95);
    }
    .date-filter-bar label {
      display: flex;
      flex-direction: column;
      gap: 4px;
      font-size: 0.72rem;
      color: var(--muted);
      font-weight: 600;
    }
    .date-filter-bar input[type="date"],
    .date-filter-bar select {
      font: inherit;
      font-size: 0.85rem;
      color: var(--text);
      background: rgba(15, 23, 42, 0.45);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 6px 10px;
      min-width: 150px;
    }
    html[data-theme="light"] .date-filter-bar input[type="date"],
    html[data-theme="light"] .date-filter-bar select {
      background: #fff;
    }
    .tax-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 8px 0 4px;
    }
    .tax-tab {
      border: 1px solid var(--card-border);
      background: transparent;
      color: var(--muted);
      border-radius: 999px;
      padding: 6px 12px;
      font: inherit;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
    }
    .tax-tab.active {
      color: #0f172a;
      background: #38bdf8;
      border-color: #38bdf8;
    }
    html[data-theme="light"] .tax-tab.active {
      color: #fff;
      background: #0284c7;
      border-color: #0284c7;
    }
    .attack-matrix-wrap { overflow-x: auto; margin-top: 8px; }
    .attack-matrix {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
    }
    .attack-matrix th, .attack-matrix td {
      border-bottom: 1px solid var(--card-border);
      padding: 8px 10px;
      text-align: left;
      vertical-align: top;
    }
    .attack-matrix th { color: var(--muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; }
    .intensity {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.7rem;
      font-weight: 700;
    }
    .intensity-quiet { background: rgba(100,116,139,0.2); color: var(--muted); }
    .intensity-watch { background: rgba(251,191,36,0.2); color: #fbbf24; }
    .intensity-active { background: rgba(251,146,60,0.22); color: #fb923c; }
    .intensity-hot { background: rgba(251,113,133,0.25); color: #fb7185; }
    html[data-theme="light"] .intensity-watch { color: #92400e; }
    html[data-theme="light"] .intensity-active { color: #c2410c; }
    html[data-theme="light"] .intensity-hot { color: #be123c; }
    .detail-modal-body {
      max-height: min(70vh, 640px);
      overflow: auto;
      font-size: 0.8rem;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .trace-steps { margin: 10px 0 0; padding: 0; list-style: none; }
    .trace-steps li {
      border-left: 3px solid rgba(56,189,248,0.45);
      padding: 6px 10px;
      margin: 0 0 6px;
      background: rgba(15,23,42,0.25);
      border-radius: 0 8px 8px 0;
    }
    html[data-theme="light"] .trace-steps li { background: #f8fafc; }
    .trace-steps .t-pillar { font-weight: 700; color: #7dd3fc; }
    html[data-theme="light"] .trace-steps .t-pillar { color: #0369a1; }
    .btn-linkish {
      background: none;
      border: none;
      color: var(--accent);
      cursor: pointer;
      font: inherit;
      font-size: 0.78rem;
      padding: 0;
      text-decoration: underline;
    }
    .forensics-layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
      gap: 14px;
      align-items: start;
      margin-top: 4px;
    }
    @media (max-width: 1100px) {
      .forensics-layout { grid-template-columns: 1fr; }
    }
    .forensics-list .tool-table-wrap { margin-top: 0; }
    .forensics-list .tool-table tbody tr {
      cursor: pointer;
    }
    .forensics-list .tool-table tbody tr:hover td {
      background: rgba(56, 189, 248, 0.06);
    }
    .forensics-list .tool-table tbody tr.is-selected td {
      background: rgba(56, 189, 248, 0.14);
    }
    .forensics-list .tool-table tbody tr.is-selected td:first-child {
      box-shadow: inset 3px 0 0 var(--accent);
    }
    .forensics-detail {
      position: sticky;
      top: 72px;
      border: 1px solid var(--card-border);
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.45);
      padding: 12px 14px 14px;
      min-height: 280px;
      max-height: min(78vh, 720px);
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    html[data-theme="light"] .forensics-detail {
      background: #f8fafc;
    }
    .forensics-detail-empty {
      margin: auto;
      text-align: center;
      color: var(--muted);
      font-size: 0.85rem;
      padding: 24px 12px;
      line-height: 1.5;
    }
    .forensics-detail-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 10px;
    }
    .forensics-detail-head h3 {
      margin: 0;
      font-size: 0.95rem;
      font-weight: 700;
      line-height: 1.3;
      word-break: break-word;
    }
    .forensics-detail-meta {
      font-size: 0.75rem;
      color: var(--muted);
      margin: 4px 0 0;
      line-height: 1.4;
    }
    .forensics-tabs {
      display: flex;
      gap: 4px;
      flex-wrap: wrap;
      margin: 0 0 10px;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 8px;
    }
    .forensics-tab {
      padding: 5px 12px;
      font-size: 0.72rem;
      font-weight: 600;
      font-family: inherit;
      border-radius: 6px;
      border: 1px solid transparent;
      background: transparent;
      color: var(--muted);
      cursor: pointer;
    }
    .forensics-tab:hover { color: var(--text); }
    .forensics-tab.is-active {
      color: var(--accent);
      background: rgba(56, 189, 248, 0.12);
      border-color: rgba(56, 189, 248, 0.35);
    }
    html[data-theme="light"] .forensics-tab.is-active {
      color: #0369a1;
    }
    .forensics-detail-body {
      flex: 1;
      overflow: auto;
      font-size: 0.8rem;
      min-height: 0;
    }
    .forensics-detail-body[hidden] { display: none !important; }
    .forensics-kv {
      display: grid;
      grid-template-columns: 88px 1fr;
      gap: 6px 10px;
      margin: 0 0 12px;
      font-size: 0.78rem;
    }
    .forensics-kv dt { color: var(--muted); margin: 0; }
    .forensics-kv dd { margin: 0; word-break: break-word; }
    .forensics-detail .trace-steps { margin-top: 0; }
    .forensics-detail pre {
      margin: 0;
      padding: 10px;
      border-radius: 8px;
      background: rgba(0, 0, 0, 0.28);
      border: 1px solid var(--card-border);
      font-size: 0.72rem;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: none;
    }
    html[data-theme="light"] .forensics-detail pre {
      background: #fff;
    }
    .forensics-detail .fd-hint {
      font-size: 0.75rem;
      color: var(--muted);
      margin: 0 0 8px;
      line-height: 1.4;
    }
    .tool-table-wrap {
      overflow-x: auto;
      margin-top: 6px;
    }
    table.tool-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
      font-variant-numeric: tabular-nums;
    }
    .tool-table th, .tool-table td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--card-border);
      white-space: nowrap;
    }
    .tool-table th {
      color: var(--muted);
      font-size: 0.67rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .tool-table td:last-child {
      max-width: 260px;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .forensics-list .tool-table td.reason-cell {
      white-space: normal;
      max-width: 220px;
    }
    .tenant-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px 14px;
      margin-bottom: 14px;
      padding: 12px 14px;
      border-radius: 10px;
      background: rgba(15, 23, 42, 0.35);
      border: 1px solid var(--card-border);
    }
    html[data-theme="light"] .tenant-bar {
      background: rgba(241, 245, 249, 0.9);
    }
    .tenant-bar label {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
    }
    .tenant-select {
      min-width: 180px;
      padding: 8px 12px;
      border-radius: 8px;
      border: 1px solid var(--card-border);
      background: var(--card);
      color: var(--text);
      font-family: inherit;
      font-size: 0.85rem;
    }
    .btn-apply, .btn-ghost {
      padding: 8px 16px;
      border-radius: 8px;
      font-family: inherit;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--card-border);
      background: linear-gradient(135deg, #38bdf8, #2563eb);
      color: white;
    }
    .btn-ghost {
      background: var(--card);
      color: var(--text);
    }
    .btn-apply:hover, .btn-ghost:hover {
      filter: brightness(1.06);
    }
    .btn-row-act {
      display: inline-flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .btn-mini {
      padding: 4px 10px;
      font-size: 0.7rem;
      font-weight: 600;
      border-radius: 6px;
      border: 1px solid var(--card-border);
      background: rgba(56, 189, 248, 0.12);
      color: var(--accent);
      cursor: pointer;
      font-family: inherit;
    }
    .btn-mini:hover {
      border-color: var(--accent);
    }
    html[data-theme="light"] .btn-mini {
      color: #0369a1;
    }
    .modal-overlay {
      display: none;
      position: fixed;
      inset: 0;
      z-index: 200;
      align-items: center;
      justify-content: center;
      padding: 20px;
      background: rgba(15, 23, 42, 0.65);
    }
    .modal-overlay.open { display: flex; }
    .modal-box {
      width: min(640px, 100%);
      max-height: min(80vh, 560px);
      overflow: auto;
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 18px 20px;
      box-shadow: 0 24px 64px rgba(0, 0, 0, 0.45);
    }
    .modal-box h3 {
      margin: 0 0 12px 0;
      font-size: 1rem;
      font-family: "Outfit", "DM Sans", sans-serif;
    }
    .modal-box pre {
      margin: 0;
      font-size: 0.72rem;
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-word;
      color: var(--text);
    }
    .modal-close {
      float: right;
      border: none;
      background: transparent;
      color: var(--muted);
      font-size: 1.25rem;
      cursor: pointer;
      line-height: 1;
      padding: 4px 8px;
    }
    .modal-close:hover { color: var(--text); }
    .dash-jump {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px 10px;
      margin: -8px 0 18px;
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.35);
      border: 1px solid var(--card-border);
    }
    html[data-theme="light"] .dash-jump {
      background: rgba(255, 255, 255, 0.55);
    }
    .dash-jump .jump-label {
      font-size: 0.65rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-right: 4px;
    }
    .dash-jump a {
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--accent);
      text-decoration: none;
      padding: 5px 10px;
      border-radius: 999px;
      border: 1px solid rgba(56, 189, 248, 0.28);
      background: rgba(56, 189, 248, 0.06);
      transition: background 0.15s, border-color 0.15s;
    }
    .dash-jump a:hover {
      background: rgba(56, 189, 248, 0.14);
      border-color: var(--accent);
    }
    html[data-theme="light"] .dash-jump a {
      color: #0369a1;
    }
    .dash-jump .jump-actions {
      margin-left: auto;
      display: inline-flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .btn-export {
      font-family: inherit;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      padding: 6px 12px;
      border-radius: 999px;
      border: 1px solid rgba(167, 139, 250, 0.45);
      background: rgba(167, 139, 250, 0.12);
      color: #c4b5fd;
    }
    .btn-export:hover {
      filter: brightness(1.08);
      border-color: #a78bfa;
    }
    html[data-theme="light"] .btn-export {
      color: #5b21b6;
    }
    .insight-summary {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 0 0 12px 0;
      min-height: 1.5em;
    }
    .insight-chip {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 0.68rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .insight-chip.warn {
      background: rgba(251, 191, 36, 0.18);
      color: #fde68a;
      border: 1px solid rgba(251, 191, 36, 0.35);
    }
    .insight-chip.info {
      background: rgba(56, 189, 248, 0.14);
      color: #7dd3fc;
      border: 1px solid rgba(56, 189, 248, 0.32);
    }
    html[data-theme="light"] .insight-chip.warn { color: #92400e; }
    html[data-theme="light"] .insight-chip.info { color: #0369a1; }
    .back-top {
      position: fixed;
      right: 20px;
      bottom: 24px;
      z-index: 150;
      width: 44px;
      height: 44px;
      border-radius: 12px;
      border: 1px solid var(--card-border);
      background: var(--card);
      color: var(--accent);
      font-size: 1.15rem;
      line-height: 1;
      cursor: pointer;
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.35);
      opacity: 0;
      pointer-events: none;
      transform: translateY(12px);
      transition: opacity 0.2s, transform 0.2s;
    }
    .back-top.visible {
      opacity: 1;
      pointer-events: auto;
      transform: translateY(0);
    }
    .back-top:hover {
      border-color: var(--accent);
    }
    @media (prefers-reduced-motion: reduce) {
      .back-top { transition: none; }
    }
  </style>
</head>
<body>
  <!--MCP_BASTION_METRICS_BOOTSTRAP-->
  <div class="dash-shell">
  <div class="header">
    <div class="header-brand">
      <div class="header-logo-wrap">
      <img
        src="/images/mcp-bastian.png"
        alt="MCP-Bastion"
        class="header-banner-img"
        width="400"
        height="68"
        loading="eager"
        decoding="async"
        onerror="if(!this.dataset._fb){this.dataset._fb='1';this.src='/static/mcp-bastian.png';return;}this.onerror=null;this.src='/static/mcp-bastian.svg'"
      />
      </div>
      <div class="header-brand-text">
        <h1>MCP-Bastion</h1>
        <p>Live security &amp; FinOps · refreshes every 2s</p>
      </div>
    </div>
    <div class="header-right">
      <button type="button" class="theme-toggle" id="themeToggle" aria-pressed="true" aria-label="Switch to light or dark theme">Switch to light theme</button>
      <div class="alert-menu" id="alertMenu">
        <button type="button" class="badge badge-btn" id="alertCountBtn" aria-expanded="false" aria-haspopup="true" aria-controls="alertDropdownPanel">
          <span id="alertCountLabel">0 Alerts</span><span class="caret" aria-hidden="true">v</span>
        </button>
        <div class="alert-dropdown-panel" id="alertDropdownPanel" role="region" aria-label="Active alerts">
          <div class="alert-dropdown-inner" id="alertDropdownList"></div>
        </div>
      </div>
    </div>
  </div>

  <div class="status-bar" role="status">
    <span class="live-indicator"><span class="live-dot" aria-hidden="true"></span><span id="liveLabel">Live</span></span>
    <span class="sep" aria-hidden="true">·</span>
    <span id="pollStatus">Connecting to MCP-Bastion metrics…</span>
    <span class="sep" aria-hidden="true">·</span>
    <span class="muted">Data age</span>
    <span id="dataFreshness" class="muted">-</span>
    <span class="sep" aria-hidden="true">·</span>
    <span id="windowStartLine" class="muted"></span>
  </div>

  <div class="kpi-summary-bar" id="kpiSummaryBar" role="region" aria-label="At a glance">
    <div class="sum-item">
      <span class="sum-lab">Total requests</span>
      <span class="sum-val skeleton-text" id="sumTotalReq">-</span>
    </div>
    <div class="sum-item">
      <span class="sum-lab">Block rate</span>
      <span class="sum-val skeleton-text" id="sumBlockPct">-</span>
    </div>
    <div class="sum-item sum-threat">
      <span class="sum-lab">Top threat</span>
      <span class="sum-val skeleton-text" id="sumTopThreat" title="">-</span>
    </div>
    <div class="sum-item">
      <span class="sum-lab">Active users / tenants</span>
      <span class="sum-val skeleton-text" id="sumActiveUsers">-</span>
    </div>
  </div>

  <div class="dashboard-loading" id="dashboardLoading" aria-live="polite" aria-busy="true">
    <div class="loading-inner">
      <div class="loading-spinner" aria-hidden="true"></div>
      <p class="loading-title">Preparing your security overview…</p>
      <p class="loading-hint">If charts stay empty, route MCP tool traffic through middleware that reports to <code>MetricsStore</code>. Poll: <code>/api/metrics</code> every 2s.</p>
    </div>
  </div>

  <div class="observe-banner" id="observeBanner" role="status" aria-live="polite">
    <div id="observeBannerTitle">OBSERVE MODE</div>
    <div class="nudge" id="observeBannerNudge"></div>
  </div>

  <div class="card onboarding-card" id="onboardingCard">
    <div class="card-head">
      <h2>Get started</h2>
      <p class="card-desc">First-run checklist - local files and middleware only (no cloud required).</p>
    </div>
    <ol class="onboard-list" id="onboardingList"></ol>
  </div>

  <div class="date-filter-bar" id="dateFilterBar" aria-label="Date and report filters">
    <label>From
      <input type="date" id="filterDateFrom" />
    </label>
    <label>To
      <input type="date" id="filterDateTo" />
    </label>
    <label>Preset
      <select id="filterPreset">
        <option value="">Custom / all</option>
        <option value="1">Last 24h (today)</option>
        <option value="7">Last 7 days</option>
        <option value="14" selected>Last 14 days</option>
        <option value="30">Last 30 days</option>
      </select>
    </label>
    <button type="button" class="btn-export" id="btnApplyFilters">Apply filters</button>
    <button type="button" class="btn-ghost" id="btnClearFilters">Clear</button>
    <span class="muted" id="filterHint" style="font-size:0.78rem;align-self:center;"></span>
  </div>

  <nav class="dash-jump" aria-label="Jump to sections">
    <span class="jump-label">Jump</span>
    <a href="#dash-posture">Security posture</a>
    <a href="#dash-taxonomy">OWASP / ASI</a>
    <a href="#dash-attack">Attack matrix</a>
    <a href="#dash-compliance">Compliance</a>
    <a href="#dash-governance">Runtime governance</a>
    <a href="#dash-audit-chain">Audit chain</a>
    <a href="#dash-alerts-insights">Alerts &amp; insights</a>
    <a href="#dash-forensics">Forensics</a>
    <a href="#dash-trends">Posture drift</a>
    <a href="#dash-finops">Cost burn</a>
    <a href="#dash-traffic">Traffic</a>
    <a href="#dash-tools">Tool drill-down</a>
    <span class="jump-actions">
      <button type="button" class="btn-export" id="btnExportMetrics" title="Download last /api/metrics snapshot">Export JSON snapshot</button>
    </span>
  </nav>

  <div class="insight-row">
    <div class="insight-card">
      <h3>Session overview</h3>
      <div class="insight-stat" id="insightPassRate">-</div>
      <p class="insight-lede" id="insightVolumeLine">Waiting for traffic…</p>
    </div>
    <div class="insight-card">
      <h3>APIs &amp; docs</h3>
      <p class="insight-lede" style="margin-top:0">Local JSON for automation, plus public docs for the 26 framework packages and handbook.</p>
      <div class="link-row">
        <a class="link-chip" href="/api/metrics" target="_blank" rel="noopener">JSON metrics</a>
        <a class="link-chip" href="/api/posture" target="_blank" rel="noopener">Posture</a>
        <a class="link-chip" href="/api/prevalidate" target="_blank" rel="noopener">Prevalidate</a>
        <a class="link-chip" href="/api/issue-guide?check=weak_schema" target="_blank" rel="noopener">Issue guide</a>
        <a class="link-chip" href="/api/taxonomy" target="_blank" rel="noopener">ASI taxonomy</a>
        <a class="link-chip" href="/api/compliance" target="_blank" rel="noopener">Compliance</a>
        <a class="link-chip" href="/api/governance" target="_blank" rel="noopener">Governance</a>
        <a class="link-chip" href="/api/health" target="_blank" rel="noopener">Health</a>
        <a class="link-chip" href="https://vaquarkhan.github.io/MCP-Bastion/integrations.html" target="_blank" rel="noopener">Integrations &amp; downloads</a>
        <a class="link-chip" href="https://vaquarkhan.github.io/MCP-Bastion/guide/handbook.html" target="_blank" rel="noopener">Docs handbook</a>
      </div>
    </div>
    <div class="insight-card">
      <h3>Top block categories</h3>
      <ul class="kind-list" id="kindPreview"><li class="muted">No blocks yet</li></ul>
    </div>
  </div>

  <div class="card" id="dash-posture">
    <div class="card-head">
      <h2>Security posture <span class="muted" style="font-weight:600;font-size:0.85rem;">(pre-deploy)</span></h2>
      <p class="card-desc">Letter grades from local scan JSON under <code>.bastion/scan/</code> — catalog, skills, OSV, and risk audit. Click a tile for findings (PMD-style why/how-to-fix). Prevalidation below is the Sonar-style issue list from the same files.</p>
    </div>
    <div class="grade-legend" id="gradeLegend" aria-label="Grade meaning">
      <span class="gl-title">What the letter means</span>
      <span class="gl-item grade-A"><strong>A</strong> clean / info only</span>
      <span class="gl-item grade-B"><strong>B</strong> low severity findings</span>
      <span class="gl-item grade-C"><strong>C</strong> medium severity</span>
      <span class="gl-item grade-D"><strong>D</strong> high severity</span>
      <span class="gl-item grade-F"><strong>F</strong> critical findings</span>
      <span class="gl-note">Combined = worst grade among present checks. Empty checks show “-” until you run scan/audit.</span>
    </div>
    <div class="posture-grid" id="postureGrid">
      <div class="grade-tile grade-none"><div class="g-label">Loading…</div><div class="g-letter">-</div></div>
    </div>
    <div class="posture-findings" id="postureFindings">
      <h3 style="font-size:0.9rem;margin:0 0 8px;">Findings</h3>
      <div class="tool-table-wrap">
        <table class="tool-table" id="postureFindingsTable">
          <thead><tr><th>Severity</th><th>Check</th><th>Message</th><th>OWASP / ASI</th><th>Detail</th></tr></thead>
          <tbody id="postureFindingsBody"></tbody>
        </table>
      </div>
    </div>
    <div class="prevalidate-box" id="prevalidateBox">
      <div class="pv-head">
        <strong>Static prevalidation</strong>
        <span class="muted" id="prevalidateNote">Sonar-style issue list from local mcp-bastion scans (not a SonarQube server).</span>
      </div>
      <div class="muted" id="prevalidateSummary" style="font-size:0.8rem;margin-bottom:8px;">Loading…</div>
      <div class="tool-table-wrap">
        <table class="tool-table" id="prevalidateTable">
          <thead><tr><th>Severity</th><th>Source</th><th>Check</th><th>Message</th><th>Guide</th></tr></thead>
          <tbody id="prevalidateBody"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="card" id="dash-taxonomy">
    <div class="card-head">
      <h2>OWASP / ASI coverage</h2>
      <p class="card-desc">Switch frameworks: Agentic (ASI), MCP Top 10, and LLM Top 10. Green = control on, amber = findings/blocks, grey = not addressed. Click a cell for sample issues.</p>
    </div>
    <div class="tax-tabs" id="taxonomyTabs" role="tablist">
      <button type="button" class="tax-tab active" data-fw="asi">ASI Top 10</button>
      <button type="button" class="tax-tab" data-fw="mcp">MCP Top 10</button>
      <button type="button" class="tax-tab" data-fw="llm">LLM Top 10</button>
    </div>
    <div class="asi-heat" id="asiHeatmap"></div>
  </div>

  <div class="card" id="dash-attack">
    <div class="card-head">
      <h2>Live attack matrix</h2>
      <p class="card-desc" id="attackHeadline">Categories under pressure from runtime blocks, mapped to OWASP / ASI. Respects the date filter above.</p>
    </div>
    <div class="attack-matrix-wrap">
      <table class="attack-matrix" id="attackMatrixTable">
        <thead>
          <tr>
            <th>Category</th>
            <th>Intensity</th>
            <th>Blocks</th>
            <th>Share</th>
            <th>Top tool</th>
            <th>OWASP / ASI</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody id="attackMatrixBody"></tbody>
      </table>
    </div>
  </div>

  <div class="card" id="dash-compliance">
    <div class="card-head">
      <h2>Compliance evidence</h2>
      <p class="card-desc" id="complianceDisclaimer">Evidence to support an audit, not a certificate.</p>
    </div>
    <div class="governance-grid" id="complianceMeta">
      <div class="gov-tile"><div class="gov-name">Policy hash</div><div class="gov-state off" id="compPolicyHash">-</div></div>
      <div class="gov-tile"><div class="gov-name">Attestation</div><div class="gov-state off" id="compAttestHash">-</div></div>
      <div class="gov-tile"><div class="gov-name">Generated</div><div class="gov-state off" id="compAttestTs">-</div></div>
    </div>
    <div class="date-filter-bar" style="margin-top:12px;margin-bottom:0;">
      <label>Framework
        <select id="reportFramework">
          <option value="soc2">SOC 2 (evidence)</option>
          <option value="gdpr">GDPR (evidence)</option>
          <option value="iso27001">ISO 27001 (evidence)</option>
          <option value="nist_ai_rmf">NIST AI RMF (evidence)</option>
          <option value="asi">OWASP ASI Top 10 (evidence)</option>
        </select>
      </label>
      <button type="button" class="btn-export" id="btnGenReport">Download PDF report</button>
      <button type="button" class="btn-export" id="btnGenReportMd" title="Markdown for git/diff">Download MD</button>
      <button type="button" class="btn-export" id="btnGenBundle">Download evidence bundle</button>
    </div>
  </div>

  <div class="card" id="dash-governance">
    <div class="card-head">
      <h2>Runtime governance &amp; policy</h2>
      <p class="card-desc">Zero-trust + core policy from <code>bastion.yaml</code> - Agent IAM, RBAC, prompt guard, rate/cost, PII, supply-chain, transport. Block counts refresh from live metrics.</p>
    </div>
    <div class="governance-grid" id="governanceGrid">
      <div class="gov-tile"><div class="gov-name">Loading…</div><div class="gov-state off">-</div></div>
    </div>
  </div>

  <div class="card" id="dash-audit-chain">
    <div class="card-head">
      <h2>Audit hash chain</h2>
      <p class="card-desc">Tamper-evident SHA-256 links for forensic audit entries. Head hash and recent links come from live <code>/api/metrics</code> → <code>audit_chain</code>. Optional anchors every N entries when configured in <code>bastion.yaml</code>.</p>
    </div>
    <div class="audit-chain-grid" id="auditChainKpis">
      <div class="gov-tile"><div class="gov-name">Chain length</div><div class="gov-state off" id="auditChainLen">-</div></div>
      <div class="gov-tile"><div class="gov-name">Head hash</div><div class="gov-state off"><span class="audit-chain-hash" id="auditChainHead">-</span></div></div>
      <div class="gov-tile"><div class="gov-name">Anchors</div><div class="gov-state off" id="auditChainAnchors">-</div></div>
    </div>
    <div class="tool-table-wrap">
      <table class="audit-links-table" id="auditChainTable">
        <thead>
          <tr><th>#</th><th>Timestamp</th><th>Entry hash</th><th>Prev hash</th></tr>
        </thead>
        <tbody id="auditChainBody">
          <tr><td colspan="4" class="muted">Waiting for audit events…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi req"><h2>Requests</h2><div class="value" id="kpiReq">0</div><p class="kpi-foot">Allowed tool calls recorded in this process.</p></div>
    <div class="kpi block"><h2>Blocked</h2><div class="value" id="kpiBlocked">0</div><p class="kpi-foot">Denied by policy (rate limits, injection, RBAC, …).</p></div>
    <div class="kpi pii"><h2>PII redacted</h2><div class="value" id="kpiPii">0</div><p class="kpi-foot" id="kpiPiiFoot">Entities masked or removed by Presidio-style detection.</p></div>
    <div class="kpi cost"><h2>Cost</h2><div class="value" id="kpiCost">$0.00</div><p class="kpi-foot" id="kpiCostFoot">Cumulative tracked spend (when cost middleware is enabled).</p></div>
  </div>

  <div class="alerts-insights-row" id="dash-alerts-insights">
    <div class="card alerts-panel-card">
      <div class="card-head">
        <h2>Recent alerts</h2>
        <p class="card-desc">Latest policy and system signals; the header badge mirrors this count.</p>
      </div>
      <div class="alerts alerts-prominent" id="alerts"></div>
    </div>
    <div class="card insights-panel-card">
      <div class="card-head">
        <h2>Insights &amp; anomalies</h2>
        <p class="card-desc">Heuristic auto-tuning hints from rolling aggregates (not ML). Act when patterns repeat.</p>
      </div>
      <div class="insight-summary" id="insightSummaryBar" aria-live="polite"></div>
      <div class="insights-feed" id="dashboardInsights"></div>
    </div>
  </div>

  <div class="card forensics-card" id="dash-forensics">
    <div class="card-head">
      <h2>Blocked requests (forensics)</h2>
      <p class="card-desc">Select a row for Trace &amp; Reproduce in the detail panel (wide screens). Filter the list by tenant; charts above stay all-tenant.</p>
    </div>
    <div class="tenant-bar">
      <label for="tenantFilter">Tenant</label>
      <select id="tenantFilter" class="tenant-select" aria-label="Filter by tenant">
        <option value="">All tenants</option>
      </select>
      <button type="button" class="btn-apply" id="tenantApply">Apply</button>
      <button type="button" class="btn-ghost" id="tenantClear">Show all</button>
      <span class="muted" id="forensicsHint" style="font-size:0.8rem;"></span>
    </div>
    <div class="forensics-layout">
      <div class="forensics-list">
        <div class="tool-table-wrap">
          <table class="tool-table" id="blockedForensicsTable">
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Tenant</th>
                <th>Agent</th>
                <th>Tool</th>
                <th>Why</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody id="blockedForensicsBody"></tbody>
          </table>
        </div>
      </div>
      <aside class="forensics-detail" id="forensicsDetail" aria-live="polite">
        <div class="forensics-detail-empty" id="forensicsDetailEmpty">
          Select a blocked request to inspect pillar trace and reproduce steps.
        </div>
        <div id="forensicsDetailPanel" hidden>
          <div class="forensics-detail-head">
            <div>
              <h3 id="forensicsDetailTitle">-</h3>
              <p class="forensics-detail-meta" id="forensicsDetailMeta"></p>
            </div>
            <button type="button" class="btn-mini" id="forensicsDetailClear" title="Clear selection">Clear</button>
          </div>
          <div class="forensics-tabs" role="tablist" aria-label="Forensics detail">
            <button type="button" class="forensics-tab is-active" role="tab" data-fd-tab="overview" aria-selected="true">Overview</button>
            <button type="button" class="forensics-tab" role="tab" data-fd-tab="trace" aria-selected="false">Trace</button>
            <button type="button" class="forensics-tab" role="tab" data-fd-tab="reproduce" aria-selected="false">Reproduce</button>
          </div>
          <div class="forensics-detail-body" id="forensicsTabOverview" data-fd-pane="overview">
            <dl class="forensics-kv" id="forensicsOverviewKv"></dl>
            <pre id="forensicsOverviewRaw"></pre>
          </div>
          <div class="forensics-detail-body" id="forensicsTabTrace" data-fd-pane="trace" hidden>
            <p class="fd-hint">Pillar pipeline for this decision (blocked step last).</p>
            <ul class="trace-steps" id="forensicsTraceSteps"></ul>
            <pre id="forensicsTraceRaw" style="margin-top:10px;"></pre>
          </div>
          <div class="forensics-detail-body" id="forensicsTabReproduce" data-fd-pane="reproduce" hidden>
            <p class="fd-hint">Not executed here. Copy into a shell after pointing at your MCP HTTP endpoint.</p>
            <pre id="forensicsReproduceBody"></pre>
          </div>
        </div>
      </aside>
    </div>
  </div>

  <div class="card" id="dash-agents">
    <div class="card-head">
      <h2>Agent identity / confused-deputy</h2>
      <p class="card-desc">Denied-by-agent counts from forensics plus Agent IAM scope map from <code>bastion.yaml</code>.</p>
    </div>
    <div id="agentDeniedSummary" class="muted" style="font-size:0.85rem;">-</div>
    <dl class="agent-scope" id="agentScopeMap"></dl>
  </div>

  <div class="card" id="dash-trends">
    <div class="card-head">
      <h2>Posture drift (audit JSONL)</h2>
      <p class="card-desc">Daily allow/block trend, drift direction, and top drivers from the local audit file - no database.</p>
    </div>
    <div id="trendHint" class="muted" style="font-size:0.8rem;"></div>
    <div class="drift-kpis" id="driftKpis" hidden>
      <div class="drift-kpi">
        <div class="dk-label">Events in window</div>
        <div class="dk-value" id="driftEvents">0</div>
        <div class="dk-sub" id="driftEventsSub">allowed / blocked</div>
      </div>
      <div class="drift-kpi">
        <div class="dk-label">Block rate</div>
        <div class="dk-value" id="driftBlockRate">0%</div>
        <div class="dk-sub" id="driftBlockRateSub">window average</div>
      </div>
      <div class="drift-kpi" id="driftDeltaTile">
        <div class="dk-label">Drift (1st→2nd half)</div>
        <div class="dk-value" id="driftDelta">0 pp</div>
        <div class="dk-sub" id="driftDeltaSub">stable</div>
      </div>
      <div class="drift-kpi">
        <div class="dk-label">Top driver</div>
        <div class="dk-value" id="driftDriver" style="font-size:1rem;">-</div>
        <div class="dk-sub" id="driftDriverSub">by blocked kind</div>
      </div>
    </div>
    <div class="drift-charts" id="driftCharts" hidden>
      <div>
        <h3 style="font-size:0.85rem;margin:0 0 6px;">Allowed vs blocked by day</h3>
        <div class="chart-wrap sm"><canvas id="chartDriftTraffic"></canvas></div>
      </div>
      <div>
        <h3 style="font-size:0.85rem;margin:0 0 6px;">Blocked by kind</h3>
        <div class="chart-wrap sm"><canvas id="chartDriftKinds"></canvas></div>
      </div>
    </div>
    <div class="spark-row" id="trendSpark" aria-label="Block-rate sparkline"></div>
    <div class="tool-table-wrap" id="driftDailyWrap" hidden style="margin-top:12px;">
      <h3 style="font-size:0.85rem;margin:0 0 6px;">Daily breakdown</h3>
      <table class="tool-table" id="driftDailyTable">
        <thead>
          <tr>
            <th>Day</th>
            <th>Events</th>
            <th>Allowed</th>
            <th>Blocked</th>
            <th>Block %</th>
            <th>Top kind</th>
            <th>Top tool</th>
            <th>Avg ms</th>
          </tr>
        </thead>
        <tbody id="driftDailyBody"></tbody>
      </table>
    </div>
    <div class="tool-table-wrap" id="driftRecentWrap" hidden style="margin-top:12px;">
      <h3 style="font-size:0.85rem;margin:0 0 6px;">Recent blocked events</h3>
      <table class="tool-table" id="driftRecentTable">
        <thead>
          <tr>
            <th>When</th>
            <th>Kind</th>
            <th>Pillar</th>
            <th>Tool</th>
            <th>Why</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="driftRecentBody"></tbody>
      </table>
    </div>
    <div class="drift-path" id="trendPath"></div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2>Pillar health</h2>
      <p class="card-desc">Each tile reflects recent activity for that pillar. Indigo tiles are runtime governance (Agent IAM, server verification).</p>
    </div>
    <div id="pillarHealth" class="pillar-grid"></div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2>Blocks by category</h2>
      <p class="card-desc">Aggregated block kinds (normalized labels). Compare with the detailed &ldquo;blocked by reason&rdquo; doughnut below.</p>
    </div>
    <div class="chart-wrap sm"><canvas id="chartBlockKinds"></canvas></div>
  </div>

  <div class="charts-row" style="grid-template-columns: 1fr; margin-bottom: 18px;">
    <div class="card" style="margin-bottom:0;">
      <h2>Latency (middleware)</h2>
      <div class="latency-row" id="latencyStats">
        <div><span class="lab">P50</span><span class="num" id="latP50">0</span> <span class="muted">ms</span></div>
        <div><span class="lab">P95</span><span class="num" id="latP95">0</span> <span class="muted">ms</span></div>
        <div><span class="lab">P99</span><span class="num" id="latP99">0</span> <span class="muted">ms</span></div>
      </div>
      <p class="muted" style="margin:10px 0 0;font-size:0.75rem;" id="latSamples">0 samples</p>
    </div>
  </div>

  <div class="card" id="dash-finops">
    <div class="card-head">
      <h2>Cost burn &amp; reduction</h2>
      <p class="card-desc">Compare actual spend to what would have happened without Bastion blocks and FinOps caps. Graphs use pricing estimates (not invoices).</p>
    </div>
    <div id="costBurn" class="burn-text">$0.00 / hr projected · $0.00 / day</div>
    <div class="finops-kpis">
      <div class="finops-kpi">
        <div class="fk-label">Actual spend</div>
        <div class="fk-value" id="finopsActual">$0.00</div>
        <div class="fk-sub" id="finopsUsed">0 tokens used</div>
      </div>
      <div class="finops-kpi would">
        <div class="fk-label">If not blocked / capped</div>
        <div class="fk-value" id="finopsWould">$0.00</div>
        <div class="fk-sub" id="finopsWouldTok">0 tokens would-have</div>
      </div>
      <div class="finops-kpi saved">
        <div class="fk-label">FinOps tokens saved</div>
        <div class="fk-value" id="finopsSaved">0</div>
        <div class="fk-sub" id="finopsSavedUsd">~$0.00 est.</div>
      </div>
      <div class="finops-kpi avoided">
        <div class="fk-label">Avoided by blocks</div>
        <div class="fk-value" id="finopsAvoided">0</div>
        <div class="fk-sub" id="finopsAvoidedUsd">~$0.00 est.</div>
      </div>
    </div>
    <div class="finops-charts">
      <div>
        <h3 style="font-size:0.85rem;margin:0 0 6px;">Tokens: used vs saved vs avoided</h3>
        <div class="chart-wrap sm"><canvas id="chartTokensCompare"></canvas></div>
      </div>
      <div>
        <h3 style="font-size:0.85rem;margin:0 0 6px;">Cost: actual vs would-have-been</h3>
        <div class="chart-wrap sm"><canvas id="chartCostCompare"></canvas></div>
      </div>
      <div>
        <h3 style="font-size:0.85rem;margin:0 0 6px;">Reduction by source</h3>
        <div class="chart-wrap sm"><canvas id="chartSavingsSource"></canvas></div>
      </div>
    </div>
    <div id="costReduction" class="burn-text" style="margin-top:4px;">
      <strong>Tokens saved:</strong> <span id="tokensSaved">0</span>
      <span class="muted"> · used <span id="tokensUsed">0</span></span>
      <span class="muted"> · avoided by blocks <span id="tokensAvoided">0</span></span><br>
      <strong>Est. $ saved (FinOps):</strong> <span id="usdSaved">$0.00</span>
      <span class="muted"> · avoided <span id="usdAvoided">$0.00</span></span>
      <span class="muted" id="savingsBySource"></span>
    </div>
    <p class="muted" style="margin:8px 0 0;font-size:0.75rem;" id="burnWindow">Window elapsed: 0s</p>
    <h3 style="font-size:0.88rem;margin:14px 0 8px;">Blocked issues driving cost avoidance</h3>
    <p class="muted" style="margin:0 0 8px;font-size:0.75rem;">What Bastion blocked, and the estimated tokens/$ that would have been spent if those calls reached the model.</p>
    <div class="tool-table-wrap">
      <table class="tool-table" id="costAvoidanceTable">
        <thead>
          <tr>
            <th>Issue / kind</th>
            <th>Tool</th>
            <th>Why blocked</th>
            <th>Est. tokens avoided</th>
            <th>Est. $ avoided</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="costAvoidanceBody"><tr><td colspan="6" class="muted">No blocked issues yet.</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="card" id="dash-traffic">
    <div class="card-head">
      <h2>Traffic · last <span id="tsWindow">10 min</span> · <span id="tsBucket">30s</span> buckets</h2>
      <p class="card-desc">Allowed vs blocked requests per bucket across the rolling window.</p>
    </div>
    <p class="chart-card-hint">Time series fill as the Bastion process records invocations. <strong>Still flat?</strong> Confirm middleware is mounted and MCP clients are calling tools.</p>
    <div class="chart-wrap"><canvas id="chartTraffic"></canvas></div>
  </div>

  <div class="charts-row">
    <div class="card" style="margin-bottom:0;">
      <h2>Blocked by reason</h2>
      <div class="chart-wrap sm"><canvas id="chartReasons"></canvas></div>
    </div>
    <div class="card" style="margin-bottom:0;">
      <h2>Top tools</h2>
      <div class="chart-wrap sm"><canvas id="chartTools"></canvas></div>
    </div>
    <div class="card" style="margin-bottom:0;">
      <h2>Cost by user</h2>
      <div class="chart-wrap sm"><canvas id="chartCost"></canvas></div>
    </div>
  </div>

  <div class="card">
    <h2>PII by entity type</h2>
    <p class="pii-legend-note">Severity coloring: <span class="pii-urgent">CREDIT_CARD / payment</span> (most urgent) · SSN / passport / bank · email &amp; phone · other entities.</p>
    <div class="chart-wrap sm"><canvas id="chartPiiEntity"></canvas></div>
  </div>

  <div class="card" id="dash-tools">
    <h2>Tool drill-down</h2>
    <div class="tool-table-wrap">
      <table class="tool-table" id="toolTable">
        <thead>
          <tr>
            <th>Tool</th>
            <th>Signal</th>
            <th>Total</th>
            <th>Allowed</th>
            <th>Blocked</th>
            <th>Blocked %</th>
            <th>Δ vs global</th>
            <th>P95 ms</th>
            <th>Avg ms</th>
            <th>Reasons</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div id="issueDetailModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="issueDetailTitle">
    <div class="modal-box" style="max-width:720px;">
      <button type="button" class="modal-close" id="issueDetailClose" aria-label="Close">&times;</button>
      <h3 id="issueDetailTitle">Issue detail</h3>
      <div id="issueDetailMeta" class="muted" style="font-size:0.8rem;margin:0 0 10px 0;"></div>
      <div id="issueDetailGuide" class="issue-guide" hidden></div>
      <ul class="trace-steps" id="issueDetailTrace"></ul>
      <pre class="detail-modal-body" id="issueDetailBody"></pre>
    </div>
  </div>
  <div id="traceModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="traceModalTitle">
    <div class="modal-box">
      <button type="button" class="modal-close" id="traceModalClose" aria-label="Close">&times;</button>
      <h3 id="traceModalTitle">Trace</h3>
      <pre id="traceModalBody"></pre>
    </div>
  </div>
  <div id="replayModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="replayModalTitle">
    <div class="modal-box">
      <button type="button" class="modal-close" id="replayModalClose" aria-label="Close">&times;</button>
      <h3 id="replayModalTitle">Reproduce request (example)</h3>
      <p class="muted" style="font-size:0.8rem;margin:0 0 10px 0;">Not executed here. Paste into a shell after pointing at your MCP HTTP endpoint.</p>
      <pre id="replayModalBody"></pre>
    </div>
  </div>

  <script src="/static/dashboard-app.js?v=37-forensics-autoselect" charset="utf-8"></script>
  <p class="dash-footer">
    <strong>MCP-Bastion dashboard</strong> · Chart.js · Theme preference stored in this browser only<br>
    <span id="footerUpdated" class="muted"></span>
    <span class="footer-links">
      <a href="https://github.com/vaquarkhan/MCP-Bastion" target="_blank" rel="noopener">GitHub</a>
      <a href="https://pypi.org/project/mcp-bastion-python/" target="_blank" rel="noopener">PyPI</a>
      <a href="/api/metrics" target="_blank" rel="noopener">Raw metrics</a>
    </span>
  </p>
  </div>
  <button type="button" class="back-top" id="backTop" aria-label="Back to top" title="Back to top">↑</button>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Serve SPA HTML with an embedded metrics snapshot so KPIs/charts work even if fetch fails."""
    html = DASHBOARD_HTML
    try:
        m = _get_dashboard_metrics_dict()
        payload = _metrics_json_for_html_embed(m)
        tag = (
            '<script type="application/json" id="mcp-bastion-bootstrap-json">'
            + payload
            + "</script>"
        )
        html = DASHBOARD_HTML.replace("<!--MCP_BASTION_METRICS_BOOTSTRAP-->", tag, 1)
    except Exception as e:
        logger.exception("dashboard bootstrap omitted: %s", e)
        html = DASHBOARD_HTML.replace("<!--MCP_BASTION_METRICS_BOOTSTRAP-->", "", 1)
    return HTMLResponse(
        html,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


def _dashboard_bind() -> tuple[str, int]:
    """Host/port for local dashboard (override: MCP_BASTION_DASHBOARD_HOST, MCP_BASTION_DASHBOARD_PORT).

    Default bind 0.0.0.0 so http://localhost:PORT and http://127.0.0.1:PORT both reach the server on Windows
    (localhost IPv6 vs IPv4 quirks). Use 127.0.0.1 only if you want loopback-only IPv4.
    """
    host = (os.environ.get("MCP_BASTION_DASHBOARD_HOST") or "0.0.0.0").strip() or "0.0.0.0"
    try:
        port = int((os.environ.get("MCP_BASTION_DASHBOARD_PORT") or "7000").strip() or "7000")
    except ValueError:
        port = 7000
    return host, port


if __name__ == "__main__":
    # Same as CLI: seed demo metrics unless explicitly disabled (MCP_BASTION_DEMO=0 / false / no).
    if os.environ.get("MCP_BASTION_DEMO") is None:
        os.environ["MCP_BASTION_DEMO"] = "1"
    import uvicorn

    _h, _p = _dashboard_bind()
    print(
        f"MCP-Bastion dashboard: http://127.0.0.1:{_p}/  (bound {_h}:{_p}; leave this window open; Ctrl+C to stop)",
        flush=True,
    )
    uvicorn.run(app, host=_h, port=_p)
