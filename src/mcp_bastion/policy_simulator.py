"""
Policy simulator ("shadow mode") for MCP-Bastion.
"""

from __future__ import annotations

from typing import Any

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.config import BastionConfig
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.external_policy import ExternalPolicyConfig, ExternalPolicyEvaluator, normalize_engine


def _build_shadow_config(base: BastionConfig | None, overrides: dict[str, Any] | None) -> BastionConfig:
    cfg = BastionConfig(**(vars(base) if base else vars(BastionConfig())))
    # Keep simulator lightweight/safe by default; callers can explicitly enable these.
    cfg.prompt_guard = False
    cfg.pii = False
    data = overrides or {}
    for flag_name, section in [
        ("prompt_guard", "prompt_guard"),
        ("pii", "pii"),
        ("rate_limit", "rate_limit"),
        ("circuit_breaker", "circuit_breaker"),
        ("content_filter", "content_filter"),
        ("rbac", "rbac"),
        ("schema_validation", "schema_validation"),
        ("replay_guard", "replay_guard"),
        ("cost_tracker", "cost_tracker"),
        ("semantic_cache", "semantic_cache"),
        ("semantic_firewall", "semantic_firewall"),
        ("sensitive_classifier", "sensitive_classifier"),
    ]:
        sec = data.get(section)
        if isinstance(sec, dict) and "enabled" in sec:
            setattr(cfg, flag_name, bool(sec.get("enabled")))
    if isinstance(data.get("sensitive_classifier"), dict):
        sc = data["sensitive_classifier"]
        cfg.sensitive_classifier_threshold = float(sc.get("threshold", cfg.sensitive_classifier_threshold))
        cfg.sensitive_classifier_use_transformers = bool(
            sc.get("use_transformers", cfg.sensitive_classifier_use_transformers)
        )
        if sc.get("model_name") is not None:
            cfg.sensitive_classifier_model_name = str(sc.get("model_name"))
        if sc.get("block_labels") is not None:
            cfg.sensitive_classifier_block_labels = list(sc.get("block_labels"))
    pe = data.get("policy_engine")
    if isinstance(pe, dict):
        if pe.get("type") is not None:
            cfg.policy_engine_type = normalize_engine(str(pe.get("type")))
        opa = pe.get("opa") if isinstance(pe.get("opa"), dict) else {}
        cedar = pe.get("cedar") if isinstance(pe.get("cedar"), dict) else {}
        if opa.get("policy_dir") is not None:
            cfg.opa_policy_dir = opa.get("policy_dir")
        if opa.get("query") is not None:
            cfg.opa_query = str(opa.get("query"))
        if cedar.get("policies_dir") is not None:
            cfg.cedar_policies_dir = cedar.get("policies_dir")
        if cedar.get("schema") is not None:
            cfg.cedar_schema_path = cedar.get("schema")
    if isinstance(data.get("rate_limit"), dict):
        rl = data["rate_limit"]
        cfg.rate_limit_max_iterations = int(rl.get("max_iterations", cfg.rate_limit_max_iterations))
        cfg.rate_limit_timeout_seconds = float(rl.get("timeout_seconds", cfg.rate_limit_timeout_seconds))
        cfg.rate_limit_token_budget = int(rl.get("token_budget", cfg.rate_limit_token_budget))
    if isinstance(data.get("cost_tracker"), dict):
        ct = data["cost_tracker"]
        cfg.cost_max_per_session = float(ct.get("max_cost_per_session", cfg.cost_max_per_session))
        cfg.cost_max_per_day = float(ct.get("max_cost_per_day", cfg.cost_max_per_day))
    return cfg


def _build_shadow_middleware(config: BastionConfig) -> MCPBastionMiddleware:
    ext = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine=normalize_engine(getattr(config, "policy_engine_type", "none")),
            opa_binary=getattr(config, "opa_binary", "opa"),
            opa_policy_dir=getattr(config, "opa_policy_dir", None),
            opa_query=getattr(config, "opa_query", "data.bastion.allow"),
            cedar_binary=getattr(config, "cedar_binary", "cedar"),
            cedar_policies_dir=getattr(config, "cedar_policies_dir", None),
            cedar_schema_path=getattr(config, "cedar_schema_path", None),
        )
    )
    eng = normalize_engine(getattr(config, "policy_engine_type", "none"))
    return MCPBastionMiddleware(
        enable_prompt_guard=config.prompt_guard,
        enable_pii_redaction=config.pii,
        enable_rate_limit=config.rate_limit,
        enable_circuit_breaker=config.circuit_breaker,
        enable_content_filter=config.content_filter,
        enable_rbac=config.rbac,
        enable_schema_validation=config.schema_validation,
        enable_replay_guard=config.replay_guard,
        enable_cost_tracker=config.cost_tracker,
        enable_semantic_cache=config.semantic_cache,
        enable_semantic_firewall=getattr(config, "semantic_firewall", False),
        enable_sensitive_classifier=getattr(config, "sensitive_classifier", False),
        sensitive_classifier_threshold=getattr(config, "sensitive_classifier_threshold", 0.65),
        sensitive_classifier_block_labels=set(getattr(config, "sensitive_classifier_block_labels", ["sensitive_business"])),
        external_policy=ext,
        enable_external_policy=eng != "none",
        enable_cost_attribution=getattr(config, "cost_attribution", True),
        shadow_mode=True,
    )


async def simulate_policy(
    events: list[dict[str, Any]],
    *,
    base_config: BastionConfig | None = None,
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Re-evaluate historical events in shadow mode.

    Returns:
      - would_block_count
      - would_block_by_pillar
      - regressions (new blocks on previously allowed)
      - misses (still allowed on previously blocked)
    """
    cfg = _build_shadow_config(base_config, overrides)
    mw = _build_shadow_middleware(cfg)
    would_block = 0
    by_pillar: dict[str, int] = {}
    regressions = 0
    misses = 0

    async def _handler(_ctx: MiddlewareContext[Any]) -> dict[str, Any]:
        return {"ok": True}

    for event in events:
        replay = event.get("replay_payload") or {}
        params = replay.get("params") if isinstance(replay, dict) else {}
        msg = {"method": "tools/call", "params": params or {}}
        ctx = MiddlewareContext(
            message=msg,
            request_id=event.get("request_id"),
            session_id=event.get("session_id"),
        )
        await mw(ctx, _handler)
        decisions = ctx.metadata.get("shadow_blocked", [])
        had_would_block = bool(decisions)
        if had_would_block:
            would_block += 1
            for d in decisions:
                p = d.get("pillar", "unknown")
                by_pillar[p] = by_pillar.get(p, 0) + 1

        original_blocked = event.get("action") == "BLOCKED"
        if had_would_block and not original_blocked:
            regressions += 1
        if (not had_would_block) and original_blocked:
            misses += 1

    return {
        "events_evaluated": len(events),
        "would_block_count": would_block,
        "would_block_pct": round((100.0 * would_block / max(1, len(events))), 2),
        "would_block_by_pillar": by_pillar,
        "regressions": regressions,
        "misses": misses,
        "config": {
            "prompt_guard": cfg.prompt_guard,
            "rate_limit": cfg.rate_limit,
            "content_filter": cfg.content_filter,
            "semantic_firewall": getattr(cfg, "semantic_firewall", False),
        },
    }
