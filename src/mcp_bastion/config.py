"""
Policy-as-Code: load bastion.yaml and build middleware.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_bastion.pillars.audit_hash_chain import AuditHashChain
from mcp_bastion.pillars.audit_log import AuditLogMiddleware
from mcp_bastion.pillars.alerts import SlackAlertSink, WebhookAlertSink, make_audit_export_callback
from mcp_bastion.pillars.telemetry_sinks import build_telemetry_sinks_from_config
from mcp_bastion.pillars.external_policy import ExternalPolicyConfig, ExternalPolicyEvaluator, normalize_engine
from mcp_bastion.pillars.circuit_breaker import CircuitBreaker
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.cost_policy import CostPolicyEngine
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.sensitive_classifier import SensitiveContentClassifier
from mcp_bastion.pillars.metrics import MetricsStore
from mcp_bastion.pillars.pii_redaction import PIIRedactor
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.rbac import RBAC
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.schema_validation import SchemaValidator, parse_tool_schemas
from mcp_bastion.pillars.semantic_cache import SemanticCache
from mcp_bastion.pillars.output_budget import OutputBudget
from mcp_bastion.pillars.grounding_guard import GroundingGuard
from mcp_bastion.pillars.identity_adapters import IdentityAdapter
from mcp_bastion.pillars.agent_iam import AgentIAM, parse_agent_policies
from mcp_bastion.pillars.argument_guards import ArgumentGuardEngine, parse_guard_rules
from mcp_bastion.pillars.server_verification import ServerVerifier
from mcp_bastion.pillars.state_backend import build_state_backend
from mcp_bastion.pillars.agent_stability import AgentStabilityMonitor
from mcp_bastion.mcp_transport import mcp_transport_config_from_bastion
from mcp_bastion.pillars.atr_rules import ATRRuleLoader
from mcp_bastion.pillars.auto_repave import AutoRepaveEngine
from mcp_bastion.pillars.canary_goallock import CanaryGoalLock
from mcp_bastion.pillars.llm_scanner import LLMScanner
from mcp_bastion.pillars.secret_redaction import SecretPatternRedactor
from mcp_bastion.pillars.threat_feeds import ThreatFeedManager
from mcp_bastion.base import CallNext, MiddlewareContext, compose_middleware
from mcp_bastion.governance_beacon import schedule_registry_beacon
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.tenant import resolve_tenant_id

logger = logging.getLogger(__name__)


def _bastion_distribution_version() -> str:
    try:
        from importlib.metadata import version

        return version("mcp-bastion-python")
    except Exception:
        return "unknown"


@dataclass
class BastionConfig:
    """Single config file schema for MCP-Bastion."""

    prompt_guard: bool = True
    prompt_guard_threshold: float = 0.85
    prompt_guard_fail_open: bool = False
    prompt_guard_heuristic_fallback: bool = True
    prompt_guard_model_id: str = "ProtectAI/deberta-v3-base-prompt-injection-v2"
    pii: bool = True
    rate_limit: bool = True
    rate_limit_max_iterations: int = 15
    rate_limit_timeout_seconds: float = 60.0
    rate_limit_token_budget: int = 50_000
    rate_limit_max_per_tool: int = 0
    response_scan: bool = False
    response_scan_extra_patterns: list[str] = field(default_factory=list)
    discovery_filter: bool = False
    output_budget: bool = False
    output_budget_max_tokens: int = 4000
    output_budget_min_tokens: int = 500
    output_budget_offload: bool = True
    output_budget_retrieve_tool: str = "bastion_get_offloaded"
    output_budget_max_response_bytes: int = 0
    grounding_guard: bool = False
    grounding_guard_workspace_root: str = "."
    grounding_guard_on_violation: str = "warn"
    circuit_breaker: bool = False
    content_filter: bool = False
    content_filter_block_code_execution: bool = True
    content_filter_block_file_paths: bool = True
    content_filter_block_urls: bool = False
    content_filter_block_secrets: bool = False
    content_filter_allowlist_patterns: list[str] = field(default_factory=list)
    content_filter_denylist_patterns: list[str] = field(default_factory=list)
    rbac: bool = False
    rbac_permissions: dict[str, list[str]] = field(default_factory=dict)
    rbac_require_authenticated_identity: bool = True
    schema_validation: bool = False
    schema_validation_schemas: dict[str, dict[str, type]] = field(default_factory=dict)
    replay_guard: bool = False
    replay_require_nonce: bool = False
    cost_tracker: bool = False
    cost_max_per_session: float = 0.50
    cost_max_per_day: float = 10.0
    cost_checkpoint_path: str | None = None
    cost_policy_enabled: bool = False
    cost_policy_config: dict[str, Any] = field(default_factory=dict)
    prompt_guard_use_ungated_default: bool = True
    boundary_mode_enabled: bool = False
    governance_attestation_enabled: bool = True
    identity_adapter_enabled: bool = False
    identity_adapter_config: dict[str, Any] = field(default_factory=dict)
    secrets_config: dict[str, Any] = field(default_factory=dict)
    argument_guards_enabled: bool = False
    argument_guards_rules: list[dict[str, Any]] = field(default_factory=list)
    semantic_cache: bool = False
    semantic_firewall: bool = False
    sensitive_classifier: bool = False
    sensitive_classifier_threshold: float = 0.65
    sensitive_classifier_use_transformers: bool = False
    sensitive_classifier_model_name: str = "distilbert-base-uncased-finetuned-sst-2-english"
    sensitive_classifier_block_labels: list[str] = field(default_factory=lambda: ["sensitive_business"])
    audit: bool = True
    audit_jsonl_path: str | None = None
    alerts_slack_webhook: str | None = None
    alerts_webhook_url: str | None = None
    alerts_webhooks: list[str] = field(default_factory=list)
    alerts_on: list[str] = field(default_factory=lambda: ["injection", "rate_limit", "cost"])
    alerts_retry_attempts: int = 3
    alerts_retry_backoff_seconds: float = 0.25
    alerts_retry_backoff_max_seconds: float = 2.0
    alerts_timeout_seconds: float = 5.0
    hot_reload: bool = False
    hot_reload_poll_seconds: float = 2.0
    audit_hash_chain_anchor_every: int = 0
    audit_anchor_webhook_url: str | None = None
    behavior_fingerprint: bool = True
    cost_attribution: bool = True
    policy_engine_type: str = "none"
    policy_engine_fail_closed: bool = True
    opa_binary: str = "opa"
    opa_policy_dir: str | None = None
    opa_query: str = "data.bastion.allow"
    cedar_binary: str = "cedar"
    cedar_policies_dir: str | None = None
    cedar_schema_path: str | None = None
    multi_tenant_enabled: bool = False
    multi_tenant_config_dir: str | None = None
    multi_tenant_default_tenant: str = "default"
    source_path: str | None = None
    edge_auth_enabled: bool = False
    edge_auth_metadata_key: str = "bastion_edge_token"
    edge_auth_secret_env: str = "BASTION_EDGE_SECRET"
    tool_allowlist_enabled: bool = False
    tool_allowlist: list[str] = field(default_factory=list)
    session_max_unique_tools: int = 0
    governance_registry_url: str | None = None
    governance_service_id: str | None = None
    telemetry_export_mode: str = "all"
    telemetry_sinks: list[dict[str, Any]] = field(default_factory=list)
    tool_metadata_guard_enabled: bool = False
    tool_metadata_guard_on_poison: str = "remove_tool"
    tool_metadata_guard_use_content_filter: bool = True
    agent_iam_enabled: bool = False
    agent_iam_token_metadata_key: str = "bastion_agent_token"
    agent_iam_require_token: bool = True
    agent_iam_agents: list[dict[str, Any]] = field(default_factory=list)
    server_verification_enabled: bool = False
    server_verification_on_mismatch: str = "block"
    server_verification_base_path: str = "."
    server_verification_manifest: dict[str, str] = field(default_factory=dict)
    server_verification_manifest_path: str | None = None
    server_verification_manifest_signature: str | None = None
    server_verification_signature_env: str = "BASTION_MANIFEST_SIGNING_KEY"
    agent_iam_isolate_sessions: bool = False
    transport_hardening_enabled: bool = True
    transport_hardening_allowed_hosts: list[str] = field(
        default_factory=lambda: ["127.0.0.1", "localhost", "[::1]"]
    )
    transport_hardening_block_browser_origin: bool = True
    transport_hardening_require_loopback: bool = True
    stdio_guard_enabled: bool = False
    tool_metadata_fingerprint_enabled: bool = False
    tool_metadata_fingerprint_path: str | None = None
    tool_metadata_fingerprint_expected: str | None = None
    governance_allowed_registry_names: list[str] = field(default_factory=list)
    governance_allowed_repository_urls: list[str] = field(default_factory=list)
    state_backend: str = "memory"
    state_backend_redis_url: str = "redis://127.0.0.1:6379/0"
    state_backend_key_prefix: str = "mcp-bastion"
    # Hybrid MCP transport (stateful + stateless) — opt-in, default off
    mcp_transport_enabled: bool = False
    mcp_transport_mode: str = "auto"
    mcp_transport_state_handle_params: list[str] = field(
        default_factory=lambda: ["state_handle", "mcp_state_handle", "stateHandle", "mcpStateHandle"]
    )
    mcp_transport_state_handle_headers: list[str] = field(
        default_factory=lambda: ["mcp-state-handle", "x-mcp-state-handle"]
    )
    mcp_transport_state_handle_metadata_keys: list[str] = field(
        default_factory=lambda: ["state_handle", "mcp_state_handle", "stateHandle"]
    )
    mcp_transport_require_handle: bool = False
    mcp_transport_handle_min_length: int = 16
    mcp_transport_protocol_enabled: bool = False
    mcp_transport_protocol_header: str = "MCP-Protocol-Version"
    mcp_transport_allowed_versions: list[str] = field(
        default_factory=lambda: ["2024-11-05", "2025-03-26"]
    )
    mcp_transport_default_version: str = "2024-11-05"
    mcp_transport_discovery_enabled: bool = False
    mcp_transport_discovery_card: dict[str, Any] = field(default_factory=dict)
    agent_stability_enabled: bool = False
    agent_stability_window_size: int = 5
    agent_stability_repeat_threshold: int = 3
    agent_stability_similarity_threshold: float = 0.92
    agent_stability_on_detect: str = "inject"  # inject | block | warn
    # Runtime governance pillars (3.0+)
    canary_goallock_enabled: bool = False
    canary_token_prefix: str = "BASTION-CANARY-"
    canary_rotate_on_detection: bool = True
    atr_rules_enabled: bool = False
    atr_rules_dir: str = "./atr-rules"
    atr_min_severity: str = "medium"
    llm_scanner_enabled: bool = False
    llm_scanner_url: str = "http://localhost:11434"
    llm_scanner_model: str = "llama3.2:3b"
    llm_scanner_confidence_threshold: float = 0.85
    llm_scanner_timeout_ms: int = 2500
    llm_scanner_only_when_uncertain: bool = True
    threat_feeds_enabled: bool = False
    threat_feeds: list[dict[str, Any]] = field(default_factory=list)
    auto_repave_enabled: bool = False
    auto_repave_triggers: dict[str, Any] = field(default_factory=dict)
    auto_repave_actions: dict[str, bool] = field(default_factory=dict)
    secrets_redact_patterns: list[dict[str, Any]] = field(default_factory=list)
    bastion_mode: str = "enforce"  # enforce | observe


def validate_bastion_config(config: BastionConfig) -> None:
    """Raise BastionConfigError on incompatible pillar combinations."""
    from mcp_bastion.errors import BastionConfigError

    if config.tool_metadata_guard_enabled and not config.content_filter and not config.prompt_guard:
        raise BastionConfigError(
            "tool_metadata_guard.enabled requires content_filter.enabled or prompt_guard.enabled — "
            "enable at least one metadata scanner or disable tool_metadata_guard"
        )

    if config.rbac and config.rbac_require_authenticated_identity:
        if not config.agent_iam_enabled and not config.edge_auth_enabled:
            raise BastionConfigError(
                "rbac.enabled with require_authenticated_identity requires agent_iam or edge_auth — "
                "otherwise callers can self-assert metadata.role"
            )

    if config.boundary_mode_enabled and not config.edge_auth_enabled and not config.agent_iam_enabled:
        raise BastionConfigError(
            "boundary_mode.enabled requires edge_auth or agent_iam — proxy boundary must authenticate clients"
        )

    if config.cost_policy_enabled and not config.cost_tracker:
        raise BastionConfigError("cost_policy.enabled requires cost_tracker.enabled")

    engine = normalize_engine(config.policy_engine_type)
    if engine != "none" and config.policy_engine_fail_closed:
        if engine == "opa":
            pol = config.opa_policy_dir
            if not pol or not Path(pol).is_dir():
                raise BastionConfigError(
                    "policy_engine.fail_closed is true but policy_engine.opa.policy_dir "
                    "is missing or not a directory"
                )
        if engine == "cedar":
            pol = config.cedar_policies_dir
            if not pol or not Path(pol).is_dir():
                raise BastionConfigError(
                    "policy_engine.fail_closed is true but policy_engine.cedar.policies_dir "
                    "is missing or not a directory"
                )


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML required for bastion.yaml: pip install pyyaml") from None
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_config(path: str | Path | None = None) -> BastionConfig:
    """
    Load bastion.yaml from path or env BASTION_CONFIG or cwd.
    Returns BastionConfig; missing keys use defaults.
    """
    if path is None:
        path = os.environ.get("BASTION_CONFIG", "bastion.yaml")
    p = Path(path)
    if not p.exists():
        return BastionConfig()
    data = _load_yaml(p)
    content_filter = data.get("content_filter", {})
    alerts = data.get("alerts", {})
    hot_reload = data.get("hot_reload", {})
    ahc = data.get("audit_hash_chain", {}) or {}
    bf = data.get("behavior_fingerprint", {}) or {}
    ca = data.get("cost_attribution", {}) or {}
    pe = data.get("policy_engine", {}) or {}
    mt = data.get("multi_tenant", {}) or {}
    gov = data.get("governance", {}) or {}
    tel = data.get("telemetry", {}) or {}
    tmg = data.get("tool_metadata_guard", {}) or {}
    edge = data.get("edge_auth", {}) or {}
    schemav = data.get("schema_validation", {}) or {}
    tal = data.get("tool_allowlist", {}) or {}
    iam = data.get("agent_iam", {}) or {}
    sv = data.get("server_verification", {}) or {}
    th = data.get("transport_hardening", {}) or {}
    sg = data.get("stdio_guard", {}) or {}
    tmf = data.get("tool_metadata_fingerprint", {}) or {}
    sess = data.get("session_limits", {}) or {}
    sb = data.get("state_backend", {}) or {}
    mcp_t = data.get("mcp_transport", {}) or {}
    mcp_stability = mcp_t.get("stability", {}) or {}
    ag = data.get("argument_guards", {}) or {}
    audit_cfg = data.get("audit", {}) or {}
    sc = data.get("sensitive_classifier", {}) or {}
    opa_pe = pe.get("opa", {}) or {}
    cedar_pe = pe.get("cedar", {}) or {}
    engine = normalize_engine(pe.get("type") or os.environ.get("BASTION_POLICY_ENGINE"))
    pg = data.get("prompt_guard", {}) or {}
    cp = data.get("cost_policy", {}) or {}
    bm = data.get("boundary_mode", {}) or {}
    ia = data.get("identity_adapter", {}) or {}
    sec = data.get("secrets", {}) or {}
    cg = data.get("canary_goallock", {}) or {}
    atr = data.get("atr_rules", {}) or {}
    lls = data.get("llm_scanner", {}) or {}
    tf = data.get("threat_feeds", {}) or {}
    ar = data.get("auto_repave", {}) or {}
    mode = str(data.get("mode", data.get("bastion_mode", "enforce")))
    boundary_on = bool(bm.get("enabled", False))
    th_require_loopback = bool(th.get("require_loopback", True))
    return BastionConfig(
        prompt_guard=pg.get("enabled", True),
        prompt_guard_threshold=float(pg.get("threshold", 0.85)),
        prompt_guard_fail_open=bool(pg.get("fail_open", False)),
        prompt_guard_heuristic_fallback=bool(pg.get("heuristic_fallback", True)),
        prompt_guard_use_ungated_default=bool(pg.get("use_ungated_default", True)),
        prompt_guard_model_id=str(
            pg.get("model_id", "ProtectAI/deberta-v3-base-prompt-injection-v2")
        ),
        pii=data.get("pii", {}).get("enabled", True),
        rate_limit=data.get("rate_limit", {}).get("enabled", True),
        rate_limit_max_iterations=data.get("rate_limit", {}).get("max_iterations", 15),
        rate_limit_timeout_seconds=float(data.get("rate_limit", {}).get("timeout_seconds", 60)),
        rate_limit_token_budget=data.get("rate_limit", {}).get("token_budget", 50_000),
        rate_limit_max_per_tool=int(data.get("rate_limit", {}).get("max_per_tool", 0)),
        response_scan=bool(data.get("response_scan", {}).get("enabled", False)),
        response_scan_extra_patterns=list(data.get("response_scan", {}).get("extra_patterns", [])),
        discovery_filter=bool(data.get("discovery_filter", {}).get("enabled", False)),
        output_budget=bool(data.get("output_budget", {}).get("enabled", False)),
        output_budget_max_tokens=int(data.get("output_budget", {}).get("max_output_tokens", 4000)),
        output_budget_min_tokens=int(data.get("output_budget", {}).get("min_tokens", 500)),
        output_budget_offload=bool(data.get("output_budget", {}).get("offload", True)),
        output_budget_retrieve_tool=str(
            data.get("output_budget", {}).get("retrieve_tool", "bastion_get_offloaded")
        ),
        output_budget_max_response_bytes=int(data.get("output_budget", {}).get("max_response_bytes", 0)),
        grounding_guard=bool(data.get("grounding_guard", {}).get("enabled", False)),
        grounding_guard_workspace_root=str(data.get("grounding_guard", {}).get("workspace_root", ".")),
        grounding_guard_on_violation=str(data.get("grounding_guard", {}).get("on_violation", "warn")),
        circuit_breaker=data.get("circuit_breaker", {}).get("enabled", False),
        content_filter=content_filter.get("enabled", False),
        content_filter_block_code_execution=content_filter.get("block_code_execution", True),
        content_filter_block_file_paths=content_filter.get("block_file_paths", True),
        content_filter_block_urls=content_filter.get("block_urls", False),
        content_filter_block_secrets=bool(content_filter.get("block_secrets", False)),
        content_filter_allowlist_patterns=list(content_filter.get("allowlist_patterns", [])),
        content_filter_denylist_patterns=list(
            content_filter.get("denylist_patterns", content_filter.get("custom_patterns", []))
        ),
        rbac=data.get("rbac", {}).get("enabled", False),
        rbac_permissions=data.get("rbac", {}).get("permissions", {}),
        rbac_require_authenticated_identity=bool(
            data.get("rbac", {}).get("require_authenticated_identity", True)
        ),
        schema_validation=bool(schemav.get("enabled", False)),
        schema_validation_schemas=parse_tool_schemas(schemav.get("schemas")),
        replay_guard=data.get("replay_guard", {}).get("enabled", False),
        replay_require_nonce=data.get("replay_guard", {}).get("require_nonce", False),
        cost_tracker=data.get("cost_tracker", {}).get("enabled", False),
        cost_max_per_session=float(data.get("cost_tracker", {}).get("max_cost_per_session", 0.50)),
        cost_max_per_day=float(data.get("cost_tracker", {}).get("max_cost_per_day", 10.0)),
        cost_checkpoint_path=data.get("cost_tracker", {}).get("checkpoint_path")
        or os.environ.get("BASTION_COST_CHECKPOINT"),
        cost_policy_enabled=bool(cp.get("enabled", False)),
        cost_policy_config=cp if isinstance(cp, dict) else {},
        boundary_mode_enabled=boundary_on,
        identity_adapter_enabled=bool(ia.get("enabled", False)),
        identity_adapter_config=ia if isinstance(ia, dict) else {},
        secrets_config=sec if isinstance(sec, dict) else {},
        argument_guards_enabled=bool(ag.get("enabled", False)),
        argument_guards_rules=list(ag.get("rules", [])) if isinstance(ag.get("rules"), list) else [],
        semantic_cache=data.get("semantic_cache", {}).get("enabled", False),
        semantic_firewall=data.get("semantic_firewall", {}).get("enabled", False),
        sensitive_classifier=sc.get("enabled", False),
        sensitive_classifier_threshold=float(sc.get("threshold", 0.65)),
        sensitive_classifier_use_transformers=bool(sc.get("use_transformers", False)),
        sensitive_classifier_model_name=str(
            sc.get("model_name", "distilbert-base-uncased-finetuned-sst-2-english")
        ),
        sensitive_classifier_block_labels=list(sc.get("block_labels", ["sensitive_business"])),
        audit=bool(audit_cfg.get("enabled", True)),
        audit_jsonl_path=audit_cfg.get("jsonl_path") or audit_cfg.get("path") or os.environ.get("BASTION_AUDIT_JSONL"),
        alerts_slack_webhook=alerts.get("slack_webhook") or os.environ.get("SLACK_WEBHOOK_URL"),
        alerts_webhook_url=alerts.get("webhook_url") or os.environ.get("BASTION_WEBHOOK_URL"),
        alerts_webhooks=alerts.get("webhooks", []),
        alerts_on=alerts.get("alert_on", ["injection", "rate_limit", "cost"]),
        alerts_retry_attempts=int(alerts.get("retry_attempts", 3)),
        alerts_retry_backoff_seconds=float(alerts.get("retry_backoff_seconds", 0.25)),
        alerts_retry_backoff_max_seconds=float(alerts.get("retry_backoff_max_seconds", 2.0)),
        alerts_timeout_seconds=float(alerts.get("timeout_seconds", 5.0)),
        hot_reload=bool(hot_reload.get("enabled", False)),
        hot_reload_poll_seconds=float(hot_reload.get("poll_seconds", 2.0)),
        audit_hash_chain_anchor_every=int(ahc.get("anchor_every", 0)),
        audit_anchor_webhook_url=ahc.get("anchor_webhook_url") or os.environ.get("BASTION_ANCHOR_WEBHOOK_URL"),
        behavior_fingerprint=bool(bf.get("enabled", True)),
        cost_attribution=bool(ca.get("enabled", True)),
        policy_engine_type=engine,
        policy_engine_fail_closed=bool(pe.get("fail_closed", True)),
        opa_binary=str(opa_pe.get("binary") or os.environ.get("BASTION_OPA_BINARY", "opa")),
        opa_policy_dir=opa_pe.get("policy_dir") or os.environ.get("BASTION_OPA_POLICY_DIR"),
        opa_query=str(opa_pe.get("query") or os.environ.get("BASTION_OPA_QUERY", "data.bastion.allow")),
        cedar_binary=str(cedar_pe.get("binary") or os.environ.get("BASTION_CEDAR_BINARY", "cedar")),
        cedar_policies_dir=cedar_pe.get("policies_dir") or os.environ.get("BASTION_CEDAR_POLICIES_DIR"),
        cedar_schema_path=cedar_pe.get("schema") or os.environ.get("BASTION_CEDAR_SCHEMA"),
        multi_tenant_enabled=bool(mt.get("enabled", False)),
        multi_tenant_config_dir=mt.get("config_dir") or os.environ.get("BASTION_TENANT_CONFIG_DIR"),
        multi_tenant_default_tenant=str(mt.get("default_tenant", "default")),
        source_path=str(p),
        edge_auth_enabled=bool(edge.get("enabled", False)),
        edge_auth_metadata_key=str(edge.get("metadata_key", "bastion_edge_token")),
        edge_auth_secret_env=str(edge.get("secret_env", "BASTION_EDGE_SECRET")),
        tool_allowlist_enabled=bool(tal.get("enabled", False)),
        tool_allowlist=list(tal.get("tools", [])),
        session_max_unique_tools=int(sess.get("max_unique_tools_per_session", 0)),
        governance_registry_url=gov.get("registry_url") or os.environ.get("BASTION_GOVERNANCE_REGISTRY_URL"),
        governance_service_id=gov.get("service_id") or os.environ.get("BASTION_SERVICE_ID"),
        telemetry_export_mode=str(tel.get("export_mode", "all")),
        telemetry_sinks=list(tel.get("sinks", [])) if isinstance(tel.get("sinks", []), list) else [],
        tool_metadata_guard_enabled=bool(tmg.get("enabled", False)),
        tool_metadata_guard_on_poison=str(tmg.get("on_poison", "remove_tool")),
        tool_metadata_guard_use_content_filter=bool(tmg.get("use_content_filter", True)),
        agent_iam_enabled=bool(iam.get("enabled", False)),
        agent_iam_token_metadata_key=str(iam.get("token_metadata_key", "bastion_agent_token")),
        agent_iam_require_token=bool(iam.get("require_token", True)),
        agent_iam_agents=list(iam.get("agents", [])) if isinstance(iam.get("agents"), list) else [],
        agent_iam_isolate_sessions=bool(iam.get("isolate_sessions", False)),
        server_verification_enabled=bool(sv.get("enabled", False)),
        server_verification_on_mismatch=str(sv.get("on_mismatch", "block")),
        server_verification_base_path=str(sv.get("base_path", ".")),
        server_verification_manifest={
            str(k): str(v) for k, v in (sv.get("manifest") or {}).items()
        },
        server_verification_manifest_path=sv.get("manifest_path") or sv.get("manifest_file"),
        server_verification_manifest_signature=sv.get("signature"),
        server_verification_signature_env=str(sv.get("signature_env", "BASTION_MANIFEST_SIGNING_KEY")),
        transport_hardening_enabled=bool(th.get("enabled", True)),
        transport_hardening_allowed_hosts=list(th.get("allowed_hosts", ["127.0.0.1", "localhost", "[::1]"])),
        transport_hardening_block_browser_origin=bool(th.get("block_browser_origin", True)),
        transport_hardening_require_loopback=th_require_loopback,
        stdio_guard_enabled=bool(sg.get("enabled", False)),
        tool_metadata_fingerprint_enabled=bool(tmf.get("enabled", False)),
        tool_metadata_fingerprint_path=tmf.get("fingerprint_path") or tmf.get("path"),
        tool_metadata_fingerprint_expected=tmf.get("expected") or tmf.get("expected_sha256"),
        governance_allowed_registry_names=list(gov.get("allowed_registry_names", []))
        if isinstance(gov.get("allowed_registry_names"), list)
        else [],
        governance_allowed_repository_urls=list(gov.get("allowed_repository_urls", []))
        if isinstance(gov.get("allowed_repository_urls"), list)
        else [],
        governance_attestation_enabled=bool(gov.get("attestation_enabled", True)),
        state_backend=str(sb.get("type", sb.get("backend", "memory"))),
        state_backend_redis_url=str(sb.get("redis_url", os.environ.get("BASTION_REDIS_URL", "redis://127.0.0.1:6379/0"))),
        state_backend_key_prefix=str(sb.get("key_prefix", "mcp-bastion")),
        mcp_transport_enabled=bool(mcp_t.get("enabled", False)),
        mcp_transport_mode=str(mcp_t.get("mode", "auto")),
        mcp_transport_state_handle_params=list(
            mcp_t.get("state_handle", {}).get("param_names", mcp_t.get("state_handle_params", []))
        )
        if isinstance(mcp_t.get("state_handle"), dict) or isinstance(mcp_t.get("state_handle_params"), list)
        else ["state_handle", "mcp_state_handle", "stateHandle", "mcpStateHandle"],
        mcp_transport_state_handle_headers=list(
            mcp_t.get("state_handle", {}).get("header_names", mcp_t.get("state_handle_headers", []))
        )
        if isinstance(mcp_t.get("state_handle"), dict) or isinstance(mcp_t.get("state_handle_headers"), list)
        else ["mcp-state-handle", "x-mcp-state-handle"],
        mcp_transport_state_handle_metadata_keys=list(
            mcp_t.get("state_handle", {}).get("metadata_keys", mcp_t.get("state_handle_metadata_keys", []))
        )
        if isinstance(mcp_t.get("state_handle"), dict)
        or isinstance(mcp_t.get("state_handle_metadata_keys"), list)
        else ["state_handle", "mcp_state_handle", "stateHandle"],
        mcp_transport_require_handle=bool(
            mcp_t.get("state_handle", {}).get("required_in_stateless", mcp_t.get("require_state_handle", False))
        )
        if isinstance(mcp_t.get("state_handle"), dict)
        else bool(mcp_t.get("require_state_handle", False)),
        mcp_transport_handle_min_length=int(
            mcp_t.get("state_handle", {}).get("min_length", mcp_t.get("handle_min_length", 16))
        )
        if isinstance(mcp_t.get("state_handle"), dict)
        else int(mcp_t.get("handle_min_length", 16)),
        mcp_transport_protocol_enabled=bool(mcp_t.get("protocol", {}).get("enabled", mcp_t.get("protocol_enabled", False)))
        if isinstance(mcp_t.get("protocol"), dict)
        else bool(mcp_t.get("protocol_enabled", False)),
        mcp_transport_protocol_header=str(
            mcp_t.get("protocol", {}).get("header", mcp_t.get("protocol_header", "MCP-Protocol-Version"))
        ),
        mcp_transport_allowed_versions=list(
            mcp_t.get("protocol", {}).get("allowed_versions", mcp_t.get("allowed_protocol_versions", []))
        )
        if isinstance(mcp_t.get("protocol"), dict) or isinstance(mcp_t.get("allowed_protocol_versions"), list)
        else ["2024-11-05", "2025-03-26"],
        mcp_transport_default_version=str(
            mcp_t.get("protocol", {}).get("default_version", mcp_t.get("default_protocol_version", "2024-11-05"))
        ),
        mcp_transport_discovery_enabled=bool(mcp_t.get("discovery", {}).get("enabled", mcp_t.get("discovery_enabled", False)))
        if isinstance(mcp_t.get("discovery"), dict)
        else bool(mcp_t.get("discovery_enabled", False)),
        mcp_transport_discovery_card=dict(mcp_t.get("discovery", {}).get("card", mcp_t.get("discovery_card", {})))
        if isinstance(mcp_t.get("discovery"), dict)
        else dict(mcp_t.get("discovery_card", {})),
        agent_stability_enabled=bool(mcp_stability.get("enabled", mcp_t.get("agent_stability_enabled", False))),
        agent_stability_window_size=int(mcp_stability.get("window_size", 5)),
        agent_stability_repeat_threshold=int(mcp_stability.get("repeat_threshold", 3)),
        agent_stability_similarity_threshold=float(mcp_stability.get("similarity_threshold", 0.92)),
        agent_stability_on_detect=str(mcp_stability.get("on_detect", "inject")),
        canary_goallock_enabled=bool(cg.get("enabled", False)),
        canary_token_prefix=str(cg.get("token_prefix", "BASTION-CANARY-")),
        canary_rotate_on_detection=bool(cg.get("rotate_on_detection", True)),
        atr_rules_enabled=bool(atr.get("enabled", False)),
        atr_rules_dir=str(atr.get("rules_dir", "./atr-rules")),
        atr_min_severity=str(atr.get("min_severity", "medium")),
        llm_scanner_enabled=bool(lls.get("enabled", False)),
        llm_scanner_url=str(lls.get("url", "http://localhost:11434")),
        llm_scanner_model=str(lls.get("model", "llama3.2:3b")),
        llm_scanner_confidence_threshold=float(lls.get("confidence_threshold", 0.85)),
        llm_scanner_timeout_ms=int(lls.get("timeout_ms", 2500)),
        llm_scanner_only_when_uncertain=bool(lls.get("only_when_heuristics_uncertain", True)),
        threat_feeds_enabled=bool(tf.get("enabled", False)),
        threat_feeds=list(tf.get("feeds", [])) if isinstance(tf.get("feeds"), list) else [],
        auto_repave_enabled=bool(ar.get("enabled", False)),
        auto_repave_triggers=dict(ar.get("triggers", {})) if isinstance(ar.get("triggers"), dict) else {},
        auto_repave_actions=dict(ar.get("actions", {})) if isinstance(ar.get("actions"), dict) else {},
        secrets_redact_patterns=list(sec.get("redact_patterns", []))
        if isinstance(sec.get("redact_patterns"), list)
        else [],
        bastion_mode=mode if mode in ("enforce", "observe") else "enforce",
    )


def _load_server_manifest(config: BastionConfig) -> dict[str, str]:
    files, _sig = _load_server_manifest_bundle(config)
    return files


def _load_server_manifest_bundle(config: BastionConfig) -> tuple[dict[str, str], str | None]:
    """Return (files, optional HMAC signature) from inline config or manifest file."""
    manifest = dict(config.server_verification_manifest)
    signature = config.server_verification_manifest_signature
    path_raw = config.server_verification_manifest_path
    if not path_raw:
        return manifest, signature
    p = Path(path_raw)
    if not p.is_file():
        logger.warning("server_verification manifest_path not found: %s", p)
        return manifest, signature
    try:
        if p.suffix.lower() in (".yaml", ".yml"):
            data = _load_yaml(p)
            files = data.get("files", data) if isinstance(data, dict) else {}
            if isinstance(data, dict) and data.get("signature"):
                signature = signature or str(data["signature"])
        else:
            import json

            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "files" in data:
                files = data["files"]
                if data.get("signature"):
                    signature = signature or str(data["signature"])
            else:
                files = data
        if isinstance(files, dict):
            for k, v in files.items():
                if str(k) in ("signature", "algorithm"):
                    continue
                manifest[str(k)] = str(v)
    except Exception as e:
        logger.warning("server_verification failed to load manifest_path %s: %s", p, e)
    return manifest, signature


def _build_chain(config: BastionConfig) -> Any:
    validate_bastion_config(config)
    AuditHashChain.configure(anchor_every=config.audit_hash_chain_anchor_every)
    sinks = []
    if config.alerts_slack_webhook:
        sinks.append(
            SlackAlertSink(
                config.alerts_slack_webhook,
                retry_attempts=config.alerts_retry_attempts,
                retry_backoff_seconds=config.alerts_retry_backoff_seconds,
                retry_backoff_max_seconds=config.alerts_retry_backoff_max_seconds,
                timeout_seconds=config.alerts_timeout_seconds,
            )
        )
    if config.alerts_webhook_url:
        sinks.append(
            WebhookAlertSink(
                config.alerts_webhook_url,
                retry_attempts=config.alerts_retry_attempts,
                retry_backoff_seconds=config.alerts_retry_backoff_seconds,
                retry_backoff_max_seconds=config.alerts_retry_backoff_max_seconds,
                timeout_seconds=config.alerts_timeout_seconds,
            )
        )
    for url in config.alerts_webhooks:
        sinks.append(
            WebhookAlertSink(
                url,
                retry_attempts=config.alerts_retry_attempts,
                retry_backoff_seconds=config.alerts_retry_backoff_seconds,
                retry_backoff_max_seconds=config.alerts_retry_backoff_max_seconds,
                timeout_seconds=config.alerts_timeout_seconds,
            )
        )
    anchor_url = config.audit_anchor_webhook_url or os.environ.get("BASTION_ANCHOR_WEBHOOK_URL")
    audit_jsonl_sink = None
    if config.audit_jsonl_path:
        from mcp_bastion.audit_jsonl import AuditJsonlSink

        audit_jsonl_sink = AuditJsonlSink(config.audit_jsonl_path)
    telemetry_callbacks = build_telemetry_sinks_from_config(config)
    export_cb = (
        make_audit_export_callback(
            alert_sinks=sinks,
            alert_on=set(config.alerts_on),
            behavior_fingerprint=config.behavior_fingerprint,
            anchor_webhook_url=anchor_url,
            telemetry_sinks=telemetry_callbacks or None,
            telemetry_export_mode=config.telemetry_export_mode,
            audit_jsonl_sink=audit_jsonl_sink,
        )
        if config.audit
        else None
    )

    audit_mw = AuditLogMiddleware(export_callback=export_cb) if config.audit else None

    denylist_patterns = list(config.content_filter_denylist_patterns)
    threat_feed_extra_heuristics: list[str] = []
    atr_loader: ATRRuleLoader | None = None
    if config.atr_rules_enabled:
        atr_loader = ATRRuleLoader(config.atr_rules_dir, min_severity=config.atr_min_severity)
        denylist_patterns.extend(atr_loader.denylist_patterns())

    threat_feed_manager: ThreatFeedManager | None = None
    if config.threat_feeds_enabled and config.threat_feeds:
        threat_feed_manager = ThreatFeedManager(config.threat_feeds)
        threat_feed_manager.refresh_all()
        denylist_patterns.extend(threat_feed_manager.patterns_for("content_filter"))
        threat_feed_extra_heuristics = threat_feed_manager.patterns_for("prompt_injection")

    content_filter = ContentFilter(
        block_code_execution=config.content_filter_block_code_execution,
        block_file_paths=config.content_filter_block_file_paths,
        block_urls=config.content_filter_block_urls,
        block_secrets=config.content_filter_block_secrets,
        allowlist_patterns=config.content_filter_allowlist_patterns,
        denylist_patterns=denylist_patterns,
    )
    ext_cfg = ExternalPolicyConfig(
        engine=normalize_engine(config.policy_engine_type),
        opa_binary=config.opa_binary,
        opa_policy_dir=config.opa_policy_dir,
        opa_query=config.opa_query,
        cedar_binary=config.cedar_binary,
        cedar_policies_dir=config.cedar_policies_dir,
        cedar_schema_path=config.cedar_schema_path,
        fail_closed=config.policy_engine_fail_closed,
    )
    external_evaluator = ExternalPolicyEvaluator(ext_cfg)
    sensitive_classifier = SensitiveContentClassifier(
        threshold=config.sensitive_classifier_threshold,
        use_transformers=config.sensitive_classifier_use_transformers,
        model_name=config.sensitive_classifier_model_name,
    )

    edge_secret: str | None = None
    if config.edge_auth_enabled:
        edge_secret = os.environ.get(config.edge_auth_secret_env)
        if not edge_secret:
            logger.warning(
                "edge_auth enabled but %s is unset; authentication checks are disabled",
                config.edge_auth_secret_env,
            )

    state_backend = build_state_backend(
        backend=config.state_backend,
        redis_url=config.state_backend_redis_url,
        key_prefix=config.state_backend_key_prefix,
    )
    mcp_transport_cfg = mcp_transport_config_from_bastion(config)
    agent_stability_monitor = None
    if config.agent_stability_enabled:
        agent_stability_monitor = AgentStabilityMonitor(
            window_size=config.agent_stability_window_size,
            repeat_threshold=config.agent_stability_repeat_threshold,
            similarity_threshold=config.agent_stability_similarity_threshold,
            backend=state_backend,
        )
    shared_backend = state_backend if config.state_backend.strip().lower() == "redis" else None

    agent_iam: AgentIAM | None = None
    if config.agent_iam_enabled:
        policies = parse_agent_policies(config.agent_iam_agents, state_backend=shared_backend)
        if not policies:
            logger.warning("agent_iam enabled but no agents resolved (check token_env / token)")
        agent_iam = AgentIAM(
            policies,
            token_metadata_key=config.agent_iam_token_metadata_key,
            require_token=config.agent_iam_require_token,
            isolate_sessions=config.agent_iam_isolate_sessions,
        )

    server_verifier: ServerVerifier | None = None
    if config.server_verification_enabled:
        manifest, manifest_sig = _load_server_manifest_bundle(config)
        signing_key = os.environ.get(config.server_verification_signature_env)
        if not manifest:
            logger.warning("server_verification enabled but manifest is empty")
        else:
            server_verifier = ServerVerifier(
                manifest,
                base_path=config.server_verification_base_path,
                on_mismatch=config.server_verification_on_mismatch,  # type: ignore[arg-type]
                manifest_signature=manifest_sig,
                signing_key=signing_key,
            )
            if config.server_verification_on_mismatch == "block":
                server_verifier.ensure_ok()

    if config.stdio_guard_enabled:
        from mcp_bastion.pillars.stdio_guard import install_stdio_guard

        install_stdio_guard()

    if config.schema_validation and not config.schema_validation_schemas:
        logger.warning(
            "schema_validation enabled but schema_validation.schemas is empty in bastion.yaml — "
            "enforcement is a no-op until tool schemas are configured"
        )
    schema_validator = SchemaValidator(config.schema_validation_schemas)

    argument_guards: ArgumentGuardEngine | None = None
    if config.argument_guards_enabled:
        rules = parse_guard_rules(config.argument_guards_rules)
        if rules:
            argument_guards = ArgumentGuardEngine(rules)
        else:
            logger.warning("argument_guards enabled but rules list is empty")

    canary_goallock: CanaryGoalLock | None = None
    if config.canary_goallock_enabled:
        canary_goallock = CanaryGoalLock(
            token_prefix=config.canary_token_prefix,
            rotate_on_detection=config.canary_rotate_on_detection,
            backend=shared_backend,
        )

    llm_scanner: LLMScanner | None = None
    if config.llm_scanner_enabled:
        llm_scanner = LLMScanner(
            url=config.llm_scanner_url,
            model=config.llm_scanner_model,
            confidence_threshold=config.llm_scanner_confidence_threshold,
            timeout_ms=config.llm_scanner_timeout_ms,
            only_when_heuristics_uncertain=config.llm_scanner_only_when_uncertain,
        )

    auto_repave: AutoRepaveEngine | None = None
    if config.auto_repave_enabled:
        auto_repave = AutoRepaveEngine(
            triggers=config.auto_repave_triggers,
            actions=config.auto_repave_actions,
            backend=shared_backend,
            on_rotate_canary=(canary_goallock.rotate_canary if canary_goallock else None),
        )

    secret_redactor: SecretPatternRedactor | None = None
    if config.secrets_redact_patterns:
        secret_redactor = SecretPatternRedactor(config.secrets_redact_patterns)

    prompt_guard_engine = PromptGuardEngine(
        threshold=config.prompt_guard_threshold,
        model_id=config.prompt_guard_model_id,
        fail_open=config.prompt_guard_fail_open,
        heuristic_fallback=config.prompt_guard_heuristic_fallback,
        use_ungated_default=config.prompt_guard_use_ungated_default,
        heuristic_extra_patterns=threat_feed_extra_heuristics or None,
    )

    if threat_feed_manager is not None:

        def _sync_threat_feed_patterns() -> None:
            merged_denylists = list(config.content_filter_denylist_patterns)
            if atr_loader is not None:
                merged_denylists.extend(atr_loader.denylist_patterns())
            merged_denylists.extend(threat_feed_manager.patterns_for("content_filter"))
            content_filter.update_denylist_patterns(merged_denylists)
            prompt_guard_engine.update_heuristic_extra_patterns(
                threat_feed_manager.patterns_for("prompt_injection")
            )

        threat_feed_manager._on_refresh = _sync_threat_feed_patterns
        threat_feed_manager.start_background()

    bastion_mw = MCPBastionMiddleware(
        prompt_guard=prompt_guard_engine,
        rate_limiter=TokenBucketRateLimiter(
            max_iterations=config.rate_limit_max_iterations,
            timeout_seconds=config.rate_limit_timeout_seconds,
            token_budget=config.rate_limit_token_budget,
            max_per_tool=config.rate_limit_max_per_tool,
            backend=shared_backend,
        ),
        cost_tracker=CostTracker(
            max_cost_per_session=config.cost_max_per_session,
            max_cost_per_day=config.cost_max_per_day,
            backend=shared_backend,
            checkpoint_path=config.cost_checkpoint_path,
        ),
        content_filter=content_filter,
        rbac=RBAC(
            config.rbac_permissions,
            require_authenticated_identity=config.rbac_require_authenticated_identity,
        ),
        schema_validator=schema_validator,
        replay_guard=ReplayGuard(require_nonce=config.replay_require_nonce, backend=shared_backend),
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
        enable_semantic_firewall=config.semantic_firewall,
        sensitive_classifier=sensitive_classifier,
        enable_sensitive_classifier=config.sensitive_classifier,
        sensitive_classifier_threshold=config.sensitive_classifier_threshold,
        sensitive_classifier_block_labels=set(config.sensitive_classifier_block_labels),
        external_policy=external_evaluator,
        enable_external_policy=normalize_engine(config.policy_engine_type) != "none",
        enable_cost_attribution=config.cost_attribution,
        default_tenant_id=config.multi_tenant_default_tenant,
        enable_edge_auth=config.edge_auth_enabled and bool(edge_secret),
        edge_auth_metadata_key=config.edge_auth_metadata_key,
        edge_auth_secret=edge_secret,
        enable_tool_allowlist=config.tool_allowlist_enabled,
        tool_allowlist=set(str(x) for x in config.tool_allowlist if str(x).strip()),
        session_max_unique_tools=max(0, int(config.session_max_unique_tools)),
        enable_tool_metadata_guard=config.tool_metadata_guard_enabled,
        tool_metadata_guard_on_poison=config.tool_metadata_guard_on_poison,
        tool_metadata_guard_use_content_filter=config.tool_metadata_guard_use_content_filter,
        enable_response_scan=config.response_scan,
        response_scan_extra_patterns=config.response_scan_extra_patterns,
        enable_discovery_filter=config.discovery_filter,
        enable_output_budget=config.output_budget,
        output_budget=OutputBudget(
            max_output_tokens=config.output_budget_max_tokens,
            min_tokens=config.output_budget_min_tokens,
            enable_offload=config.output_budget_offload,
            retrieve_tool=config.output_budget_retrieve_tool,
            max_response_bytes=config.output_budget_max_response_bytes,
        ),
        enable_grounding_guard=config.grounding_guard,
        grounding_guard=GroundingGuard(
            workspace_root=config.grounding_guard_workspace_root,
            on_violation=config.grounding_guard_on_violation,  # type: ignore[arg-type]
        ),
        agent_iam=agent_iam,
        enable_agent_iam=config.agent_iam_enabled and agent_iam is not None,
        server_verifier=server_verifier,
        enable_server_verification=config.server_verification_enabled and server_verifier is not None,
        state_backend=state_backend,
        argument_guards=argument_guards,
        enable_argument_guards=config.argument_guards_enabled and argument_guards is not None,
        cost_policy=CostPolicyEngine.from_config(config.cost_policy_config)
        if config.cost_policy_enabled
        else None,
        enable_cost_policy=config.cost_policy_enabled,
        config_source_path=config.source_path,
        enable_governance_attestation=config.governance_attestation_enabled,
        enable_boundary_mode=config.boundary_mode_enabled,
        identity_adapter=IdentityAdapter.from_config(config.identity_adapter_config)
        if config.identity_adapter_enabled
        else None,
        enable_identity_adapter=config.identity_adapter_enabled,
        canary_goallock=canary_goallock,
        enable_canary_goallock=config.canary_goallock_enabled and canary_goallock is not None,
        atr_rules=atr_loader,
        enable_atr_rules=config.atr_rules_enabled and atr_loader is not None,
        llm_scanner=llm_scanner,
        enable_llm_scanner=config.llm_scanner_enabled and llm_scanner is not None,
        auto_repave=auto_repave,
        enable_auto_repave=config.auto_repave_enabled and auto_repave is not None,
        secret_redactor=secret_redactor,
        enable_secret_redaction=secret_redactor is not None,
        mcp_transport_config=mcp_transport_cfg,
        agent_stability=agent_stability_monitor,
        enable_agent_stability=config.agent_stability_enabled and agent_stability_monitor is not None,
        agent_stability_on_detect=config.agent_stability_on_detect,
        shadow_mode=config.bastion_mode == "observe",
    )
    if config.governance_registry_url:
        schedule_registry_beacon(
            str(config.governance_registry_url).strip(),
            {
                "event": "bastion_process_start",
                "service_id": config.governance_service_id or "unspecified",
                "bastion_version": _bastion_distribution_version(),
                "config_path": config.source_path,
            },
        )

    if audit_mw is not None:
        return compose_middleware(audit_mw, bastion_mw)
    return bastion_mw


class _HotReloadingMiddleware:
    """Reload bastion.yaml in-process when it changes on disk."""

    def __init__(
        self,
        *,
        config_path: Path,
        initial_config: BastionConfig,
        poll_seconds: float,
    ) -> None:
        self._config_path = config_path
        self._poll_seconds = max(0.25, poll_seconds)
        self._last_poll = 0.0
        self._last_file_sig = self._file_sig()
        self._chain = _build_chain(initial_config)
        self._lock = threading.Lock()

    def _file_sig(self) -> tuple[int, int] | None:
        """Return (mtime_ns, size) so we detect edits even when st_mtime rounds the same on some hosts."""
        try:
            st = self._config_path.stat()
            return (int(st.st_mtime_ns), int(st.st_size))
        except OSError:
            return None

    def _mtime(self) -> tuple[int, int] | None:
        """Alias for :meth:`_file_sig` (tests and older call sites)."""
        return self._file_sig()

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._last_poll < self._poll_seconds:
            return
        self._last_poll = now
        new_sig = self._file_sig()
        if new_sig is None or self._last_file_sig is None or new_sig == self._last_file_sig:
            return
        try:
            new_config = load_config(self._config_path)
            new_chain = _build_chain(new_config)
        except Exception as e:
            logger.warning("Hot reload skipped; invalid config %s: %s", self._config_path, e)
            return
        with self._lock:
            self._chain = new_chain
            self._last_file_sig = new_sig
        logger.info("Reloaded bastion config from %s", self._config_path)

    async def __call__(self, context: MiddlewareContext[Any], call_next: CallNext[Any]) -> Any:
        self._maybe_reload()
        with self._lock:
            chain = self._chain
        return await chain(context, call_next)


class _TenantRoutingMiddleware:
    """Route a single Bastion instance across tenant-specific config files."""

    def __init__(self, *, base_config: BastionConfig, config_dir: Path, default_tenant: str) -> None:
        self._base = base_config
        self._dir = config_dir
        self._default_tenant = default_tenant or "default"
        self._lock = threading.Lock()
        self._chains: dict[str, tuple[Any, float | None]] = {}

    def _tenant_file(self, tenant_id: str) -> Path:
        safe = "".join(ch for ch in tenant_id if ch.isalnum() or ch in ("-", "_", "."))
        return self._dir / f"{safe or 'default'}.yaml"

    def _build_for_tenant(self, tenant_id: str) -> Any:
        cfg_path = self._tenant_file(tenant_id)
        if cfg_path.exists():
            cfg = load_config(cfg_path)
        else:
            cfg = BastionConfig(**vars(self._base))
            cfg.source_path = self._base.source_path
        cfg.multi_tenant_enabled = False
        cfg.multi_tenant_default_tenant = self._default_tenant
        return _build_chain(cfg)

    def _get_chain(self, tenant_id: str) -> Any:
        path = self._tenant_file(tenant_id)
        mtime = path.stat().st_mtime if path.exists() else None
        with self._lock:
            item = self._chains.get(tenant_id)
            if item is not None and item[1] == mtime:
                return item[0]
        chain = self._build_for_tenant(tenant_id)
        with self._lock:
            self._chains[tenant_id] = (chain, mtime)
        return chain

    async def __call__(self, context: MiddlewareContext[Any], call_next: CallNext[Any]) -> Any:
        tenant_id = resolve_tenant_id(context, self._default_tenant)
        context.metadata["tenant_id"] = tenant_id
        chain = self._get_chain(tenant_id)
        return await chain(context, call_next)


def build_middleware_from_config(config: BastionConfig | None = None) -> Any:
    """
    Build composed middleware from BastionConfig.
    If config is None, load from load_config().
    """
    if config is None:
        config = load_config()
    path = Path(config.source_path) if config.source_path else None
    if config.hot_reload and path is not None and path.exists():
        return _HotReloadingMiddleware(
            config_path=path,
            initial_config=config,
            poll_seconds=config.hot_reload_poll_seconds,
        )
    if config.multi_tenant_enabled and config.multi_tenant_config_dir:
        cfg_dir = Path(config.multi_tenant_config_dir)
        cfg_dir.mkdir(parents=True, exist_ok=True)
        return _TenantRoutingMiddleware(
            base_config=config,
            config_dir=cfg_dir,
            default_tenant=config.multi_tenant_default_tenant,
        )
    return _build_chain(config)
