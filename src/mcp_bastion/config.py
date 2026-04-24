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
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.sensitive_classifier import SensitiveContentClassifier
from mcp_bastion.pillars.metrics import MetricsStore
from mcp_bastion.pillars.pii_redaction import PIIRedactor
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.rbac import RBAC
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.schema_validation import SchemaValidator
from mcp_bastion.pillars.semantic_cache import SemanticCache
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
    pii: bool = True
    rate_limit: bool = True
    rate_limit_max_iterations: int = 15
    rate_limit_timeout_seconds: float = 60.0
    rate_limit_token_budget: int = 50_000
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
    schema_validation: bool = False
    replay_guard: bool = False
    replay_require_nonce: bool = False
    cost_tracker: bool = False
    cost_max_per_session: float = 0.50
    cost_max_per_day: float = 10.0
    semantic_cache: bool = False
    semantic_firewall: bool = False
    sensitive_classifier: bool = False
    sensitive_classifier_threshold: float = 0.65
    sensitive_classifier_use_transformers: bool = False
    sensitive_classifier_model_name: str = "distilbert-base-uncased-finetuned-sst-2-english"
    sensitive_classifier_block_labels: list[str] = field(default_factory=lambda: ["sensitive_business"])
    audit: bool = True
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
    tal = data.get("tool_allowlist", {}) or {}
    sess = data.get("session_limits", {}) or {}
    sc = data.get("sensitive_classifier", {}) or {}
    opa_pe = pe.get("opa", {}) or {}
    cedar_pe = pe.get("cedar", {}) or {}
    engine = normalize_engine(pe.get("type") or os.environ.get("BASTION_POLICY_ENGINE"))
    return BastionConfig(
        prompt_guard=data.get("prompt_guard", {}).get("enabled", True),
        pii=data.get("pii", {}).get("enabled", True),
        rate_limit=data.get("rate_limit", {}).get("enabled", True),
        rate_limit_max_iterations=data.get("rate_limit", {}).get("max_iterations", 15),
        rate_limit_timeout_seconds=float(data.get("rate_limit", {}).get("timeout_seconds", 60)),
        rate_limit_token_budget=data.get("rate_limit", {}).get("token_budget", 50_000),
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
        schema_validation=data.get("schema_validation", {}).get("enabled", False),
        replay_guard=data.get("replay_guard", {}).get("enabled", False),
        replay_require_nonce=data.get("replay_guard", {}).get("require_nonce", False),
        cost_tracker=data.get("cost_tracker", {}).get("enabled", False),
        cost_max_per_session=float(data.get("cost_tracker", {}).get("max_cost_per_session", 0.50)),
        cost_max_per_day=float(data.get("cost_tracker", {}).get("max_cost_per_day", 10.0)),
        semantic_cache=data.get("semantic_cache", {}).get("enabled", False),
        semantic_firewall=data.get("semantic_firewall", {}).get("enabled", False),
        sensitive_classifier=sc.get("enabled", False),
        sensitive_classifier_threshold=float(sc.get("threshold", 0.65)),
        sensitive_classifier_use_transformers=bool(sc.get("use_transformers", False)),
        sensitive_classifier_model_name=str(
            sc.get("model_name", "distilbert-base-uncased-finetuned-sst-2-english")
        ),
        sensitive_classifier_block_labels=list(sc.get("block_labels", ["sensitive_business"])),
        audit=data.get("audit", {}).get("enabled", True),
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
    )


def _build_chain(config: BastionConfig) -> Any:
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
    telemetry_callbacks = build_telemetry_sinks_from_config(config)
    export_cb = (
        make_audit_export_callback(
            alert_sinks=sinks,
            alert_on=set(config.alerts_on),
            behavior_fingerprint=config.behavior_fingerprint,
            anchor_webhook_url=anchor_url,
            telemetry_sinks=telemetry_callbacks or None,
            telemetry_export_mode=config.telemetry_export_mode,
        )
        if config.audit
        else None
    )

    audit_mw = AuditLogMiddleware(export_callback=export_cb) if config.audit else None
    content_filter = ContentFilter(
        block_code_execution=config.content_filter_block_code_execution,
        block_file_paths=config.content_filter_block_file_paths,
        block_urls=config.content_filter_block_urls,
        block_secrets=config.content_filter_block_secrets,
        allowlist_patterns=config.content_filter_allowlist_patterns,
        denylist_patterns=config.content_filter_denylist_patterns,
    )
    ext_cfg = ExternalPolicyConfig(
        engine=normalize_engine(config.policy_engine_type),
        opa_binary=config.opa_binary,
        opa_policy_dir=config.opa_policy_dir,
        opa_query=config.opa_query,
        cedar_binary=config.cedar_binary,
        cedar_policies_dir=config.cedar_policies_dir,
        cedar_schema_path=config.cedar_schema_path,
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

    bastion_mw = MCPBastionMiddleware(
        rate_limiter=TokenBucketRateLimiter(
            max_iterations=config.rate_limit_max_iterations,
            timeout_seconds=config.rate_limit_timeout_seconds,
            token_budget=config.rate_limit_token_budget,
        ),
        cost_tracker=CostTracker(
            max_cost_per_session=config.cost_max_per_session,
            max_cost_per_day=config.cost_max_per_day,
        ),
        content_filter=content_filter,
        rbac=RBAC(config.rbac_permissions),
        replay_guard=ReplayGuard(require_nonce=config.replay_require_nonce),
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
