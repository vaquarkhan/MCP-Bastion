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

from mcp_bastion.pillars.audit_log import AuditLogMiddleware
from mcp_bastion.pillars.alerts import SlackAlertSink, WebhookAlertSink, make_audit_export_callback
from mcp_bastion.pillars.circuit_breaker import CircuitBreaker
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.metrics import MetricsStore
from mcp_bastion.pillars.pii_redaction import PIIRedactor
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.rbac import RBAC
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.schema_validation import SchemaValidator
from mcp_bastion.pillars.semantic_cache import SemanticCache
from mcp_bastion.base import CallNext, MiddlewareContext, compose_middleware
from mcp_bastion.middleware import MCPBastionMiddleware

logger = logging.getLogger(__name__)


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
    source_path: str | None = None


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
        source_path=str(p),
    )


def _build_chain(config: BastionConfig) -> Any:
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
    export_cb = make_audit_export_callback(
        alert_sinks=sinks,
        alert_on=set(config.alerts_on),
    ) if config.audit else None

    audit_mw = AuditLogMiddleware(export_callback=export_cb) if config.audit else None
    content_filter = ContentFilter(
        block_code_execution=config.content_filter_block_code_execution,
        block_file_paths=config.content_filter_block_file_paths,
        block_urls=config.content_filter_block_urls,
        allowlist_patterns=config.content_filter_allowlist_patterns,
        denylist_patterns=config.content_filter_denylist_patterns,
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
        self._last_mtime = self._mtime()
        self._chain = _build_chain(initial_config)
        self._lock = threading.Lock()

    def _mtime(self) -> float | None:
        try:
            return self._config_path.stat().st_mtime
        except OSError:
            return None

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._last_poll < self._poll_seconds:
            return
        self._last_poll = now
        mtime = self._mtime()
        if mtime is None or self._last_mtime is None or mtime <= self._last_mtime:
            return
        try:
            new_config = load_config(self._config_path)
            new_chain = _build_chain(new_config)
        except Exception as e:
            logger.warning("Hot reload skipped; invalid config %s: %s", self._config_path, e)
            return
        with self._lock:
            self._chain = new_chain
            self._last_mtime = mtime
        logger.info("Reloaded bastion config from %s", self._config_path)

    async def __call__(self, context: MiddlewareContext[Any], call_next: CallNext[Any]) -> Any:
        self._maybe_reload()
        with self._lock:
            chain = self._chain
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
    return _build_chain(config)
