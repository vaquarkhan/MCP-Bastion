"""
Audit logging for MCP-Bastion.

Every tool call logged with: who, what, when, blocked/allowed, why.
Structured JSON for export to CloudWatch, Datadog, OpenTelemetry.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from mcp_bastion.base import CallNext, Middleware, MiddlewareContext

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Structured audit log entry for compliance and observability."""

    timestamp: str
    session_id: str | None
    request_id: str | None
    tool: str
    action: str  # ALLOWED | BLOCKED
    tenant_id: str | None = None
    reason: str | None = None
    latency_ms: float = 0.0
    tokens_used: int = 0
    error_code: int | None = None
    forensic_event_id: str | None = None
    forensic_request: dict[str, Any] | None = None
    forensic_response: dict[str, Any] | None = None
    forensic_trace: list[dict[str, Any]] = field(default_factory=list)
    replay_payload: dict[str, Any] | None = None
    cost_usd: float = 0.0
    cost_dimensions: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def _get_tool_name(message: Any) -> str:
    """Extract tool name from tools/call message."""
    if hasattr(message, "root"):
        msg = message.root
    else:
        msg = message
    if isinstance(msg, dict):
        params = msg.get("params") or msg.get("result") or msg
        if isinstance(params, dict):
            return str(params.get("name", "unknown"))
    if hasattr(msg, "params") and hasattr(msg.params, "name"):
        return str(msg.params.name)
    return "unknown"


def _is_call_tool_request(message: Any) -> bool:
    if hasattr(message, "root"):
        msg = message.root
    else:
        msg = message
    if hasattr(msg, "method") and getattr(msg, "method", None) == "tools/call":
        return True
    if isinstance(msg, dict) and msg.get("method") == "tools/call":
        return True
    return False


class AuditLogMiddleware(Middleware[Any]):
    """
    Logs every tool call with structured audit data.

    Use for compliance, observability, and export to CloudWatch/Datadog/OpenTelemetry.
    """

    def __init__(
        self,
        *,
        log_level: int = logging.INFO,
        export_callback: Callable[[AuditEntry], None] | None = None,
        include_tokens: bool = True,
    ) -> None:
        self.log_level = log_level
        self.export_callback = export_callback
        self.include_tokens = include_tokens

    async def on_message(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any],
    ) -> Any:
        """Wrap execution and log audit entry."""
        msg = context.message
        if not _is_call_tool_request(msg):
            return await call_next(context)

        tool = _get_tool_name(msg)
        start = time.perf_counter()
        action = "ALLOWED"
        reason = None
        error_code = None
        tokens_used = 0

        try:
            result = await call_next(context)
            if context.metadata.get("tokens_used"):
                tokens_used = context.metadata["tokens_used"]
            return result
        except Exception as e:
            action = "BLOCKED"
            reason = str(e)
            if hasattr(e, "code"):
                error_code = getattr(e, "code", None)
            raise
        finally:
            latency_ms = (time.perf_counter() - start) * 1000
            if not self.include_tokens:
                tokens_used = 0
            cost_usd = float(context.metadata.get("cost_usd") or context.metadata.get("cost") or 0.0)
            cost_dimensions = context.metadata.get("cost_dimensions")
            if not isinstance(cost_dimensions, dict):
                cost_dimensions = None

            entry = AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                tenant_id=context.metadata.get("tenant_id"),
                session_id=context.session_id,
                request_id=context.request_id,
                tool=tool,
                action=action,
                reason=reason,
                latency_ms=round(latency_ms, 2),
                tokens_used=tokens_used,
                error_code=error_code,
                forensic_event_id=context.metadata.get("forensic_event_id") or str(uuid4()),
                forensic_request=context.metadata.get("forensic_request"),
                forensic_response=context.metadata.get("forensic_response"),
                forensic_trace=context.metadata.get("pillar_trace", []),
                replay_payload=context.metadata.get("replay_payload"),
                cost_usd=cost_usd,
                cost_dimensions=cost_dimensions,
            )

            logger.log(self.log_level, "audit %s", entry.to_json())

            if self.export_callback:
                try:
                    self.export_callback(entry)
                except Exception as ex:
                    logger.warning("audit export failed: %s", ex)
