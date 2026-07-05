"""
FinOps output budget: truncate oversized tool/resource text before it hits the agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from mcp_bastion.pillars.session_offload import SessionOffloadStore
from mcp_bastion.pillars.tokens import count_text_tokens, truncate_text_to_token_budget


@dataclass
class OutputBudgetResult:
    """Summary of output budget processing for FinOps telemetry."""

    applied: bool = False
    original_tokens: int = 0
    output_tokens: int = 0
    tokens_saved: int = 0
    offloaded: bool = False
    offload_key: str | None = None
    truncated_items: int = 0


class OutputBudget:
    """
    Truncate large MCP text content items to a token budget.

    When offload is enabled, full text is kept in SessionOffloadStore and a short
    pointer is returned so agents can retrieve via the configured retrieve tool.
    """

    def __init__(
        self,
        *,
        max_output_tokens: int = 4000,
        min_tokens: int = 500,
        head_ratio: float = 0.7,
        enable_offload: bool = True,
        retrieve_tool: str = "bastion_get_offloaded",
        offload_store: SessionOffloadStore | None = None,
        token_counter: Callable[[str], int] | None = None,
    ) -> None:
        if max_output_tokens < 1:
            raise ValueError("max_output_tokens must be >= 1")
        if min_tokens < 0:
            raise ValueError("min_tokens must be >= 0")
        if not 0.0 < head_ratio < 1.0:
            raise ValueError("head_ratio must be between 0 and 1")
        self.max_output_tokens = max_output_tokens
        self.min_tokens = min_tokens
        self.head_ratio = head_ratio
        self.enable_offload = enable_offload
        self.retrieve_tool = retrieve_tool.strip()
        self.offload_store = offload_store or SessionOffloadStore()
        self._count_tokens = token_counter or count_text_tokens

    def process_content_items(
        self,
        content: list[dict[str, Any]],
        *,
        session_id: str | None = None,
        tool_name: str | None = None,
    ) -> tuple[list[dict[str, Any]], OutputBudgetResult]:
        """Return possibly truncated content and processing summary."""
        summary = OutputBudgetResult()
        if not content:
            return content, summary

        out: list[dict[str, Any]] = []
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "text" or "text" not in item:
                out.append(item)
                continue

            text = str(item["text"])
            original = self._count_tokens(text)
            summary.original_tokens += original

            if original <= self.min_tokens or original <= self.max_output_tokens:
                summary.output_tokens += original
                out.append(item)
                continue

            summary.applied = True
            summary.truncated_items += 1

            if self.enable_offload:
                key = self.offload_store.put(text, session_id=session_id, tool_name=tool_name)
                summary.offloaded = True
                summary.offload_key = key
                pointer = (
                    f"[MCP-Bastion: {original:,} tokens offloaded to session cache]\n"
                    f"Key: {key}\n"
                    f"Retrieve with tool `{self.retrieve_tool}` and argument `{{\"key\": \"{key}\"}}`.\n"
                    f"Preview:\n"
                )
                preview_budget = min(200, self.max_output_tokens)
                preview = truncate_text_to_token_budget(
                    text, preview_budget, head_ratio=self.head_ratio, token_counter=self._count_tokens
                )
                new_text = pointer + preview
            else:
                new_text = truncate_text_to_token_budget(
                    text, self.max_output_tokens, head_ratio=self.head_ratio, token_counter=self._count_tokens
                )
                new_text = (
                    f"[MCP-Bastion: truncated from {original:,} to ~{self.max_output_tokens:,} tokens]\n"
                    + new_text
                )

            kept = self._count_tokens(new_text)
            summary.output_tokens += kept
            summary.tokens_saved += max(0, original - kept)
            out.append({**item, "text": new_text})

        return out, summary
