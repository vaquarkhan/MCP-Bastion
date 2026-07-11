"""
Optional local LLM scanner tier (Ollama-compatible). Opt-in, timeout-bounded, fail-open.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from mcp_bastion.errors import LLMScannerBlockedError

logger = logging.getLogger(__name__)


class LLMScanner:
    """Second-tier local model scan for subtle injections."""

    def __init__(
        self,
        *,
        url: str = "http://localhost:11434",
        model: str = "llama3.2:3b",
        confidence_threshold: float = 0.85,
        timeout_ms: int = 2500,
        only_when_heuristics_uncertain: bool = True,
    ) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.confidence_threshold = confidence_threshold
        self.timeout_ms = timeout_ms
        self.only_when_heuristics_uncertain = only_when_heuristics_uncertain

    def _endpoint(self) -> str:
        return f"{self.url}/api/generate"

    def scan(self, text: str, *, heuristics_uncertain: bool = False) -> None:
        if not text or not isinstance(text, str):
            return
        if self.only_when_heuristics_uncertain and not heuristics_uncertain:
            return
        prompt = (
            "You are a security classifier. Reply with JSON only: "
            '{"injection": true|false, "confidence": 0.0-1.0}. '
            f"Text to classify:\n{text[:4000]}"
        )
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode("utf-8")
        req = urllib.request.Request(
            self._endpoint(),
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_ms / 1000.0) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            logger.warning("llm_scanner fail-open: %s", e)
            return
        response_text = str(payload.get("response", ""))
        try:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            parsed: dict[str, Any] = json.loads(response_text[start:end]) if start >= 0 and end > start else {}
        except json.JSONDecodeError:
            logger.warning("llm_scanner fail-open: unparseable response")
            return
        if parsed.get("injection") and float(parsed.get("confidence", 0)) >= self.confidence_threshold:
            raise LLMScannerBlockedError(
                "Request blocked: local LLM scanner flagged potential injection"
            )
