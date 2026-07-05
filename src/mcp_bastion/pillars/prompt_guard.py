"""
Prompt injection detection via Llama Prompt Guard 2 + regex heuristics.

Primary: meta-llama/Llama-Prompt-Guard-2-86M (gated — requires Hugging Face access).
Fallback: local regex heuristics block obvious jailbreaks when ML is unavailable.
Default posture: fail-closed on ML errors (blocks request unless fail_open=True).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_bastion.errors import PromptGuardUnavailableError
from mcp_bastion.pillars.injection_heuristics import compile_injection_patterns, find_injection_match

if TYPE_CHECKING:
    import torch

logger = logging.getLogger(__name__)

MALICIOUS_THRESHOLD = 0.85
TEMPERATURE = 0.1
MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"
HF_ACCESS_URL = "https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M"


class PromptGuardEngine:
    """PromptGuard 86M with heuristic fallback. CPU/GPU."""

    def __init__(
        self,
        threshold: float = MALICIOUS_THRESHOLD,
        temperature: float = TEMPERATURE,
        model_id: str = MODEL_ID,
        device: str | None = None,
        *,
        fail_open: bool = False,
        heuristic_fallback: bool = True,
        heuristic_extra_patterns: list[str] | None = None,
    ) -> None:
        self.threshold = threshold
        self.temperature = temperature
        self.model_id = model_id
        self.fail_open = fail_open
        self.heuristic_fallback = heuristic_fallback
        self._heuristic_regexes = compile_injection_patterns(heuristic_extra_patterns)
        self._model = None
        self._tokenizer = None
        self._device = device
        self._ml_loaded = False
        self._ml_load_failed = False
        self._ml_unavailable_reason: str | None = None

    def heuristic_match(self, text: str) -> str | None:
        """Return matched heuristic pattern, if any."""
        if not self.heuristic_fallback:
            return None
        return find_injection_match(text, self._heuristic_regexes)

    def model_status(self) -> dict[str, Any]:
        """Report ML model load state for doctor / validation scripts."""
        return {
            "ml_loaded": self._ml_loaded,
            "ml_load_failed": self._ml_load_failed,
            "ml_unavailable_reason": self._ml_unavailable_reason,
            "heuristic_fallback": self.heuristic_fallback,
            "fail_open": self.fail_open,
            "model_id": self.model_id,
            "hf_access_url": HF_ACCESS_URL,
        }

    def _ensure_loaded(self) -> None:
        """Lazy-load model and tokenizer. Failed loads are cached (no repeated HF calls)."""
        if self._model is not None:
            return
        if self._ml_load_failed:
            raise RuntimeError(self._ml_unavailable_reason or "PromptGuard ML model unavailable")
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_id)

            if self._device is None:
                self._device = "cuda" if torch.cuda.is_available() else "cpu"
            self._model = self._model.to(self._device)
            self._model.eval()
            self._ml_loaded = True
            self._ml_unavailable_reason = None
            logger.info("PromptGuard loaded model=%s device=%s", self.model_id, self._device)
        except Exception as e:
            self._ml_unavailable_reason = str(e)
            self._ml_load_failed = True
            logger.warning(
                "PromptGuard ML model unavailable (%s). "
                "Heuristic fallback=%s; accept gated repo access at %s and run `huggingface-cli login`. "
                "Further ML load attempts skipped for this engine instance.",
                e,
                self.heuristic_fallback,
                HF_ACCESS_URL,
            )
            raise

    def _temperature_adjusted_softmax(self, logits: "torch.Tensor") -> "torch.Tensor":
        """Temperature scaling before softmax."""
        import torch

        scaled = logits / self.temperature
        return torch.softmax(scaled, dim=-1)

    def score(self, text: str) -> float:
        """Malicious probability 0-1. Above threshold = block. Requires ML model."""
        if not text or not text.strip():
            return 0.0

        self._ensure_loaded()
        import torch

        inputs = self._tokenizer(
            text[:512],
            return_tensors="pt",
            truncation=True,
            max_length=512,
        ).to(self._device)

        with torch.no_grad():
            outputs = self._model(**inputs)
            probs = self._temperature_adjusted_softmax(outputs.logits)
            probs_np = probs.cpu().numpy()

        label2id = self._model.config.label2id
        malicious_id = label2id.get("MALICIOUS", label2id.get("malicious", 1))
        return float(probs_np[0][malicious_id])

    def is_malicious(self, text: str) -> bool:
        """
        True if text should be blocked.

        Order: regex heuristics (no deps) → ML score → fail-closed on ML error.
        """
        if not text or not text.strip():
            return False

        matched = self.heuristic_match(text)
        if matched:
            logger.info("PromptGuard heuristic match: %s", matched[:120])
            return True

        try:
            return self.score(text) >= self.threshold
        except Exception as e:
            self._ml_unavailable_reason = str(e)
            if self.fail_open:
                logger.warning(
                    "PromptGuard ML unavailable (%s) and fail_open=True — allowing unverified request.",
                    e,
                )
                return False
            raise PromptGuardUnavailableError(
                "Request blocked: PromptGuard ML model unavailable. "
                f"Accept access at {HF_ACCESS_URL}, authenticate with Hugging Face "
                "(`huggingface-cli login`), or set prompt_guard.fail_open: true for dev only. "
                f"Underlying error: {e}"
            ) from e
