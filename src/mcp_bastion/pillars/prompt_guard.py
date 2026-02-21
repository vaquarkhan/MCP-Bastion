"""
Prompt injection detection via Llama Prompt Guard 2.

Uses meta-llama/Llama-Prompt-Guard-2-86M, temperature-adjusted softmax.
Blocks when malicious probability exceeds threshold (default 0.85).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import torch

logger = logging.getLogger(__name__)

MALICIOUS_THRESHOLD = 0.85
TEMPERATURE = 0.1
MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"


class PromptGuardEngine:
    """PromptGuard 86M, temperature softmax. CPU/GPU."""

    def __init__(
        self,
        threshold: float = MALICIOUS_THRESHOLD,
        temperature: float = TEMPERATURE,
        model_id: str = MODEL_ID,
        device: str | None = None,
    ) -> None:
        self.threshold = threshold
        self.temperature = temperature
        self.model_id = model_id
        self._model = None
        self._tokenizer = None
        self._device = device

    def _ensure_loaded(self) -> None:
        """Lazy-load model and tokenizer."""
        if self._model is not None:
            return
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_id)

            if self._device is None:
                self._device = "cuda" if torch.cuda.is_available() else "cpu"
            self._model = self._model.to(self._device)
            self._model.eval()
            logger.info("PromptGuard loaded model=%s device=%s", self.model_id, self._device)
        except Exception as e:
            logger.warning("PromptGuard model load failed: %s. Injection check disabled.", e)
            raise

    def _temperature_adjusted_softmax(self, logits: "torch.Tensor") -> "torch.Tensor":
        """Temperature scaling before softmax."""
        import torch
        scaled = logits / self.temperature
        return torch.softmax(scaled, dim=-1)

    def score(self, text: str) -> float:
        """Malicious probability 0-1. Above threshold = block."""
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
        """True if score >= threshold."""
        try:
            score = self.score(text)
            return score >= self.threshold
        except Exception as e:
            logger.warning("PromptGuard inference failed: %s. Allowing request.", e)
            return False
