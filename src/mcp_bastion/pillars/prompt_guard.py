"""
Prompt injection detection via ML classifier + regex heuristics.

Default ML model: ProtectAI/deberta-v3-base-prompt-injection-v2 (ungated, no HF login).
Optional: meta-llama/Llama-Prompt-Guard-2-86M when use_ungated_default=false (HF gated).
Fallback: regex heuristics catch obvious jailbreak strings only (not novel injection).
Heuristic mode is not a substitute for ML scoring or argument_guards.
Default posture: fail-closed on ML errors (blocks request unless fail_open=True).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_bastion.errors import PromptGuardUnavailableError
from mcp_bastion.pillars.injection_heuristics import (
    compile_injection_patterns,
    find_injection_match,
    has_injection_intent,
)

if TYPE_CHECKING:
    import torch

logger = logging.getLogger(__name__)

MALICIOUS_THRESHOLD = 0.85
TEMPERATURE = 0.1
MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"
UNGATED_MODEL_ID = "ProtectAI/deberta-v3-base-prompt-injection-v2"
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
        use_ungated_default: bool = True,
        require_ml_corroboration: bool = True,
        ml_corroboration_ceiling: float = 1.01,
    ) -> None:
        self.threshold = threshold
        self.temperature = temperature
        self.use_ungated_default = use_ungated_default
        self.model_id = UNGATED_MODEL_ID if use_ungated_default else model_id
        self.fail_open = fail_open
        self.heuristic_fallback = heuristic_fallback
        self._heuristic_regexes = compile_injection_patterns(heuristic_extra_patterns)
        self._model = None
        self._tokenizer = None
        self._device = device
        self._ml_loaded = False
        self._ml_load_failed = False
        self._ml_unavailable_reason: str | None = None
        # N-2 fix: when the ML flags malicious but there is no injection-intent marker and no
        # heuristic match, treat it as the known business-verb false positive and allow. Set
        # require_ml_corroboration=False for max-recall (higher false-positive) deployments.
        self.require_ml_corroboration = require_ml_corroboration
        # ProtectAI is uncalibrated and returns ~1.0 even for the business-verb false positives,
        # so a confidence "ceiling" cannot separate them. Default 1.01 = ceiling effectively off;
        # corroboration is decided purely by the injection-intent marker.
        self.ml_corroboration_ceiling = ml_corroboration_ceiling

    def heuristic_match(self, text: str) -> str | None:
        """Return matched heuristic pattern, if any."""
        if not self.heuristic_fallback:
            return None
        return find_injection_match(text, self._heuristic_regexes)

    def update_heuristic_extra_patterns(self, patterns: list[str] | None) -> None:
        """Replace merged threat-feed / config heuristic patterns."""
        self._heuristic_regexes = compile_injection_patterns(patterns)

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

        Order: benign allowlist → regex heuristics → ML score → fail-closed on ML error.
        """
        if not text or not text.strip():
            return False

        from mcp_bastion.pillars.injection_heuristics import is_benign_allowlisted

        if is_benign_allowlisted(text):
            logger.debug("PromptGuard benign allowlist hit; skipping ML")
            return False

        matched = self.heuristic_match(text)
        if matched:
            logger.info("PromptGuard heuristic match: %s", matched[:120])
            return True

        try:
            score = self.score(text)
            if score < self.threshold:
                return False
            # ML says malicious. Corroborate to suppress the business-verb false positives (N-2):
            # a real injection targets the model's control surface (intent markers) or matches the
            # heuristic regexes above. If neither holds and the model isn't near-certain, allow.
            if (
                self.require_ml_corroboration
                and score < self.ml_corroboration_ceiling
                and not has_injection_intent(text)
            ):
                logger.info(
                    "PromptGuard: ML score %.3f but no injection-intent marker; "
                    "treating as benign (N-2 false-positive guard)",
                    score,
                )
                return False
            return True
        except Exception as e:
            self._ml_unavailable_reason = str(e)
            if self.fail_open:
                logger.warning(
                    "PromptGuard ML unavailable (%s) and fail_open=True - allowing unverified request.",
                    e,
                )
                return False
            raise PromptGuardUnavailableError(
                "Request blocked: PromptGuard ML model unavailable. "
                "Default model is ungated ProtectAI/deberta-v3-base-prompt-injection-v2 "
                "(pip install transformers torch). "
                f"If using gated Llama Prompt Guard, accept access at {HF_ACCESS_URL} and "
                "`huggingface-cli login`, or set prompt_guard.use_ungated_default: true. "
                "Dev-only: prompt_guard.fail_open: true. "
                f"Underlying error: {e}"
            ) from e
