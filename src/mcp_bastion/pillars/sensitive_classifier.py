"""
Model-based sensitive business content classifier.

Primary mode uses a lightweight local scoring model with term weights.
Optional mode uses a local transformers classifier when installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class SensitiveClassification:
    label: str
    score: float
    matches: list[str]
    source: str


class SensitiveContentClassifier:
    """
    Detect unstructured sensitive business content.

    This intentionally works without network calls:
    - default: small local weighted model (fast, deterministic)
    - optional: local DistilBERT-like text classifier if transformers is installed
    """

    _WEIGHTS: dict[str, float] = {
        "m&a": 0.45,
        "acquisition": 0.36,
        "merger": 0.34,
        "due diligence": 0.31,
        "ipo": 0.30,
        "insider": 0.24,
        "embezzl": 0.38,
        "fraud": 0.29,
        "whistleblower": 0.34,
        "layoff": 0.24,
        "confidential": 0.22,
        "board minutes": 0.28,
        "earnings before release": 0.40,
        "customer list": 0.24,
        "source code leak": 0.42,
        "trade secret": 0.36,
    }

    def __init__(
        self,
        *,
        threshold: float = 0.65,
        use_transformers: bool = False,
        model_name: str = "distilbert-base-uncased-finetuned-sst-2-english",
    ) -> None:
        self.threshold = float(max(0.0, min(1.0, threshold)))
        self.use_transformers = bool(use_transformers)
        self.model_name = model_name
        self._pipeline: Any = None

    def _get_pipeline(self) -> Any:
        if self._pipeline is not None:
            return self._pipeline
        if not self.use_transformers:
            return None
        try:
            from transformers import pipeline

            self._pipeline = pipeline("text-classification", model=self.model_name)
            return self._pipeline
        except Exception:
            return None

    def classify(self, text: str) -> SensitiveClassification:
        raw = (text or "").strip()
        if not raw:
            return SensitiveClassification(label="not_sensitive", score=0.0, matches=[], source="empty")

        pipe = self._get_pipeline()
        if pipe is not None:
            try:
                pred = pipe(raw[:4096])[0]
                label = str(pred.get("label", "")).lower()
                score = float(pred.get("score", 0.0))
                # Generic classifier fallback mapping: treat highly negative/conflictive text as risk signal.
                if "negative" in label and score >= self.threshold:
                    return SensitiveClassification(
                        label="sensitive_business",
                        score=score,
                        matches=["transformers_negative_signal"],
                        source="transformers",
                    )
            except Exception:
                pass

        lower = raw.lower()
        score = 0.0
        hits: list[str] = []
        for term, w in self._WEIGHTS.items():
            if term in lower:
                score += w
                hits.append(term)
        # Normalize to [0,1] with diminishing returns.
        norm = score / (1.0 + score) if score > 0 else 0.0
        label = "sensitive_business" if norm >= self.threshold else "not_sensitive"
        return SensitiveClassification(label=label, score=round(norm, 4), matches=hits, source="weighted_local")
