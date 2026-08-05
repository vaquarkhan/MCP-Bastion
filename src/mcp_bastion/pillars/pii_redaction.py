"""
PII redaction via Microsoft Presidio.

presidio-analyzer, presidio-anonymizer, spaCy. Sanitizes TextContent.
Optional reversible tokenization is handled by ``pii_vault`` (opt-in).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Presidio's US_SSN recognizer can miss well-formed dashed SSNs in short strings; supplement with a format pass.
_SSN_DASHED_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _redact_dashed_ssn_patterns(text: str, placeholder: str = "<US_SSN>") -> str:
    """Redact XXX-XX-XXXX (dashes required). Does not validate SSN assignment validity."""
    if not text:
        return text
    return _SSN_DASHED_PATTERN.sub(placeholder, text)


class PIIRedactor:
    """Presidio + spaCy. Sanitizes TextContent."""

    def __init__(
        self,
        entities: list[str] | None = None,
        language: str = "en",
    ) -> None:
        self.entities = entities or [
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "US_SSN",
            "US_PASSPORT",
            "MEDICAL_LICENSE",
            "IBAN_CODE",
        ]
        self.language = language
        self._analyzer = None
        self._anonymizer = None

    def _ensure_loaded(self) -> None:
        """Lazy-load Presidio components with optimized spaCy config."""
        if self._analyzer is not None:
            return
        try:
            try:
                import spacy
                from spacy.util import is_package
            except ImportError as e:
                raise RuntimeError("spaCy is not installed") from e

            if not is_package("en_core_web_sm"):
                raise RuntimeError(
                    "spaCy model en_core_web_sm is not installed — "
                    "run: python -m spacy download en_core_web_sm"
                )
            # Load once here so Presidio does not invoke spaCy's auto-download helper (sys.exit in CI).
            spacy.load("en_core_web_sm")

            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            from presidio_anonymizer import AnonymizerEngine

            config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": self.language, "model_name": "en_core_web_sm"}],
            }
            provider = NlpEngineProvider(nlp_configuration=config)
            nlp_engine = provider.create_engine()

            self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=[self.language])
            self._anonymizer = AnonymizerEngine()
        except Exception as e:
            logger.warning("Presidio load failed: %s. PII redaction disabled.", e)
            raise

    def detect_spans(self, text: str) -> list[Any]:
        """Return ``EntitySpan`` list for reversible vault abstraction."""
        from mcp_bastion.pillars.pii_vault import detect_entities_presidio

        return detect_entities_presidio(self, text)

    def redact_text(self, text: str) -> str:
        """
        Analyze and anonymize PII in the given text.

        Returns sanitized text with detected entities replaced by placeholders.
        """
        if not text or not isinstance(text, str):
            return text

        try:
            self._ensure_loaded()
            results = self._analyzer.analyze(
                text=text,
                language=self.language,
                entities=self.entities,
            )
            if not results:
                return _redact_dashed_ssn_patterns(text)
            logger.debug("redacted %d entities", len(results))
            try:
                from collections import Counter

                from mcp_bastion.pillars.metrics import MetricsStore

                MetricsStore.get().record_pii_entities(dict(Counter(r.entity_type for r in results)))
            except Exception:
                pass
            anonymized = self._anonymizer.anonymize(text=text, analyzer_results=results)
            return _redact_dashed_ssn_patterns(anonymized.text)
        except Exception as e:
            logger.warning("PII redaction failed: %s. Applying pattern fallback only.", e)
            return _redact_dashed_ssn_patterns(text)

    def vault_text(
        self,
        text: str,
        vault: Any,
        session_key: str,
        *,
        detect: Callable[[str], list[Any]] | None = None,
    ) -> str:
        """Abstract PII into vault tokens (reversible). Falls back to regex detect."""
        if vault is None:
            return self.redact_text(text)
        detector = detect or self.detect_spans
        return vault.abstract_text(text, session_key, detect=detector)

    def redact_content_items(self, content: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Redact PII from MCP content items.

        Processes TextContent items; other types are passed through unchanged.
        """
        if not content:
            return content

        result = []
        for item in content:
            if not isinstance(item, dict):
                result.append(item)
                continue
            if item.get("type") == "text" and "text" in item:
                result.append({
                    **item,
                    "text": self.redact_text(str(item["text"])),
                })
            else:
                result.append(item)
        return result

    def vault_content_items(
        self,
        content: list[dict[str, Any]],
        vault: Any,
        session_key: str,
        *,
        detect: Callable[[str], list[Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Vault-abstract text content items (reversible)."""
        if not content:
            return content
        if vault is None:
            return self.redact_content_items(content)
        detector = detect or self.detect_spans
        return vault.abstract_content_items(content, session_key, detect=detector)
