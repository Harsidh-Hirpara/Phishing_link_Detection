"""
AI output sanitizer.

Prevents the LLM from making unsupported claims about
domain reputation, legitimacy, ownership, or popularity.

The sanitizer replaces unsupported statements instead of
deleting individual words, preserving readable output.
"""

import re
from copy import deepcopy


class AIOutputSanitizer:
    """
    Sanitize LLM-generated phishing analysis.
    """

    UNSUPPORTED_PATTERNS = [
        r"\bwell[- ]known\b",
        r"\btrusted\b",
        r"\btrustworthy\b",
        r"\blegitimate\b",
        r"\bpopular\b",
        r"\breputable\b",
        r"\bfamous\b",
        r"\bofficial\b",
        r"\bowned by\b",
        r"\bbelongs to\b",
    ]

    def sanitize(
        self,
        result: dict,
        evidence: dict,
    ) -> dict:
        """
        Sanitize the complete AI result.

        If domain reputation evidence is not available,
        unsupported reputation claims are replaced with
        evidence-based wording.
        """

        sanitized = deepcopy(result)

        # ==========================================
        # Reputation evidence check
        # ==========================================

        reputation_available = bool(
            evidence.get("domain_reputation")
        )

        if reputation_available:
            return sanitized

        # ==========================================
        # Summary
        # ==========================================

        sanitized["summary"] = self._sanitize_field(
            sanitized.get("summary", ""),
            fallback=(
                "No strong phishing indicators were "
                "identified from the available evidence."
            ),
        )

        # ==========================================
        # Recommendation
        # ==========================================

        sanitized["recommendation"] = self._sanitize_field(
            sanitized.get("recommendation", ""),
            fallback=(
                "Review the URL carefully before proceeding."
            ),
        )

        # ==========================================
        # Indicators
        # ==========================================

        indicators = sanitized.get(
            "indicators",
            [],
        )

        cleaned_indicators = []

        for indicator in indicators:

            if not isinstance(indicator, dict):
                continue

            name = str(
                indicator.get(
                    "name",
                    "",
                )
            ).strip()

            reason = str(
                indicator.get(
                    "reason",
                    "",
                )
            ).strip()

            severity = str(
                indicator.get(
                    "severity",
                    "low",
                )
            ).lower().strip()

            if not name:
                continue

            if severity not in {
                "low",
                "medium",
                "high",
            }:
                severity = "low"

            # If the indicator reason contains an unsupported
            # reputation claim, replace the reason rather
            # than deleting individual words.
            if self._contains_unsupported_claim(
                reason
            ):
                reason = (
                    "This assessment is based only on "
                    "the available URL security evidence."
                )

            cleaned_indicators.append(
                {
                    "name": name,
                    "severity": severity,
                    "reason": reason,
                }
            )

        sanitized["indicators"] = cleaned_indicators

        # ==========================================
        # Final fallbacks
        # ==========================================

        if not sanitized.get("summary"):
            sanitized["summary"] = (
                "No strong phishing indicators were "
                "identified from the available evidence."
            )

        if not sanitized.get("recommendation"):
            sanitized["recommendation"] = (
                "Review the URL carefully before proceeding."
            )

        return sanitized

    def _sanitize_field(
        self,
        text: str,
        fallback: str,
    ) -> str:
        """
        Sanitize a summary or recommendation.

        If unsupported reputation language is detected,
        replace the complete field with a safe,
        evidence-based statement.
        """

        if not text:
            return fallback

        text = str(text).strip()

        if self._contains_unsupported_claim(text):
            return fallback

        return text

    def _contains_unsupported_claim(
        self,
        text: str,
    ) -> bool:
        """
        Determine whether text contains unsupported
        reputation or legitimacy claims.
        """

        if not text:
            return False

        for pattern in self.UNSUPPORTED_PATTERNS:

            if re.search(
                pattern,
                text,
                flags=re.IGNORECASE,
            ):
                return True

        return False