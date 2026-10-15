"""
AI safety and consistency validation.

This layer does not perform the primary phishing analysis.
It checks whether the LLM assessment is consistent with
strong objective evidence.
"""

from copy import deepcopy


class AISafetyValidator:
    """
    Validate LLM output against objective security evidence.
    """

    def validate(
        self,
        ai_result: dict,
        evidence: dict,
    ) -> dict:
        """
        Validate and, when necessary, constrain the AI result.
        """

        result = deepcopy(ai_result)

        reasons = []

        threat_intelligence = evidence.get(
            "threat_intelligence",
            {},
        )

        hostname = evidence.get(
            "hostname",
            {},
        )

        protocol = evidence.get(
            "protocol",
            {},
        )

        suspicious_keywords = evidence.get(
            "suspicious_keywords",
            [],
        )

        # ==================================================
        # Guardrail 1: Confirmed threat intelligence
        # ==================================================

        if threat_intelligence.get("listed") is True:

            result["verdict"] = "phishing"

            result["risk_score"] = max(
                int(result.get("risk_score", 0)),
                90,
            )

            result["confidence"] = max(
                float(result.get("confidence", 0)),
                0.95,
            )

            reasons.append(
                "The URL is listed by the configured "
                "threat-intelligence source."
            )

        # ==================================================
        # Guardrail 2: Strong technical combination
        # ==================================================

        is_http = (
            protocol.get("is_http") is True
        )

        is_ip = (
            hostname.get("type")
            in {"ipv4", "ipv6"}
        )

        keyword_count = len(
            suspicious_keywords
        )

        strong_combination = (
            is_http
            and is_ip
            and keyword_count >= 2
        )

        if strong_combination:

            if result.get("verdict") == "safe":

                result["verdict"] = "suspicious"

                result["risk_score"] = max(
                    int(result.get("risk_score", 0)),
                    65,
                )

                result["confidence"] = min(
                    max(
                        float(
                            result.get(
                                "confidence",
                                0,
                            )
                        ),
                        0.75,
                    ),
                    0.95,
                )

                reasons.append(
                    "The AI assessment was constrained because "
                    "the URL combines unencrypted HTTP, a direct "
                    "IP address, and multiple suspicious keywords."
                )

            elif result.get("verdict") == "suspicious":

                result["risk_score"] = max(
                    int(result.get("risk_score", 0)),
                    65,
                )

                reasons.append(
                    "The URL contains multiple strong "
                    "technical risk indicators."
                )

        # ==================================================
        # Guardrail 3: Prevent impossible values
        # ==================================================

        result["risk_score"] = max(
            0,
            min(
                100,
                int(result.get("risk_score", 0)),
            ),
        )

        result["confidence"] = max(
            0.0,
            min(
                1.0,
                float(
                    result.get(
                        "confidence",
                        0,
                    )
                ),
            ),
        )

        # ==================================================
        # Add validator information
        # ==================================================

        result["validation"] = {
            "validated": True,
            "guardrails_triggered": len(
                reasons
            ) > 0,
            "reasons": reasons,
        }

        return result