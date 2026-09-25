"""
AI-powered URL analysis orchestration service.

Coordinates:

    URL validation
    URL parsing
    Evidence Builder
    Threat Intelligence
    LLM analysis
    AI Safety Validation
    AI Output Sanitization
"""

from app.features.url_parser import (
    is_valid_url,
    normalize_url,
    parse_url,
)

from app.features.evidence_builder import (
    EvidenceBuilder,
)

from app.services.threat_service import (
    ThreatService,
)

from app.services.llm_service import (
    LLMService,
)

from app.services.ai_safety_validator import (
    AISafetyValidator,
)

from app.services.ai_output_sanitizer import (
    AIOutputSanitizer,
)


class AIAnalysisService:

    def __init__(
        self,
        evidence_builder: EvidenceBuilder | None = None,
        threat_service: ThreatService | None = None,
        llm_service: LLMService | None = None,
        safety_validator: AISafetyValidator | None = None,
        output_sanitizer: AIOutputSanitizer | None = None,
    ):

        self.evidence_builder = (
            evidence_builder
            or EvidenceBuilder()
        )

        self.threat_service = (
            threat_service
            or ThreatService()
        )

        self.llm_service = (
            llm_service
            or LLMService()
        )

        self.safety_validator = (
            safety_validator
            or AISafetyValidator()
        )

        self.output_sanitizer = (
            output_sanitizer
            or AIOutputSanitizer()
        )

    def analyze(
        self,
        url: str,
        check_threat_intelligence: bool = True,
    ) -> dict:

        # ==================================================
        # 1. VALIDATE
        # ==================================================

        if not url or not url.strip():
            raise ValueError(
                "Please enter a URL"
            )

        if not is_valid_url(url):
            raise ValueError(
                "Invalid URL format"
            )

        # ==================================================
        # 2. NORMALIZE
        # ==================================================

        normalized_url = normalize_url(
            url.strip()
        )

        # ==================================================
        # 3. PARSE
        # ==================================================

        parsed_url = parse_url(
            normalized_url
        )

        # ==================================================
        # 4. THREAT INTELLIGENCE
        # ==================================================

        threat_result = {
            "checked": False,
            "listed": False,
            "source": None,
            "threat": None,
            "last_analysis": None,
            "api_error": False,
        }

        if check_threat_intelligence:

            raw_threat_result = (
                self.threat_service.check_url(
                    normalized_url
                )
            )

            threat_result = (
                self._normalize_threat_result(
                    raw_threat_result
                )
            )

        # ==================================================
        # 5. BUILD EVIDENCE
        # ==================================================

        evidence = self.evidence_builder.build(
            parsed_url,
            threat_result,
        )

        # ==================================================
        # 6. LLM
        # ==================================================

        raw_ai_result = (
            self.llm_service.analyze(
                evidence
            )
        )

        # ==================================================
        # 7. SAFETY VALIDATION
        # ==================================================

        validated_ai_result = (
            self.safety_validator.validate(
                raw_ai_result,
                evidence,
            )
        )

        # ==================================================
        # 8. SANITIZATION
        # ==================================================

        final_ai_result = (
            self.output_sanitizer.sanitize(
                validated_ai_result,
                evidence,
            )
        )

        # ==================================================
        # 9. FINAL RESPONSE
        # ==================================================

        return {
            "url": normalized_url,

            "analysis": final_ai_result,

            "evidence": evidence,

            "threat_intelligence": threat_result,

            # IMPORTANT:
            # Send the seven objective security checks
            # directly to the frontend.
            "checks": evidence.get(
                "checks",
                [],
            ),
        }

    def _normalize_threat_result(
        self,
        result: dict,
    ) -> dict:

        if not result:

            return {
                "checked": True,
                "listed": False,
                "source": "URLhaus",
                "threat": None,
                "last_analysis": None,
                "api_error": True,
            }

        is_phishing = bool(
            result.get(
                "is_phishing",
                False,
            )
        )

        return {
            "checked": True,
            "listed": is_phishing,
            "source": "URLhaus",
            "threat": result.get(
                "threat"
            ),
            "last_analysis": result.get(
                "last_analysis"
            ),
            "api_error": bool(
                result.get(
                    "api_error",
                    False,
                )
            ),
        }