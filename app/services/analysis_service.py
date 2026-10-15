"""
Main URL analysis service.

Coordinates:
    URL validation
    URL normalization
    URL parsing
    Rule-based analysis
    External threat intelligence
"""

from app.features.url_parser import (
    is_valid_url,
    normalize_url,
    parse_url,
)

from app.features.rule_engine import RuleEngine
from app.services.threat_service import ThreatService


class AnalysisService:
    """
    Main service responsible for phishing URL analysis.
    """

    def __init__(
        self,
        rule_engine: RuleEngine | None = None,
        threat_service: ThreatService | None = None,
    ):
        self.rule_engine = rule_engine or RuleEngine()
        self.threat_service = threat_service or ThreatService()

    def analyze(
        self,
        url: str,
        check_threat_intelligence: bool = False,
    ) -> dict:
        """
        Analyze a URL.

        By default, only local rule-based analysis is performed.
        External threat intelligence can be enabled explicitly.
        """

        # ==========================================
        # 1. Validate URL
        # ==========================================

        if not url or not url.strip():
            raise ValueError("Please enter a URL")

        if not is_valid_url(url):
            raise ValueError("Invalid URL format")

        # ==========================================
        # 2. Normalize URL
        # ==========================================

        normalized_url = normalize_url(url.strip())

        # ==========================================
        # 3. Parse URL
        # ==========================================

        parsed_url = parse_url(normalized_url)

        # ==========================================
        # 4. Local Rule Engine
        # ==========================================

        result = self.rule_engine.analyze(
            parsed_url,
            normalized_url,
        )

        # ==========================================
        # 5. Base Response
        # ==========================================

        analysis = {
            "url": normalized_url,
            "verdict": result["verdict"],
            "safety_score": result["safety_score"],
            "risk_score": result["risk_score"],
            "checks": result["checks"],
            "threat_intelligence": None,
        }

        # ==========================================
        # 6. External Threat Intelligence
        # ==========================================

        if check_threat_intelligence:

            threat_result = self.threat_service.check_url(
                normalized_url
            )

            analysis["threat_intelligence"] = threat_result

            # ======================================
            # URLhaus detected the URL
            # ======================================

            if threat_result.get("is_phishing"):

                analysis["risk_score"] += 50

                analysis["safety_score"] = max(
                    0,
                    100 - analysis["risk_score"],
                )

                analysis["verdict"] = "unsafe"

                analysis["checks"].insert(
                    0,
                    {
                        "name": "Global Threat Database",
                        "status": "fail",
                        "description": (
                            "URL detected in the URLhaus "
                            "malicious URL database"
                        ),
                    },
                )

            # ======================================
            # URLhaus successfully checked URL
            # ======================================

            elif not threat_result.get("api_error"):

                analysis["checks"].insert(
                    0,
                    {
                        "name": "Global Threat Database",
                        "status": "pass",
                        "description": (
                            "URL checked against URLhaus "
                            "threat intelligence database"
                        ),
                    },
                )

            # ======================================
            # API unavailable
            # ======================================

            else:

                analysis["checks"].insert(
                    0,
                    {
                        "name": "Global Threat Database",
                        "status": "warn",
                        "description": (
                            "Threat intelligence service "
                            "was unavailable"
                        ),
                    },
                )

        return analysis