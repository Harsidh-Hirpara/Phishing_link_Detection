from app.services.ai_analysis_service import AIAnalysisService


class FakeThreatService:
    def check_url(self, url):
        return {
            "is_phishing": False,
            "threat": None,
            "last_analysis": None,
            "api_error": False,
        }


class FakeLLMService:
    def analyze(self, evidence):
        return {
            "verdict": "safe",
            "risk_score": 5,
            "confidence": 0.9,
            "summary": "No strong phishing indicators were identified from the available evidence.",
            "indicators": [],
            "recommendation": "Review the URL carefully before proceeding.",
        }


def test_ai_pipeline_without_external_services():
    service = AIAnalysisService(
        threat_service=FakeThreatService(),
        llm_service=FakeLLMService(),
    )

    result = service.analyze(
        "https://example.com",
        check_threat_intelligence=True,
    )

    assert result["analysis"]["verdict"] == "safe"
    assert result["analysis"]["risk_score"] == 5
    assert len(result["checks"]) == 7


def test_validator_constrains_strong_combination():
    service = AIAnalysisService(
        threat_service=FakeThreatService(),
        llm_service=FakeLLMService(),
    )

    result = service.analyze(
        "http://192.168.1.10/verify-login-urgent-confirm",
        check_threat_intelligence=False,
    )

    assert result["analysis"]["verdict"] == "suspicious"
    assert result["analysis"]["risk_score"] >= 65
    assert result["analysis"]["validation"]["guardrails_triggered"] is True
