import json
import pytest
import requests
from unittest.mock import Mock, patch

from app.services.llm_service import LLMService


@pytest.fixture
def evidence():
    return {
        "url": "https://google.com",
        "protocol": "https",
        "hostname": "google.com",
        "hostname_type": "domain",
        "pathname": "/",
        "query": "",
        "url_length": 18,
        "threat_intelligence": {
            "source": "URLhaus",
            "checked": True,
            "listed": False,
        },
    }


def test_llm_service_analyze_success(evidence):
    service = LLMService()

    model_result = {
        "verdict": "safe",
        "risk_score": 5,
        "confidence": 0.95,
        "reason": "No suspicious indicators found.",
        "indicators": [],
        "recommendations": [],
    }

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "OK"
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "response": json.dumps(model_result)
    }

    with patch(
        "app.services.llm_service.requests.post",
        return_value=mock_response,
    ) as mock_post:
        result = service.analyze(evidence)

    mock_post.assert_called_once()
    assert result["verdict"] == "safe"
    assert result["risk_score"] == 5
    assert result["confidence"] == 0.95



def test_llm_service_preserves_zero_confidence(evidence):
    service = LLMService()
    model_result = {
        "verdict": "safe",
        "risk_score": 0,
        "confidence": 0.0,
        "summary": "No strong indicators found.",
        "indicators": [],
        "recommendation": "Verify URLs before sharing sensitive information.",
    }
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "OK"
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"response": json.dumps(model_result)}
    with patch("app.services.llm_service.requests.post", return_value=mock_response):
        result = service.analyze(evidence)
    assert result["confidence"] == 0.0

def test_llm_service_handles_unavailable_ollama(evidence):
    service = LLMService()

    with patch(
        "app.services.llm_service.requests.post",
        side_effect=requests.ConnectionError("Ollama unavailable"),
    ):
        with pytest.raises(RuntimeError, match="LLM service unavailable"):
            service.analyze(evidence)

def test_llm_service_flags_unlisted_intelligence_as_non_proof(evidence):
    service = LLMService()
    model_result = {
        "verdict": "safe",
        "risk_score": 0,
        "confidence": 0.6,
        "summary": "No strong phishing indicators were identified from the available evidence.",
        "indicators": [],
        "recommendation": "Verify URLs before sharing sensitive information.",
    }
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "OK"
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"response": json.dumps(model_result)}
    with patch("app.services.llm_service.requests.post", return_value=mock_response):
        result = service.analyze(evidence)
    assert result["summary"] == model_result["summary"]
    assert result["indicators"] == []

def test_unlisted_threat_intelligence_indicator_is_filtered(evidence):
    service = LLMService()

    model_result = {
        "verdict": "safe",
        "risk_score": 0,
        "confidence": 0.6,
        "summary": (
            "No strong phishing indicators were identified "
            "from the available evidence."
        ),
        "indicators": [
            {
                "name": "Unlisted in threat intelligence",
                "severity": "low",
                "reason": (
                    "The URL was not listed in threat intelligence databases."
                ),
            },
            {
                "name": "Suspicious URL pattern",
                "severity": "medium",
                "reason": "Example of an independent indicator.",
            },
        ],
        "recommendation": "Review the URL carefully.",
    }

    result = service._validate_result(
        model_result,
        evidence=evidence,
    )

    names = [item["name"] for item in result["indicators"]]

    assert "Unlisted in threat intelligence" not in names
    assert "Suspicious URL pattern" in names


def test_unlisted_indicator_is_preserved_when_threat_lookup_fails(evidence):
    service = LLMService()
    evidence["threat_intelligence"]["api_error"] = True

    result = {
        "verdict": "safe",
        "risk_score": 0,
        "confidence": 0.5,
        "summary": "Threat lookup failed.",
        "indicators": [
            {
                "name": "Unlisted in threat intelligence",
                "severity": "low",
                "reason": "The lookup did not return a reliable result.",
            }
        ],
        "recommendation": "Verify the URL independently.",
    }

    validated = service._validate_result(result, evidence=evidence)

    assert len(validated["indicators"]) == 1


def test_threat_intelligence_indicator_is_preserved_when_listed(evidence):
    service = LLMService()
    evidence["threat_intelligence"]["listed"] = True

    result = {
        "verdict": "phishing",
        "risk_score": 90,
        "confidence": 0.95,
        "summary": "Threat intelligence reports this URL.",
        "indicators": [
            {
                "name": "Threat Intelligence Listing",
                "severity": "high",
                "reason": "The URL is listed as malicious.",
            }
        ],
        "recommendation": "Do not open this URL.",
    }

    validated = service._validate_result(result, evidence=evidence)

    assert len(validated["indicators"]) == 1
    assert validated["indicators"][0]["name"] == "Threat Intelligence Listing"

def test_generic_threat_intelligence_listing_is_filtered_when_unlisted(evidence):
    service = LLMService()

    result = {
        "verdict": "safe",
        "risk_score": 0,
        "confidence": 0.95,
        "summary": "No strong phishing indicators were identified.",
        "indicators": [
            {
                "name": "Threat Intelligence Listing",
                "severity": "low",
                "reason": (
                    "The URL was not listed in threat intelligence, "
                    "which is consistent with it being safe."
                ),
            }
        ],
        "recommendation": "Proceed as usual",
    }

    validated = service._validate_result(result, evidence=evidence)

    assert validated["indicators"] == []
