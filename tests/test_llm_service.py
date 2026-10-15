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
