import json

import pytest

from app.services.llm_service import LLMService


def test_parse_plain_json():
    service = LLMService()
    raw = '{"verdict":"safe","risk_score":5,"confidence":0.9,"summary":"ok","indicators":[],"recommendation":"review"}'
    assert service._parse_response(raw)["verdict"] == "safe"


def test_parse_markdown_json():
    service = LLMService()
    raw = '```json\n{"verdict":"suspicious","risk_score":55,"confidence":0.8,"summary":"risk","indicators":[],"recommendation":"review"}\n```'
    result = service._parse_response(raw)
    assert result["risk_score"] == 55


def test_validate_result_normalizes_ranges():
    service = LLMService()
    result = service._validate_result({
        "verdict": "phishing",
        "risk_score": 120,
        "confidence": 2,
        "summary": "test",
        "indicators": [],
        "recommendation": "do not proceed",
    })
    assert result["risk_score"] == 100
    assert result["confidence"] == 1.0
    assert result["verdict"] == "phishing"


def test_analyze_uses_ollama(monkeypatch):
    service = LLMService()

    class FakeResponse:
        status_code = 200
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "response": json.dumps({
                    "verdict": "safe",
                    "risk_score": 2,
                    "confidence": 0.9,
                    "summary": "No strong indicators.",
                    "indicators": [],
                    "recommendation": "Review before proceeding.",
                })
            }

    monkeypatch.setattr("app.services.llm_service.requests.post", lambda *a, **k: FakeResponse())
    result = service.analyze({"url": "https://example.com"})
    assert result["verdict"] == "safe"
