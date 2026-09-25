"""Offline detection suite. Live Ollama/URLhaus tests are opt-in."""

import os

import pytest

from app.features.evidence_builder import EvidenceBuilder
from app.features.url_parser import is_valid_url, normalize_url, parse_url
from app.services.ai_safety_validator import AISafetyValidator


def test_detection_evidence_safe_url():
    url = normalize_url("https://example.com")
    evidence = EvidenceBuilder().build(parse_url(url))
    assert evidence["protocol"]["is_https"] is True
    assert evidence["hostname"]["type"] == "domain"
    assert evidence["suspicious_keywords"] == []
    assert len(evidence["checks"]) == 7


def test_detection_evidence_suspicious_url():
    url = normalize_url("http://192.168.1.10/verify-login-urgent-confirm")
    evidence = EvidenceBuilder().build(parse_url(url))
    assert evidence["protocol"]["is_http"] is True
    assert evidence["hostname"]["type"] == "ipv4"
    assert len(evidence["suspicious_keywords"]) >= 2


def test_invalid_urls_are_rejected():
    for url in ["", "not-a-url", "http://", "https://", "example"]:
        assert is_valid_url(url) is False


@pytest.mark.skipif(
    os.getenv("RUN_LIVE_AI_TESTS") != "1",
    reason="Set RUN_LIVE_AI_TESTS=1 to run live Ollama/URLhaus tests",
)
def test_live_ai_pipeline():
    from app.services.ai_analysis_service import AIAnalysisService
    result = AIAnalysisService().analyze("https://example.com")
    assert result["analysis"]["verdict"] in {"safe", "suspicious", "phishing"}
