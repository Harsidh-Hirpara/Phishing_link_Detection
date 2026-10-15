
import pytest

pytest.importorskip("flask")

import server_main
from server_main import app


class FakeController:
    def analyze(self, url, check_threat_intelligence=True, run_sandbox=True):
        return {
            "url": url,
            "analysis": {
                "verdict": "malicious",
                "risk_score": 90,
                "confidence": 0.98,
                "summary": "Threat evidence is strong.",
                "recommendation": "Do not proceed.",
                "indicators": [],
                "validation": {"validated": True},
            },
            "evidence": {
                "protocol": {
                    "value": "https",
                    "is_https": True,
                    "is_http": False,
                },
                "hostname": {
                    "value": "example.com",
                    "type": "domain",
                    "length": 11,
                    "subdomain_count": 0,
                },
                "suspicious_keywords": [],
                "special_character_indicators": [],
                "url_length": 19,
                "threat_intelligence": {
                    "checked": True,
                    "listed": True,
                    "api_error": False,
                },
                "checks": [],
            },
            "threat_intelligence": {
                "checked": True,
                "listed": True,
                "api_error": False,
            },
        }


def test_analyze_endpoint_maps_safety_score_correctly(monkeypatch):
    monkeypatch.setattr(
        server_main,
        "jarvis_controller",
        FakeController(),
    )
    client = app.test_client()
    response = client.post(
        "/api/analyze",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["verdict"] == "malicious"
    assert data["risk_score"] == 90
    assert data["safety_score"] == 90


def test_analyze_endpoint_rejects_invalid_url(monkeypatch):
    monkeypatch.setattr(
        server_main,
        "jarvis_controller",
        FakeController(),
    )
    client = app.test_client()
    response = client.post(
        "/api/analyze",
        json={"url": "not-a-url"},
    )

    assert response.status_code == 400
