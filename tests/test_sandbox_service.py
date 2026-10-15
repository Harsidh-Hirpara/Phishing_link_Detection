from app.services.sandbox_service import (
    TERMINATE_THRESHOLD,
    SandboxTerminated,
    _SandboxSession,
    _is_non_public_ip,
    _is_safe_public_http_url,
)
"""
Tests for SandboxService.

These tests cover the _SandboxSession event accumulation logic
and limit enforcement without launching a real browser.

Browser integration tests (requiring Playwright) are marked
with @pytest.mark.integration and are skipped by default.
Run them with: pytest -m integration
"""

import pytest

from app.services.sandbox_service import (
    TERMINATE_THRESHOLD,
    SandboxTerminated,
    _SandboxSession,
)


# ============================================================
# SESSION UNIT TESTS
# ============================================================


class TestSandboxSession:
    """Unit-test the _SandboxSession event accumulation logic."""

    def test_initial_state(self):
        session = _SandboxSession("https://example.com")

        assert session.url == "https://example.com"
        assert session.redirect_count == 0
        assert session.cumulative_threat_score == 0
        assert session.network_events == []
        assert session.browser_events == []
        assert session.page_events == []
        assert session.terminated_early is False
        assert session.termination_reason is None
        assert session.screenshot_b64 is None

    def test_add_network_event(self):
        session = _SandboxSession("https://example.com")
        session.add_network_event(
            "request",
            {"url": "https://example.com/page"},
            threat_weight=0,
        )

        assert len(session.network_events) == 1
        ev = session.network_events[0]
        assert ev["kind"] == "request"
        assert ev["threat_weight"] == 0
        assert "timestamp" in ev

    def test_threat_score_accumulates(self):
        session = _SandboxSession("https://evil.com")
        session.add_network_event("download_attempt", {}, threat_weight=30)
        session.add_page_event("password_field_detected", {}, threat_weight=25)
        session.add_browser_event("popup_opened", {}, threat_weight=20)

        assert session.cumulative_threat_score == 75

    def test_terminate_threshold_not_raised_below(self):
        """Session should NOT raise when score is below threshold."""
        session = _SandboxSession("https://example.com")
        session.add_network_event("request", {}, threat_weight=TERMINATE_THRESHOLD - 1)

        # Should not raise
        session.check_terminate_threshold()
        assert session.terminated_early is False

    def test_terminate_threshold_raises_at_threshold(self):
        """Session MUST raise SandboxTerminated at or above threshold."""
        session = _SandboxSession("https://example.com")
        session.add_network_event("download_attempt", {}, threat_weight=TERMINATE_THRESHOLD)

        with pytest.raises(SandboxTerminated):
            session.check_terminate_threshold()

        assert session.terminated_early is True
        assert session.termination_reason is not None

    def test_terminate_only_fires_once(self):
        """Repeated threshold checks must not re-raise after first termination."""
        session = _SandboxSession("https://example.com")
        session.add_network_event("download_attempt", {}, threat_weight=TERMINATE_THRESHOLD)

        with pytest.raises(SandboxTerminated):
            session.check_terminate_threshold()

        # Second call should NOT raise (already terminated)
        session.check_terminate_threshold()
        assert session.terminated_early is True

    def test_to_dict_structure(self):
        session = _SandboxSession("https://example.com")
        session.add_network_event("request", {"url": "https://example.com"})
        session.add_page_event("page_title", {"title": "Test Page"})

        result = session.to_dict()

        required_keys = {
            "url",
            "started_at",
            "ended_at",
            "redirect_count",
            "terminated_early",
            "cumulative_threat_score",
            "network_events",
            "browser_events",
            "page_events",
            "threat_events",
            "screenshot_b64",
        }

        assert required_keys.issubset(result.keys())
        assert result["url"] == "https://example.com"
        assert result["ended_at"] is not None

    def test_threat_events_filtered(self):
        """to_dict() must only include events with threat_weight > 0."""
        session = _SandboxSession("https://example.com")
        session.add_network_event("request", {}, threat_weight=0)
        session.add_page_event("password_field_detected", {}, threat_weight=30)

        result = session.to_dict()

        assert len(result["threat_events"]) == 1
        assert result["threat_events"][0]["kind"] == "password_field_detected"

    def test_event_timestamp_present(self):
        session = _SandboxSession("https://example.com")
        session.add_browser_event("popup_opened", {"url": "https://popup.com"})

        ev = session.browser_events[0]
        # Timestamp should be ISO format string
        assert ev["timestamp"].endswith("Z") or "+" in ev["timestamp"] or "T" in ev["timestamp"]


@pytest.mark.parametrize(
    "address, expected",
    [
        ("127.0.0.1", True),
        ("192.168.1.1", True),
        ("10.0.0.1", True),
        ("::1", True),
        ("8.8.8.8", False),
        ("example.com", False),
    ],
)
def test_non_public_ip_classification(address, expected):
    assert _is_non_public_ip(address) is expected

def test_safe_public_http_url_allows_public_ip(monkeypatch):
    import socket

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        ],
    )

    assert _is_safe_public_http_url("https://public.example") is True


def test_safe_public_http_url_blocks_private_ip():
    assert _is_safe_public_http_url("http://127.0.0.1") is False


def test_safe_public_http_url_blocks_dns_failure(monkeypatch):
    import socket

    def fail_dns(*args, **kwargs):
        raise socket.gaierror("DNS lookup failed")

    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)

    assert _is_safe_public_http_url("https://dns-failure.example") is False


def test_safe_public_http_url_blocks_mixed_public_private_dns(monkeypatch):
    import socket

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 443)),
        ],
    )

    assert _is_safe_public_http_url("https://mixed.example") is False
