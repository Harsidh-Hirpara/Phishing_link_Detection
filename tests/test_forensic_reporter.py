"""
Tests for ForensicReporter.
"""

import pytest

from app.services.forensic_reporter import ForensicReporter


# ============================================================
# HELPERS
# ============================================================


def make_pre_scan(
    verdict="suspicious",
    risk_score=55,
    confidence=0.7,
    summary="Pre-scan summary.",
    threat_intelligence=None,
):
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "summary": summary,
        "indicators": [],
        "recommendation": "Check carefully.",
        "threat_intelligence": threat_intelligence or {
            "checked": True,
            "listed": False,
            "source": "URLhaus",
            "api_error": False,
        },
    }


def make_sandbox(
    url="https://evil.com",
    terminated_early=False,
    cumulative_threat_score=0,
    redirect_count=0,
    page_title="Evil Page",
    network_events=None,
    browser_events=None,
    page_events=None,
    threat_events=None,
):
    return {
        "url": url,
        "started_at": "2026-10-04T10:00:00+00:00",
        "ended_at": "2026-10-04T10:00:15+00:00",
        "page_title": page_title,
        "redirect_count": redirect_count,
        "terminated_early": terminated_early,
        "termination_reason": "Score exceeded threshold." if terminated_early else None,
        "cumulative_threat_score": cumulative_threat_score,
        "network_events": network_events or [],
        "browser_events": browser_events or [],
        "page_events": page_events or [],
        "threat_events": threat_events or [],
        "screenshot_b64": None,
    }


def make_behavior(
    verdict="malicious",
    confidence=0.9,
    behavior_score=75,
    rule_findings=None,
):
    return {
        "verdict": verdict,
        "confidence": confidence,
        "behavior_score": behavior_score,
        "summary": "Credential harvesting detected.",
        "rule_findings": rule_findings or [
            {
                "rule_id": "RULE_PW_FIELD",
                "name": "Password Field",
                "severity": "high",
                "description": "Password input found.",
                "evidence": {},
                "score_contribution": 40,
            }
        ],
        "rule_score": 40,
        "llm_verdict": "malicious",
        "llm_confidence": 0.9,
        "llm_summary": "LLM says malicious.",
        "llm_indicators": [],
    }


# ============================================================
# TESTS
# ============================================================


class TestForensicReporter:

    def setup_method(self):
        self.reporter = ForensicReporter()

    # ----------------------------------------------------------
    # Output structure

    def test_report_required_keys(self):
        report = self.reporter.build(
            url="https://example.com",
            pre_scan=make_pre_scan(),
            sandbox=None,
            behavior=None,
        )

        required = {
            "session_id",
            "generated_at",
            "url",
            "final_verdict",
            "final_confidence",
            "final_risk_score",
            "pre_scan",
            "sandbox_triggered",
            "sandbox",
            "behavior_analyzed",
            "behavior",
            "timeline",
            "narrative",
            "recommendation",
        }
        assert required.issubset(report.keys())

    def test_session_id_is_uuid(self):
        import uuid
        report = self.reporter.build(
            url="https://example.com",
            pre_scan=make_pre_scan(),
            sandbox=None,
            behavior=None,
        )
        # Should not raise
        uuid.UUID(report["session_id"])

    def test_sandbox_none_when_not_triggered(self):
        report = self.reporter.build(
            url="https://example.com",
            pre_scan=make_pre_scan(),
            sandbox=None,
            behavior=None,
        )

        assert report["sandbox_triggered"] is False
        assert report["sandbox"] is None
        assert report["behavior_analyzed"] is False
        assert report["behavior"] is None

    def test_sandbox_present_when_triggered(self):
        report = self.reporter.build(
            url="https://evil.com",
            pre_scan=make_pre_scan(),
            sandbox=make_sandbox(),
            behavior=make_behavior(),
        )

        assert report["sandbox_triggered"] is True
        assert report["sandbox"] is not None
        assert report["behavior_analyzed"] is True
        assert report["behavior"] is not None

    # ----------------------------------------------------------
    # Verdict computation

    def test_no_sandbox_uses_pre_scan_verdict(self):
        report = self.reporter.build(
            url="https://example.com",
            pre_scan=make_pre_scan(verdict="safe", risk_score=10),
            sandbox=None,
            behavior=None,
        )

        assert report["final_verdict"] == "safe"

    def test_behavior_malicious_overrides_pre_scan_safe(self):
        """If behavior says malicious, the final verdict must be malicious."""
        report = self.reporter.build(
            url="https://evil.com",
            pre_scan=make_pre_scan(verdict="safe", risk_score=5),
            sandbox=make_sandbox(),
            behavior=make_behavior(verdict="malicious"),
        )

        assert report["final_verdict"] == "malicious"

    def test_pre_scan_malicious_not_overridden_by_safe_behavior(self):
        """Pre-scan malicious verdict should NOT be lowered by safe behavior."""
        report = self.reporter.build(
            url="https://phish.com",
            pre_scan=make_pre_scan(verdict="phishing", risk_score=90),
            sandbox=make_sandbox(),
            behavior=make_behavior(verdict="safe", confidence=0.3, behavior_score=0),
        )

        # malicious/phishing pre-scan rank=2, safe behavior rank=0
        # final = max = malicious
        assert report["final_verdict"] == "malicious"

    def test_risk_score_bounded(self):
        report = self.reporter.build(
            url="https://example.com",
            pre_scan=make_pre_scan(risk_score=100),
            sandbox=make_sandbox(cumulative_threat_score=100),
            behavior=make_behavior(behavior_score=100),
        )

        assert 0 <= report["final_risk_score"] <= 100

    # ----------------------------------------------------------
    # Timeline

    def test_timeline_has_pre_scan_event(self):
        report = self.reporter.build(
            url="https://example.com",
            pre_scan=make_pre_scan(),
            sandbox=None,
            behavior=None,
        )

        kinds = [ev.get("kind") for ev in report["timeline"]]
        assert "pre_scan_complete" in kinds

    def test_timeline_sandbox_skipped_when_no_sandbox(self):
        report = self.reporter.build(
            url="https://example.com",
            pre_scan=make_pre_scan(),
            sandbox=None,
            behavior=None,
        )

        kinds = [ev.get("kind") for ev in report["timeline"]]
        assert "sandbox_skipped" in kinds

    def test_timeline_behavior_event_when_sandbox_run(self):
        report = self.reporter.build(
            url="https://evil.com",
            pre_scan=make_pre_scan(),
            sandbox=make_sandbox(),
            behavior=make_behavior(),
        )

        kinds = [ev.get("kind") for ev in report["timeline"]]
        assert "behavior_analysis_complete" in kinds

    # ----------------------------------------------------------
    # Narrative

    def test_narrative_contains_url(self):
        report = self.reporter.build(
            url="https://evil.com",
            pre_scan=make_pre_scan(),
            sandbox=None,
            behavior=None,
        )

        assert "https://evil.com" in report["narrative"]

    def test_narrative_mentions_sandbox_not_triggered(self):
        report = self.reporter.build(
            url="https://example.com",
            pre_scan=make_pre_scan(),
            sandbox=None,
            behavior=None,
        )

        assert "NOT triggered" in report["narrative"]

    def test_narrative_mentions_sandbox_when_run(self):
        report = self.reporter.build(
            url="https://evil.com",
            pre_scan=make_pre_scan(),
            sandbox=make_sandbox(terminated_early=True),
            behavior=make_behavior(),
        )

        assert "TERMINATION REASON" in report["narrative"]

    # ----------------------------------------------------------
    # Recommendation

    def test_recommendation_malicious_warns_strongly(self):
        report = self.reporter.build(
            url="https://evil.com",
            pre_scan=make_pre_scan(),
            sandbox=make_sandbox(),
            behavior=make_behavior(verdict="malicious"),
        )

        assert "NOT visit" in report["recommendation"]

    def test_recommendation_suspicious_warns(self):
        report = self.reporter.build(
            url="https://suspicious.com",
            pre_scan=make_pre_scan(verdict="suspicious"),
            sandbox=None,
            behavior=None,
        )

        assert "caution" in report["recommendation"].lower()

    def test_recommendation_safe_is_gentle(self):
        report = self.reporter.build(
            url="https://example.com",
            pre_scan=make_pre_scan(verdict="safe", risk_score=5),
            sandbox=None,
            behavior=None,
        )

        assert "strong threat" in report["recommendation"].lower()

    # ----------------------------------------------------------
    # Sandbox summary

    def test_sandbox_summary_contains_screenshot_key(self):
        report = self.reporter.build(
            url="https://evil.com",
            pre_scan=make_pre_scan(),
            sandbox=make_sandbox(),
            behavior=make_behavior(),
        )

        assert "screenshot_b64" in report["sandbox"]

    def test_sandbox_summary_event_counts(self):
        sb = make_sandbox(
            network_events=[{"timestamp": "t", "kind": "request", "data": {}, "threat_weight": 0}],
            browser_events=[{"timestamp": "t", "kind": "popup_opened", "data": {}, "threat_weight": 20}],
            page_events=[{"timestamp": "t", "kind": "page_title", "data": {}, "threat_weight": 0}],
        )
        report = self.reporter.build(
            url="https://evil.com",
            pre_scan=make_pre_scan(),
            sandbox=sb,
            behavior=make_behavior(),
        )

        assert report["sandbox"]["total_network_events"] == 1
        assert report["sandbox"]["total_browser_events"] == 1
        assert report["sandbox"]["total_page_events"] == 1
