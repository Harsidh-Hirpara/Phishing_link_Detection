"""
Tests for JarvisController.

All external dependencies (ThreatService, LLMService,
SandboxService, BehaviorAnalyzer) are replaced with
lightweight fakes so tests run offline without Ollama,
URLhaus, or Playwright.
"""

import pytest

from app.services.jarvis_controller import JarvisController, SANDBOX_THRESHOLD


# ============================================================
# FAKES
# ============================================================


class FakeThreatService:
    def __init__(self, is_phishing=False, api_error=False):
        self._phishing = is_phishing
        self._error = api_error

    def check_url(self, url):
        return {
            "is_phishing": self._phishing,
            "threat": None,
            "last_analysis": None,
            "api_error": self._error,
        }


class FakeLLMService:
    def __init__(self, verdict="safe", risk_score=10, confidence=0.8):
        self._verdict = verdict
        self._risk_score = risk_score
        self._confidence = confidence

    def analyze(self, evidence):
        return {
            "verdict": self._verdict,
            "risk_score": self._risk_score,
            "confidence": self._confidence,
            "summary": "Fake LLM summary.",
            "indicators": [],
            "recommendation": "Test recommendation.",
        }


class FakeAISafetyValidator:
    def validate(self, ai_result, evidence):
        ai_result["validation"] = {
            "validated": True,
            "guardrails_triggered": False,
            "reasons": [],
        }
        return ai_result


class FakeAIOutputSanitizer:
    def sanitize(self, validated, evidence):
        return validated


class FakeSandboxService:
    def __init__(
        self,
        terminated_early=False,
        cumulative_threat_score=0,
        page_title="Fake Page",
    ):
        self._terminated_early = terminated_early
        self._score = cumulative_threat_score
        self._title = page_title
        self.called_with = None

    def run(self, url):
        self.called_with = url
        return {
            "url": url,
            "started_at": "2026-10-04T10:00:00+00:00",
            "ended_at": "2026-10-04T10:00:15+00:00",
            "page_title": self._title,
            "redirect_count": 0,
            "max_redirects": 5,
            "max_requests": 150,
            "timeout_seconds": 15,
            "terminated_early": self._terminated_early,
            "termination_reason": (
                "Score exceeded threshold."
                if self._terminated_early
                else None
            ),
            "cumulative_threat_score": self._score,
            "network_events": [],
            "browser_events": [],
            "page_events": [],
            "threat_events": [],
            "screenshot_b64": None,
        }


class FakeBehaviorAnalyzer:
    def __init__(self, verdict="safe", behavior_score=5):
        self._verdict = verdict
        self._score = behavior_score
        self.called = False

    def analyze(self, sandbox):
        self.called = True
        return {
            "rule_findings": [],
            "rule_score": self._score,
            "llm_verdict": self._verdict,
            "llm_confidence": 0.8,
            "llm_summary": "Fake behavior summary.",
            "llm_indicators": [],
            "verdict": self._verdict,
            "confidence": 0.8,
            "behavior_score": self._score,
            "summary": "Fake behavior analysis.",
        }


def make_controller(
    threat_is_phishing=False,
    llm_verdict="safe",
    llm_risk_score=10,
    sandbox_service=None,
    behavior_verdict="safe",
    behavior_score=5,
):
    fake_sandbox = sandbox_service or FakeSandboxService()
    fake_behavior = FakeBehaviorAnalyzer(
        verdict=behavior_verdict,
        behavior_score=behavior_score,
    )

    return JarvisController(
        threat_service=FakeThreatService(is_phishing=threat_is_phishing),
        llm_service=FakeLLMService(
            verdict=llm_verdict,
            risk_score=llm_risk_score,
        ),
        safety_validator=FakeAISafetyValidator(),
        output_sanitizer=FakeAIOutputSanitizer(),
        sandbox_service=fake_sandbox,
        behavior_analyzer=fake_behavior,
    ), fake_sandbox, fake_behavior


# ============================================================
# TESTS
# ============================================================


class TestJarvisControllerValidation:

    def test_empty_url_raises_value_error(self):
        controller, _, _ = make_controller()
        with pytest.raises(ValueError, match="Please enter a URL"):
            controller.analyze("")

    def test_blank_url_raises_value_error(self):
        controller, _, _ = make_controller()
        with pytest.raises(ValueError, match="Please enter a URL"):
            controller.analyze("   ")

    def test_invalid_url_raises_value_error(self):
        controller, _, _ = make_controller()
        with pytest.raises(ValueError, match="Invalid URL format"):
            controller.analyze("not a url")

    def test_valid_url_does_not_raise(self):
        controller, _, _ = make_controller()
        result = controller.analyze(
            "https://example.com",
            run_sandbox=False,
        )
        assert result is not None


class TestJarvisControllerFastPath:
    """When pre-scan risk score < SANDBOX_THRESHOLD, sandbox must NOT run."""

    def test_sandbox_not_triggered_on_low_risk(self):
        """LLM risk_score=10 < threshold — sandbox should be skipped."""
        controller, fake_sandbox, fake_behavior = make_controller(
            llm_risk_score=10,
        )

        result = controller.analyze("https://example.com")

        assert fake_sandbox.called_with is None
        assert fake_behavior.called is False
        assert result["jarvis"]["sandbox_triggered"] is False

    def test_fast_path_result_has_compat_fields(self):
        controller, _, _ = make_controller(llm_risk_score=5)
        result = controller.analyze("https://example.com")

        required = {
            "url",
            "verdict",
            "risk_score",
            "safety_score",
            "confidence",
            "checks",
            "evidence",
            "threat_intelligence",
            "analysis",
            "jarvis",
        }
        assert required.issubset(result.keys())


class TestJarvisControllerSandboxPath:
    """When pre-scan risk score >= SANDBOX_THRESHOLD, sandbox must run."""

    def test_sandbox_triggered_on_high_risk(self):
        """LLM risk_score=SANDBOX_THRESHOLD → sandbox must run."""
        controller, fake_sandbox, fake_behavior = make_controller(
            llm_risk_score=SANDBOX_THRESHOLD,
        )

        result = controller.analyze("https://suspicious.example.com")

        assert fake_sandbox.called_with is not None
        assert fake_behavior.called is True
        assert result["jarvis"]["sandbox_triggered"] is True

    def test_sandbox_url_matches_normalized_input(self):
        controller, fake_sandbox, _ = make_controller(
            llm_risk_score=SANDBOX_THRESHOLD,
        )

        # URL without protocol — should be normalized to https://
        controller.analyze("evil.com")

        assert fake_sandbox.called_with is not None
        assert fake_sandbox.called_with.startswith("https://")

    def test_run_sandbox_false_skips_sandbox_even_at_high_risk(self):
        """Explicit run_sandbox=False must override threshold routing."""
        controller, fake_sandbox, fake_behavior = make_controller(
            llm_risk_score=100,
        )

        result = controller.analyze(
            "https://example.com",
            run_sandbox=False,
        )

        assert fake_sandbox.called_with is None
        assert fake_behavior.called is False
        assert result["jarvis"]["sandbox_triggered"] is False


class TestJarvisControllerVerdicts:

    def test_threat_intelligence_listed_raises_verdict(self):
        """URLhaus listing must force a high-risk verdict (via real safety validator)."""
        from app.services.ai_safety_validator import AISafetyValidator

        # Use the real safety validator so the listed=True guardrail fires
        controller = JarvisController(
            threat_service=FakeThreatService(is_phishing=True),
            llm_service=FakeLLMService(verdict="safe", risk_score=5),
            safety_validator=AISafetyValidator(),  # real validator
            output_sanitizer=FakeAIOutputSanitizer(),
            sandbox_service=FakeSandboxService(),
            behavior_analyzer=FakeBehaviorAnalyzer(),
        )

        result = controller.analyze(
            "https://example.com",
            run_sandbox=False,
        )

        # Real AISafetyValidator maps listed=True → verdict="phishing", risk_score>=90
        # JarvisController normalize_verdict maps "phishing" → stays as normalized string
        assert result["verdict"] in ("malicious", "phishing", "suspicious")
        assert result["risk_score"] >= 70


    def test_behavior_malicious_overrides_pre_scan_safe(self):
        """Behavior verdict of malicious must override pre-scan safe."""
        controller, _, _ = make_controller(
            llm_verdict="safe",
            llm_risk_score=SANDBOX_THRESHOLD,
            behavior_verdict="malicious",
            behavior_score=75,
        )

        result = controller.analyze("https://evil.com")

        assert result["jarvis"]["sandbox_triggered"] is True
        assert result["jarvis"]["behavior"]["verdict"] == "malicious"
        # Final verdict should reflect the behavior verdict
        assert result["verdict"] in ("malicious", "suspicious")


class TestJarvisControllerForensicReport:

    def test_forensic_report_present(self):
        controller, _, _ = make_controller(llm_risk_score=5)
        result = controller.analyze(
            "https://example.com",
            run_sandbox=False,
        )

        forensic = result["jarvis"]["forensic_report"]
        assert "session_id" in forensic
        assert "narrative" in forensic
        assert "final_verdict" in forensic

    def test_forensic_narrative_mentions_url(self):
        controller, _, _ = make_controller(llm_risk_score=5)
        result = controller.analyze(
            "https://example.com",
            run_sandbox=False,
        )

        narrative = result["jarvis"]["forensic_report"]["narrative"]
        assert "example.com" in narrative

    def test_forensic_timeline_has_pre_scan_event(self):
        controller, _, _ = make_controller(llm_risk_score=5)
        result = controller.analyze(
            "https://example.com",
            run_sandbox=False,
        )

        timeline = result["jarvis"]["forensic_report"]["timeline"]
        kinds = [ev.get("kind") for ev in timeline]
        assert "pre_scan_complete" in kinds


class TestJarvisControllerSandboxFailure:
    """If sandbox raises an exception, analysis must still complete."""

    def test_sandbox_failure_is_non_fatal(self):

        class FailingSandboxService:
            def run(self, url):
                raise RuntimeError("Playwright crashed")

        controller, _, _ = make_controller(llm_risk_score=SANDBOX_THRESHOLD)
        controller.sandbox_service = FailingSandboxService()

        # Should not raise — must return a result
        result = controller.analyze("https://example.com")
        assert result is not None
        assert "jarvis" in result

    def test_sandbox_error_sandbox_still_in_response(self):

        class FailingSandboxService:
            def run(self, url):
                raise RuntimeError("Network error")

        controller, _, _ = make_controller(llm_risk_score=SANDBOX_THRESHOLD)
        controller.sandbox_service = FailingSandboxService()

        result = controller.analyze("https://example.com")

        # sandbox triggered flag reflects an attempt was made
        assert result["jarvis"]["sandbox_triggered"] is True


class TestJarvisControllerBackwardCompatibility:
    """Verify all original AIAnalysisService fields are present."""

    def test_all_original_fields_present(self):
        controller, _, _ = make_controller()
        result = controller.analyze(
            "https://example.com",
            run_sandbox=False,
        )

        original_fields = {
            "url",
            "safety_score",
            "risk_score",
            "verdict",
            "confidence",
            "summary",
            "recommendation",
            "indicators",
            "validation",
            "checks",
            "analysis",
            "evidence",
            "threat_intelligence",
        }

        for field in original_fields:
            assert field in result, f"Missing backward-compat field: {field}"

    def test_analysis_sub_object_has_original_fields(self):
        controller, _, _ = make_controller()
        result = controller.analyze(
            "https://example.com",
            run_sandbox=False,
        )

        analysis = result["analysis"]
        for field in (
            "verdict",
            "risk_score",
            "safety_score",
            "confidence",
            "summary",
            "recommendation",
            "indicators",
            "validation",
        ):
            assert field in analysis, f"Missing analysis.{field}"
