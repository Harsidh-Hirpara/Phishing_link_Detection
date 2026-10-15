"""
Tests for BehaviorRuleEngine and BehaviorAnalyzer.

All deterministic rule tests run without any LLM.
LLM integration is mocked via monkeypatch.
"""

import pytest

from app.services.behavior_analyzer import (
    BehaviorAnalyzer,
    BehaviorFinding,
    BehaviorLLMReasoner,
    BehaviorRuleEngine,
)


# ============================================================
# HELPERS
# ============================================================


def make_sandbox(
    network_events=None,
    browser_events=None,
    page_events=None,
    url="https://example.com",
    page_title=None,
    redirect_count=0,
    terminated_early=False,
    termination_reason=None,
    cumulative_threat_score=0,
):
    return {
        "url": url,
        "page_title": page_title,
        "redirect_count": redirect_count,
        "terminated_early": terminated_early,
        "termination_reason": termination_reason,
        "cumulative_threat_score": cumulative_threat_score,
        "network_events": network_events or [],
        "browser_events": browser_events or [],
        "page_events": page_events or [],
        "threat_events": [],
        "screenshot_b64": None,
    }


def make_event(kind, data=None, threat_weight=0):
    from datetime import datetime, timezone
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "data": data or {},
        "threat_weight": threat_weight,
    }


# ============================================================
# RULE ENGINE TESTS
# ============================================================


class TestBehaviorRuleEngine:

    def setup_method(self):
        self.engine = BehaviorRuleEngine()

    # ----------------------------------------------------------
    # Password field

    def test_no_findings_on_clean_sandbox(self):
        sandbox = make_sandbox()
        findings = self.engine.evaluate(sandbox)
        assert findings == []

    def test_password_field_triggers(self):
        page_events = [make_event("password_field_detected", {"count": 1})]
        sandbox = make_sandbox(page_events=page_events)
        findings = self.engine.evaluate(sandbox)

        assert any(f.rule_id == "RULE_PW_FIELD" for f in findings)

    def test_password_field_severity_is_high(self):
        page_events = [make_event("password_field_detected", {"count": 2})]
        sandbox = make_sandbox(page_events=page_events)
        findings = self.engine.evaluate(sandbox)

        pw = next(f for f in findings if f.rule_id == "RULE_PW_FIELD")
        assert pw.severity == "high"
        assert pw.score_contribution == 40

    # ----------------------------------------------------------
    # Cross-origin form

    def test_cross_origin_form_triggers(self):
        page_events = [
            make_event(
                "cross_origin_form_detected",
                {
                    "action": "https://evil.com/steal",
                    "original_host": "bank.com",
                    "form_host": "evil.com",
                },
            )
        ]
        sandbox = make_sandbox(page_events=page_events)
        findings = self.engine.evaluate(sandbox)

        assert any(f.rule_id == "RULE_XORIGIN_FORM" for f in findings)

    def test_cross_origin_form_score(self):
        page_events = [
            make_event("cross_origin_form_detected", {"form_host": "evil.com"})
        ]
        sandbox = make_sandbox(page_events=page_events)
        findings = self.engine.evaluate(sandbox)

        f = next(x for x in findings if x.rule_id == "RULE_XORIGIN_FORM")
        assert f.score_contribution == 45

    # ----------------------------------------------------------
    # Hidden iframe

    def test_hidden_iframe_triggers(self):
        page_events = [
            make_event("hidden_iframe_detected", {"srcs": ["https://c2.evil.com"]})
        ]
        sandbox = make_sandbox(page_events=page_events)
        findings = self.engine.evaluate(sandbox)

        assert any(f.rule_id == "RULE_HIDDEN_IFRAME" for f in findings)

    # ----------------------------------------------------------
    # Obfuscated script

    def test_obfuscated_script_triggers(self):
        page_events = [
            make_event("obfuscated_script_detected", {"patterns": ["eval(", "atob("]})
        ]
        sandbox = make_sandbox(page_events=page_events)
        findings = self.engine.evaluate(sandbox)

        assert any(f.rule_id == "RULE_OBFUSC_SCRIPT" for f in findings)

    def test_obfuscated_script_severity_medium(self):
        page_events = [
            make_event("obfuscated_script_detected", {"patterns": ["eval("]})
        ]
        sandbox = make_sandbox(page_events=page_events)
        findings = self.engine.evaluate(sandbox)

        f = next(x for x in findings if x.rule_id == "RULE_OBFUSC_SCRIPT")
        assert f.severity == "medium"

    # ----------------------------------------------------------
    # Download attempt

    def test_download_attempt_triggers(self):
        network_events = [
            make_event("download_attempt", {"url": "https://evil.com/malware.exe"})
        ]
        sandbox = make_sandbox(network_events=network_events)
        findings = self.engine.evaluate(sandbox)

        assert any(f.rule_id == "RULE_DOWNLOAD" for f in findings)

    def test_blocked_download_also_triggers(self):
        network_events = [
            make_event("blocked_download", {"url": "https://evil.com/virus.zip"})
        ]
        sandbox = make_sandbox(network_events=network_events)
        findings = self.engine.evaluate(sandbox)

        assert any(f.rule_id == "RULE_DOWNLOAD" for f in findings)

    def test_download_severity_critical(self):
        network_events = [make_event("download_attempt", {})]
        sandbox = make_sandbox(network_events=network_events)
        findings = self.engine.evaluate(sandbox)

        f = next(x for x in findings if x.rule_id == "RULE_DOWNLOAD")
        assert f.severity == "critical"
        assert f.score_contribution == 60

    # ----------------------------------------------------------
    # Redirect chain

    def test_redirect_chain_not_triggered_below_3(self):
        network_events = [
            make_event("redirect", {"hop": 1}),
            make_event("redirect", {"hop": 2}),
        ]
        sandbox = make_sandbox(network_events=network_events)
        findings = self.engine.evaluate(sandbox)

        assert not any(f.rule_id == "RULE_REDIRECT_CHAIN" for f in findings)

    def test_redirect_chain_triggers_at_3(self):
        network_events = [make_event("redirect", {"hop": i}) for i in range(1, 4)]
        sandbox = make_sandbox(network_events=network_events)
        findings = self.engine.evaluate(sandbox)

        assert any(f.rule_id == "RULE_REDIRECT_CHAIN" for f in findings)

    def test_redirect_limit_reached_severity_critical(self):
        network_events = [
            make_event("redirect", {"hop": i}) for i in range(1, 7)
        ] + [make_event("redirect_limit_reached", {"count": 6, "limit": 5})]
        sandbox = make_sandbox(network_events=network_events)
        findings = self.engine.evaluate(sandbox)

        f = next(x for x in findings if x.rule_id == "RULE_REDIRECT_CHAIN")
        assert f.severity == "critical"

    # ----------------------------------------------------------
    # Popup storm

    def test_popup_storm_not_triggered_below_2(self):
        browser_events = [make_event("popup_opened", {})]
        sandbox = make_sandbox(browser_events=browser_events)
        findings = self.engine.evaluate(sandbox)

        assert not any(f.rule_id == "RULE_POPUP_STORM" for f in findings)

    def test_popup_storm_triggers_at_2(self):
        browser_events = [
            make_event("popup_opened", {}),
            make_event("popup_opened", {}),
        ]
        sandbox = make_sandbox(browser_events=browser_events)
        findings = self.engine.evaluate(sandbox)

        assert any(f.rule_id == "RULE_POPUP_STORM" for f in findings)

    # ----------------------------------------------------------
    # Session terminated early

    def test_early_termination_rule_triggers(self):
        sandbox = make_sandbox(
            terminated_early=True,
            termination_reason="Score exceeded threshold.",
        )
        findings = self.engine.evaluate(sandbox)

        assert any(f.rule_id == "RULE_EARLY_TERM" for f in findings)

    def test_early_termination_not_triggered_when_false(self):
        sandbox = make_sandbox(terminated_early=False)
        findings = self.engine.evaluate(sandbox)

        assert not any(f.rule_id == "RULE_EARLY_TERM" for f in findings)

    # ----------------------------------------------------------
    # Multiple rules at once

    def test_multiple_rules_all_trigger(self):
        sandbox = make_sandbox(
            page_events=[
                make_event("password_field_detected", {"count": 1}),
                make_event("cross_origin_form_detected", {"form_host": "evil.com"}),
                make_event("hidden_iframe_detected", {"srcs": []}),
            ],
            network_events=[
                make_event("download_attempt", {}),
            ],
        )
        findings = self.engine.evaluate(sandbox)
        rule_ids = {f.rule_id for f in findings}

        assert "RULE_PW_FIELD" in rule_ids
        assert "RULE_XORIGIN_FORM" in rule_ids
        assert "RULE_HIDDEN_IFRAME" in rule_ids
        assert "RULE_DOWNLOAD" in rule_ids


# ============================================================
# LLM REASONER TESTS (mocked)
# ============================================================


class TestBehaviorLLMReasoner:

    def test_no_findings_returns_safe(self):
        reasoner = BehaviorLLMReasoner()
        result = reasoner.reason([], {})

        assert result["verdict"] == "safe"
        assert "llm_summary" in result

    def test_fallback_with_critical_finding(self):
        """When LLM is unavailable, fallback derives verdict from rules."""
        reasoner = BehaviorLLMReasoner()

        critical_finding = BehaviorFinding(
            rule_id="RULE_DOWNLOAD",
            name="Drive-by Download",
            severity="critical",
            description="Download detected.",
            score_contribution=60,
        )

        result = reasoner._fallback_response([critical_finding])
        assert result["verdict"] == "malicious"

    def test_fallback_with_high_finding(self):
        reasoner = BehaviorLLMReasoner()

        high_finding = BehaviorFinding(
            rule_id="RULE_PW_FIELD",
            name="Password Field",
            severity="high",
            description="Password input detected.",
            score_contribution=40,
        )

        result = reasoner._fallback_response([high_finding])
        assert result["verdict"] in ("suspicious", "malicious")

    def test_fallback_with_no_findings(self):
        reasoner = BehaviorLLMReasoner()
        result = reasoner._fallback_response([])
        assert result["verdict"] == "safe"

    def test_validate_normalizes_invalid_verdict(self):
        reasoner = BehaviorLLMReasoner()
        result = reasoner._validate({"verdict": "garbage", "confidence": 0.5})
        assert result["verdict"] == "suspicious"

    def test_validate_clamps_confidence(self):
        reasoner = BehaviorLLMReasoner()
        result = reasoner._validate({"verdict": "safe", "confidence": 1.5})
        assert result["confidence"] <= 1.0


# ============================================================
# BEHAVIOR ANALYZER TESTS (LLM mocked)
# ============================================================


class TestBehaviorAnalyzer:

    def _make_analyzer_with_mock_llm(self, llm_verdict="suspicious"):
        """Create a BehaviorAnalyzer with a mocked LLM that always returns the given verdict."""

        class MockLLM:
            def reason(self, findings, meta):
                return {
                    "verdict": llm_verdict,
                    "confidence": 0.8,
                    "llm_summary": "Mocked LLM summary.",
                    "llm_indicators": [],
                }

        return BehaviorAnalyzer(
            rule_engine=BehaviorRuleEngine(),
            llm_reasoner=MockLLM(),
        )

    def test_analyze_clean_sandbox_returns_safe(self):
        analyzer = self._make_analyzer_with_mock_llm(llm_verdict="safe")
        sandbox = make_sandbox()
        result = analyzer.analyze(sandbox)

        assert result["verdict"] == "safe"
        assert result["rule_findings"] == []

    def test_analyze_with_critical_finding_returns_malicious(self):
        analyzer = self._make_analyzer_with_mock_llm(llm_verdict="safe")

        # Even if LLM says "safe", a critical rule must produce malicious
        sandbox = make_sandbox(
            network_events=[make_event("download_attempt", {})]
        )
        result = analyzer.analyze(sandbox)

        assert result["verdict"] == "malicious"

    def test_llm_can_raise_verdict(self):
        """LLM verdict of malicious raises a safe rule verdict."""
        analyzer = self._make_analyzer_with_mock_llm(llm_verdict="malicious")
        sandbox = make_sandbox()  # No rule findings
        result = analyzer.analyze(sandbox)

        assert result["verdict"] == "malicious"

    def test_llm_cannot_lower_verdict(self):
        """LLM verdict of safe does NOT lower a rules-derived malicious verdict."""
        analyzer = self._make_analyzer_with_mock_llm(llm_verdict="safe")
        sandbox = make_sandbox(
            network_events=[make_event("download_attempt", {})]
        )
        result = analyzer.analyze(sandbox)

        # Rule says malicious (critical), LLM says safe — malicious wins
        assert result["verdict"] == "malicious"

    def test_result_contains_required_keys(self):
        analyzer = self._make_analyzer_with_mock_llm()
        sandbox = make_sandbox()
        result = analyzer.analyze(sandbox)

        required = {
            "rule_findings",
            "rule_score",
            "llm_verdict",
            "llm_confidence",
            "llm_summary",
            "verdict",
            "confidence",
            "behavior_score",
            "summary",
        }
        assert required.issubset(result.keys())

    def test_behavior_score_is_bounded(self):
        analyzer = self._make_analyzer_with_mock_llm()
        sandbox = make_sandbox(
            page_events=[
                make_event("password_field_detected", {"count": 3}),
                make_event("cross_origin_form_detected", {"form_host": "evil.com"}),
                make_event("hidden_iframe_detected", {"srcs": []}),
            ],
            network_events=[make_event("download_attempt", {})],
        )
        result = analyzer.analyze(sandbox)

        assert 0 <= result["behavior_score"] <= 100
