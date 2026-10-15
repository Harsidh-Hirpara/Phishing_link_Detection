"""
JARVIS Controller — main pipeline orchestrator.

Pipeline stages:
    1. Validate & normalize the URL
    2. Pre-scan (URLhaus + Heuristics + Qwen) — parallel where possible
    3. Route: risk score < threshold → fast result
              risk score >= threshold → browser sandbox
    4. Sandbox: visit URL in controlled Playwright browser
    5. Behavior analysis (rules + Qwen) of sandbox events
    6. Forensic report assembly

Backward-compatible surface:
    JarvisController.analyze() returns a superset of the dict
    previously returned by AIAnalysisService.analyze().
    Existing fields (verdict, risk_score, confidence, summary,
    recommendation, indicators, checks, evidence,
    threat_intelligence) are all preserved.

Sandbox isolation note:
    The controlled browser runs inside the same OS process as Flask.
    This provides application-level isolation (separate browser
    context, blocked downloads, no stored credentials, enforced
    timeouts) but NOT OS-level sandboxing.  For full isolation,
    deploy this service inside a dedicated container or VM.
"""

import logging
import os
from typing import Optional

from app.features.evidence_builder import EvidenceBuilder
from app.features.url_parser import is_valid_url, normalize_url, parse_url
from app.services.ai_output_sanitizer import AIOutputSanitizer
from app.services.ai_safety_validator import AISafetyValidator
from app.services.behavior_analyzer import BehaviorAnalyzer
from app.services.forensic_reporter import ForensicReporter
from app.services.llm_service import LLMService
from app.services.sandbox_service import SandboxService
from app.services.threat_service import ThreatService


logger = logging.getLogger(__name__)


# ============================================================
# CONFIG
# ============================================================

# Risk score threshold that triggers the browser sandbox.
SANDBOX_THRESHOLD = int(
    os.getenv("SANDBOX_THRESHOLD", "30")
)


# ============================================================
# CONTROLLER
# ============================================================

class JarvisController:
    """
    Top-level JARVIS pipeline controller.

    Designed to be a drop-in replacement for AIAnalysisService,
    with additional sandbox and behavioral analysis fields
    appended to the response.
    """

    def __init__(
        self,
        evidence_builder: Optional[EvidenceBuilder] = None,
        threat_service: Optional[ThreatService] = None,
        llm_service: Optional[LLMService] = None,
        safety_validator: Optional[AISafetyValidator] = None,
        output_sanitizer: Optional[AIOutputSanitizer] = None,
        sandbox_service: Optional[SandboxService] = None,
        behavior_analyzer: Optional[BehaviorAnalyzer] = None,
        forensic_reporter: Optional[ForensicReporter] = None,
    ) -> None:

        # --- Pre-scan components (existing pipeline) ---------

        self.evidence_builder = (
            evidence_builder or EvidenceBuilder()
        )

        self.threat_service = (
            threat_service or ThreatService()
        )

        self.llm_service = (
            llm_service or LLMService()
        )

        self.safety_validator = (
            safety_validator or AISafetyValidator()
        )

        self.output_sanitizer = (
            output_sanitizer or AIOutputSanitizer()
        )

        # --- New JARVIS components ---------------------------

        self.sandbox_service = (
            sandbox_service or SandboxService()
        )

        self.behavior_analyzer = (
            behavior_analyzer or BehaviorAnalyzer()
        )

        self.forensic_reporter = (
            forensic_reporter or ForensicReporter()
        )

    # =========================================================
    # PUBLIC API
    # =========================================================

    def analyze(
        self,
        url: str,
        check_threat_intelligence: bool = True,
        run_sandbox: bool = True,
    ) -> dict:
        """
        Run the full JARVIS pipeline.

        Parameters
        ----------
        url:
            The URL to analyze.
        check_threat_intelligence:
            If False, skip the URLhaus lookup (used in tests
            and fast-path scenarios).
        run_sandbox:
            If False, skip the browser sandbox regardless of
            the pre-scan risk score (used in tests).

        Returns
        -------
        dict
            Full JARVIS result including all backward-compatible
            fields plus sandbox, behavior, and forensic report.
        """

        # ==================================================
        # 1. VALIDATE
        # ==================================================

        if not url or not url.strip():
            raise ValueError("Please enter a URL")

        if not is_valid_url(url):
            raise ValueError("Invalid URL format")

        # ==================================================
        # 2. NORMALIZE
        # ==================================================

        normalized_url = normalize_url(url.strip())

        # ==================================================
        # 3. PRE-SCAN
        # ==================================================

        pre_scan_result = self._run_pre_scan(
            normalized_url,
            check_threat_intelligence,
        )

        pre_scan_risk_score = int(
            pre_scan_result.get("analysis", {}).get("risk_score", 0)
        )

        logger.info(
            "JARVIS pre-scan complete | "
            "url=%s | verdict=%s | risk_score=%s",
            normalized_url,
            pre_scan_result.get("analysis", {}).get("verdict"),
            pre_scan_risk_score,
        )

        # ==================================================
        # 4. ROUTE: sandbox or fast path
        # ==================================================

        sandbox_result: Optional[dict] = None
        behavior_result: Optional[dict] = None

        if run_sandbox and pre_scan_risk_score >= SANDBOX_THRESHOLD:

            logger.info(
                "JARVIS routing to sandbox | "
                "risk_score=%s >= threshold=%s",
                pre_scan_risk_score,
                SANDBOX_THRESHOLD,
            )

            # ==================================================
            # 5. SANDBOX
            # ==================================================

            try:
                sandbox_result = self.sandbox_service.run(
                    normalized_url
                )

                logger.info(
                    "JARVIS sandbox complete | "
                    "terminated_early=%s | "
                    "threat_score=%s",
                    sandbox_result.get("terminated_early"),
                    sandbox_result.get("cumulative_threat_score"),
                )

            except Exception as exc:
                logger.exception(
                    "JARVIS sandbox error: %s", exc
                )
                # Sandbox failure is non-fatal —
                # continue with pre-scan result only
                sandbox_result = self._sandbox_error_result(
                    normalized_url,
                    str(exc),
                )

            # ==================================================
            # 6. BEHAVIOR ANALYSIS
            # ==================================================

            try:
                behavior_result = self.behavior_analyzer.analyze(
                    sandbox_result
                )

                logger.info(
                    "JARVIS behavior analysis complete | "
                    "verdict=%s | behavior_score=%s",
                    behavior_result.get("verdict"),
                    behavior_result.get("behavior_score"),
                )

            except Exception as exc:
                logger.exception(
                    "JARVIS behavior analysis error: %s", exc
                )
                behavior_result = self._behavior_error_result(
                    str(exc)
                )

        else:
            logger.info(
                "JARVIS fast path | "
                "risk_score=%s < threshold=%s",
                pre_scan_risk_score,
                SANDBOX_THRESHOLD,
            )

        # ==================================================
        # 7. FORENSIC REPORT
        # ==================================================

        # Build a flat pre_scan dict for the reporter
        pre_scan_for_report = self._flatten_pre_scan(
            pre_scan_result
        )

        forensic_report = self.forensic_reporter.build(
            url=normalized_url,
            pre_scan=pre_scan_for_report,
            sandbox=sandbox_result,
            behavior=behavior_result,
        )

        # ==================================================
        # 8. ASSEMBLE FINAL RESPONSE
        # ==================================================

        return self._build_response(
            normalized_url,
            pre_scan_result,
            sandbox_result,
            behavior_result,
            forensic_report,
        )

    # =========================================================
    # PRE-SCAN
    # =========================================================

    def _run_pre_scan(
        self,
        url: str,
        check_threat_intelligence: bool,
    ) -> dict:
        """
        Run the existing static analysis pipeline:
          1. Parse URL
          2. URLhaus threat intelligence
          3. Build evidence
          4. Qwen LLM analysis
          5. Safety validation
          6. Output sanitization

        Returns the full result dict from the existing pipeline.
        """

        # ---- Parse ----------------------------------------

        parsed_url = parse_url(url)

        # ---- Threat intelligence ---------------------------

        threat_result = {
            "checked": False,
            "listed": False,
            "source": None,
            "threat": None,
            "last_analysis": None,
            "api_error": False,
        }

        if check_threat_intelligence:
            raw_threat = self.threat_service.check_url(url)
            threat_result = self._normalize_threat(raw_threat)

        # ---- Evidence -------------------------------------

        evidence = self.evidence_builder.build(
            parsed_url,
            threat_result,
        )

        # ---- LLM ------------------------------------------

        raw_ai = self.llm_service.analyze(evidence)

        # ---- Safety validation ----------------------------

        validated = self.safety_validator.validate(
            raw_ai,
            evidence,
        )

        # ---- Sanitization ---------------------------------

        final_ai = self.output_sanitizer.sanitize(
            validated,
            evidence,
        )

        return {
            "url": url,
            "analysis": final_ai,
            "evidence": evidence,
            "threat_intelligence": threat_result,
            "checks": evidence.get("checks", []),
        }

    # =========================================================
    # HELPERS
    # =========================================================

    def _normalize_threat(self, result: dict) -> dict:

        if not result:
            return {
                "checked": True,
                "listed": False,
                "source": "URLhaus",
                "threat": None,
                "last_analysis": None,
                "api_error": True,
            }

        is_phishing = bool(result.get("is_phishing", False))

        return {
            "checked": True,
            "listed": is_phishing,
            "source": "URLhaus",
            "threat": result.get("threat"),
            "last_analysis": result.get("last_analysis"),
            "api_error": bool(result.get("api_error", False)),
        }

    def _flatten_pre_scan(self, pre_scan_result: dict) -> dict:
        """
        Convert the pre-scan result dict into the flat structure
        expected by ForensicReporter.
        """

        analysis = pre_scan_result.get("analysis", {})

        return {
            "verdict": analysis.get("verdict", "suspicious"),
            "risk_score": analysis.get("risk_score", 0),
            "confidence": analysis.get("confidence", 0.0),
            "summary": analysis.get("summary", ""),
            "indicators": analysis.get("indicators", []),
            "recommendation": analysis.get("recommendation", ""),
            "threat_intelligence": pre_scan_result.get(
                "threat_intelligence", {}
            ),
        }

    def _sandbox_error_result(
        self,
        url: str,
        error: str,
    ) -> dict:
        """
        Return a minimal sandbox result when sandbox execution fails.
        """

        return {
            "url": url,
            "started_at": None,
            "ended_at": None,
            "page_title": None,
            "redirect_count": 0,
            "max_redirects": 5,
            "max_requests": 150,
            "timeout_seconds": 15,
            "terminated_early": False,
            "termination_reason": None,
            "cumulative_threat_score": 0,
            "network_events": [],
            "browser_events": [],
            "page_events": [],
            "threat_events": [],
            "screenshot_b64": None,
            "error": error,
        }

    def _behavior_error_result(self, error: str) -> dict:
        """
        Return a minimal behavior result when analysis fails.
        """

        return {
            "rule_findings": [],
            "rule_score": 0,
            "llm_verdict": "unknown",
            "llm_confidence": 0.0,
            "llm_summary": f"Behavior analysis failed: {error}",
            "llm_indicators": [],
            "verdict": "suspicious",
            "confidence": 0.3,
            "behavior_score": 0,
            "summary": f"Behavior analysis could not complete: {error}",
        }

    # =========================================================
    # RESPONSE ASSEMBLY
    # =========================================================

    def _build_response(
        self,
        url: str,
        pre_scan: dict,
        sandbox: Optional[dict],
        behavior: Optional[dict],
        forensic_report: dict,
    ) -> dict:
        """
        Build the final API response dict.

        All original fields are preserved for backward compatibility.
        New JARVIS fields are added without removing any existing ones.
        """

        analysis = pre_scan.get("analysis", {})
        evidence = pre_scan.get("evidence", {})
        threat_intelligence = pre_scan.get("threat_intelligence", {})

        # Final verdict: use forensic report if sandbox was run
        final_verdict = forensic_report.get(
            "final_verdict",
            analysis.get("verdict", "suspicious"),
        )

        final_risk_score = forensic_report.get(
            "final_risk_score",
            analysis.get("risk_score", 0),
        )

        final_confidence = forensic_report.get(
            "final_confidence",
            analysis.get("confidence", 0.0),
        )

        return {
            # ------------------------------------------------
            # BACKWARD-COMPATIBLE FIELDS
            # These match exactly what AIAnalysisService returned.
            # ------------------------------------------------

            "url": url,

            # Frontend uses safety_score
            "safety_score": final_risk_score,
            "risk_score": final_risk_score,

            "verdict": final_verdict,
            "confidence": final_confidence,

            "summary": analysis.get("summary", ""),
            "recommendation": forensic_report.get(
                "recommendation",
                analysis.get("recommendation", ""),
            ),
            "indicators": analysis.get("indicators", []),
            "validation": analysis.get("validation", {}),

            "checks": pre_scan.get("checks", []),

            "analysis": {
                "verdict": final_verdict,
                "risk_score": final_risk_score,
                "safety_score": final_risk_score,
                "confidence": final_confidence,
                "summary": analysis.get("summary", ""),
                "recommendation": forensic_report.get(
                    "recommendation",
                    analysis.get("recommendation", ""),
                ),
                "indicators": analysis.get("indicators", []),
                "validation": analysis.get("validation", {}),
            },

            "evidence": evidence,
            "threat_intelligence": threat_intelligence,

            # ------------------------------------------------
            # NEW JARVIS FIELDS
            # ------------------------------------------------

            "jarvis": {
                # Pipeline routing
                "sandbox_triggered": sandbox is not None,
                "sandbox_threshold": SANDBOX_THRESHOLD,
                "pre_scan_risk_score": int(
                    analysis.get("risk_score", 0)
                ),

                # Pre-scan
                "pre_scan": {
                    "verdict": analysis.get("verdict"),
                    "risk_score": analysis.get("risk_score", 0),
                    "confidence": analysis.get("confidence", 0.0),
                    "summary": analysis.get("summary", ""),
                },

                # Sandbox
                "sandbox": (
                    {
                        "started_at": sandbox.get("started_at"),
                        "ended_at": sandbox.get("ended_at"),
                        "page_title": sandbox.get("page_title"),
                        "redirect_count": sandbox.get(
                            "redirect_count", 0
                        ),
                        "terminated_early": sandbox.get(
                            "terminated_early", False
                        ),
                        "termination_reason": sandbox.get(
                            "termination_reason"
                        ),
                        "cumulative_threat_score": sandbox.get(
                            "cumulative_threat_score", 0
                        ),
                        "total_network_events": len(
                            sandbox.get("network_events", [])
                        ),
                        "total_browser_events": len(
                            sandbox.get("browser_events", [])
                        ),
                        "total_page_events": len(
                            sandbox.get("page_events", [])
                        ),
                        "threat_events": sandbox.get(
                            "threat_events", []
                        ),
                        "screenshot_b64": sandbox.get(
                            "screenshot_b64"
                        ),
                    }
                    if sandbox
                    else None
                ),

                # Behavior analysis
                "behavior": (
                    {
                        "verdict": behavior.get("verdict"),
                        "confidence": behavior.get("confidence", 0.0),
                        "behavior_score": behavior.get(
                            "behavior_score", 0
                        ),
                        "summary": behavior.get("summary", ""),
                        "rule_findings": behavior.get(
                            "rule_findings", []
                        ),
                        "rule_score": behavior.get("rule_score", 0),
                        "llm_verdict": behavior.get("llm_verdict"),
                        "llm_summary": behavior.get("llm_summary"),
                    }
                    if behavior
                    else None
                ),

                # Forensic report
                "forensic_report": {
                    "session_id": forensic_report.get("session_id"),
                    "generated_at": forensic_report.get("generated_at"),
                    "final_verdict": forensic_report.get("final_verdict"),
                    "final_risk_score": forensic_report.get(
                        "final_risk_score"
                    ),
                    "narrative": forensic_report.get("narrative"),
                    "timeline": forensic_report.get("timeline", []),
                    "recommendation": forensic_report.get(
                        "recommendation"
                    ),
                },
            },
        }
