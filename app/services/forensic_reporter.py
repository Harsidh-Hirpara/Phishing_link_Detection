"""
Forensic report builder.

Assembles the complete JARVIS analysis into a structured,
human-readable forensic report.  The report captures:

- Session identity and timing
- Pre-scan findings (URLhaus, Heuristics, Qwen)
- Whether the sandbox was triggered
- Sandbox session metadata and event timeline
- Behavioral analysis findings (rules + LLM)
- Final verdict and confidence
- Recommended user action
"""

import uuid
from datetime import datetime, timezone
from typing import Optional


class ForensicReporter:
    """
    Builds a forensic report from JARVIS pipeline outputs.
    """

    def build(
        self,
        url: str,
        pre_scan: dict,
        sandbox: Optional[dict],
        behavior: Optional[dict],
    ) -> dict:
        """
        Parameters
        ----------
        url:
            The analyzed URL (normalized).
        pre_scan:
            Output from the pre-scan phase
            (URLhaus + Heuristics + Qwen).
        sandbox:
            Output from SandboxService.run(), or None if
            the risk score was below the sandbox threshold.
        behavior:
            Output from BehaviorAnalyzer.analyze(), or None
            if the sandbox was not triggered.

        Returns
        -------
        dict
            The full forensic report.
        """

        session_id = str(uuid.uuid4())
        generated_at = datetime.now(timezone.utc).isoformat()

        # ====================================================
        # FINAL VERDICT
        # ====================================================

        final_verdict, final_confidence, final_score = (
            self._compute_final(pre_scan, behavior)
        )

        # ====================================================
        # TIMELINE
        # ====================================================

        timeline = self._build_timeline(
            pre_scan,
            sandbox,
            behavior,
        )

        # ====================================================
        # SANDBOX SUMMARY
        # ====================================================

        sandbox_summary = self._summarize_sandbox(sandbox)

        # ====================================================
        # BEHAVIOR SUMMARY
        # ====================================================

        behavior_summary = self._summarize_behavior(behavior)

        # ====================================================
        # NARRATIVE REPORT TEXT
        # ====================================================

        narrative = self._build_narrative(
            url,
            pre_scan,
            sandbox,
            behavior,
            final_verdict,
            final_score,
        )

        # ====================================================
        # ASSEMBLE
        # ====================================================

        return {
            # ------------------------------------------------
            # Identity
            # ------------------------------------------------
            "session_id": session_id,
            "generated_at": generated_at,
            "url": url,

            # ------------------------------------------------
            # Final verdict
            # ------------------------------------------------
            "final_verdict": final_verdict,
            "final_confidence": final_confidence,
            "final_risk_score": final_score,

            # ------------------------------------------------
            # Pre-scan
            # ------------------------------------------------
            "pre_scan": {
                "verdict": pre_scan.get("verdict", "unknown"),
                "risk_score": pre_scan.get("risk_score", 0),
                "confidence": pre_scan.get("confidence", 0.0),
                "threat_intelligence": pre_scan.get(
                    "threat_intelligence", {}
                ),
                "indicators": pre_scan.get("indicators", []),
                "summary": pre_scan.get("summary", ""),
            },

            # ------------------------------------------------
            # Sandbox
            # ------------------------------------------------
            "sandbox_triggered": sandbox is not None,
            "sandbox": sandbox_summary,

            # ------------------------------------------------
            # Behavior
            # ------------------------------------------------
            "behavior_analyzed": behavior is not None,
            "behavior": behavior_summary,

            # ------------------------------------------------
            # Full event timeline
            # ------------------------------------------------
            "timeline": timeline,

            # ------------------------------------------------
            # Narrative
            # ------------------------------------------------
            "narrative": narrative,

            # ------------------------------------------------
            # Recommendation
            # ------------------------------------------------
            "recommendation": self._build_recommendation(
                final_verdict,
                final_score,
            ),
        }

    # =========================================================
    # VERDICT COMPUTATION
    # =========================================================

    def _compute_final(
        self,
        pre_scan: dict,
        behavior: Optional[dict],
    ) -> tuple[str, float, int]:
        """
        Compute final verdict, confidence, and risk score.

        Rules:
        - If behavior is available, it takes priority over pre-scan.
        - The final risk score is the maximum of both stages.
        - Verdict uses the more severe of the two.
        """

        pre_verdict = pre_scan.get("verdict", "suspicious")
        pre_score = int(pre_scan.get("risk_score", 0))
        pre_conf = float(pre_scan.get("confidence", 0.5))

        if behavior is None:
            # No sandbox — use pre-scan result only
            return pre_verdict, pre_conf, pre_score

        beh_verdict = behavior.get("verdict", "suspicious")
        beh_score = int(behavior.get("behavior_score", 0))
        beh_conf = float(behavior.get("confidence", 0.5))

        # Final score preserves the highest risk from either stage.
        final_score = max(pre_score, beh_score)
        final_score = max(0, min(100, final_score))

        # Final verdict = most severe
        rank = {
            "safe": 0,
            "suspicious": 1,
            "phishing": 2,
            "malicious": 2,
        }

        pre_rank = rank.get(pre_verdict, 1)
        beh_rank = rank.get(beh_verdict, 1)
        final_rank = max(pre_rank, beh_rank)

        verdict_map = {
            0: "safe",
            1: "suspicious",
            2: "malicious",
        }
        final_verdict = verdict_map[final_rank]

        # Normalize to the three UI verdicts
        if final_verdict == "phishing":
            final_verdict = "malicious"

        # Confidence = average weighted toward behavior
        final_conf = round(
            pre_conf * 0.35 + beh_conf * 0.65,
            3,
        )

        return final_verdict, final_conf, final_score

    # =========================================================
    # SANDBOX SUMMARY
    # =========================================================

    def _summarize_sandbox(
        self,
        sandbox: Optional[dict],
    ) -> Optional[dict]:

        if sandbox is None:
            return None

        return {
            "started_at": sandbox.get("started_at"),
            "ended_at": sandbox.get("ended_at"),
            "page_title": sandbox.get("page_title"),
            "redirect_count": sandbox.get("redirect_count", 0),
            "terminated_early": sandbox.get("terminated_early", False),
            "termination_reason": sandbox.get("termination_reason"),
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
            "threat_events": sandbox.get("threat_events", []),
            "screenshot_b64": sandbox.get("screenshot_b64"),
        }

    # =========================================================
    # BEHAVIOR SUMMARY
    # =========================================================

    def _summarize_behavior(
        self,
        behavior: Optional[dict],
    ) -> Optional[dict]:

        if behavior is None:
            return None

        return {
            "verdict": behavior.get("verdict", "unknown"),
            "confidence": behavior.get("confidence", 0.0),
            "behavior_score": behavior.get("behavior_score", 0),
            "summary": behavior.get("summary", ""),
            "rule_findings": behavior.get("rule_findings", []),
            "rule_score": behavior.get("rule_score", 0),
            "llm_verdict": behavior.get("llm_verdict", "unknown"),
            "llm_confidence": behavior.get("llm_confidence", 0.0),
            "llm_summary": behavior.get("llm_summary", ""),
            "llm_indicators": behavior.get("llm_indicators", []),
        }

    # =========================================================
    # TIMELINE
    # =========================================================

    def _build_timeline(
        self,
        pre_scan: dict,
        sandbox: Optional[dict],
        behavior: Optional[dict],
    ) -> list[dict]:
        """
        Build a merged, chronological event timeline from all phases.
        """

        events: list[dict] = []

        # Pre-scan events (synthesized — no real timestamps)
        events.append({
            "phase": "pre_scan",
            "kind": "pre_scan_complete",
            "data": {
                "verdict": pre_scan.get("verdict"),
                "risk_score": pre_scan.get("risk_score"),
                "threat_intelligence_listed": (
                    pre_scan.get("threat_intelligence", {}).get(
                        "listed", False
                    )
                ),
            },
        })

        if sandbox is None:
            events.append({
                "phase": "routing",
                "kind": "sandbox_skipped",
                "data": {
                    "reason": (
                        "Pre-scan risk score was below the "
                        "sandbox trigger threshold."
                    )
                },
            })
            return events

        # Sandbox network events
        for ev in sandbox.get("network_events", []):
            events.append({
                "phase": "sandbox",
                "timestamp": ev.get("timestamp"),
                "kind": ev.get("kind"),
                "data": ev.get("data", {}),
                "threat_weight": ev.get("threat_weight", 0),
            })

        # Sandbox browser events
        for ev in sandbox.get("browser_events", []):
            events.append({
                "phase": "sandbox",
                "timestamp": ev.get("timestamp"),
                "kind": ev.get("kind"),
                "data": ev.get("data", {}),
                "threat_weight": ev.get("threat_weight", 0),
            })

        # Sandbox page events
        for ev in sandbox.get("page_events", []):
            events.append({
                "phase": "sandbox",
                "timestamp": ev.get("timestamp"),
                "kind": ev.get("kind"),
                "data": ev.get("data", {}),
                "threat_weight": ev.get("threat_weight", 0),
            })

        # Behavior analysis summary
        if behavior:
            events.append({
                "phase": "behavior_analysis",
                "kind": "behavior_analysis_complete",
                "data": {
                    "verdict": behavior.get("verdict"),
                    "rule_findings_count": len(
                        behavior.get("rule_findings", [])
                    ),
                    "behavior_score": behavior.get(
                        "behavior_score", 0
                    ),
                },
            })

        # Sort by timestamp where available
        events.sort(
            key=lambda e: e.get("timestamp", ""),
        )

        return events

    # =========================================================
    # NARRATIVE
    # =========================================================

    def _build_narrative(
        self,
        url: str,
        pre_scan: dict,
        sandbox: Optional[dict],
        behavior: Optional[dict],
        final_verdict: str,
        final_score: int,
    ) -> str:

        lines = [
            f"JARVIS Forensic Report",
            f"URL: {url}",
            f"Final Verdict: {final_verdict.upper()}",
            f"Final Risk Score: {final_score}/100",
            "",
            "--- PRE-SCAN ---",
            f"Verdict: {pre_scan.get('verdict', 'unknown')}",
            f"Risk Score: {pre_scan.get('risk_score', 0)}/100",
        ]

        threat = pre_scan.get("threat_intelligence", {})

        if threat.get("listed"):
            lines.append(
                "Threat Intelligence: LISTED as malicious "
                f"by {threat.get('source', 'unknown')}."
            )
        elif threat.get("checked"):
            lines.append(
                "Threat Intelligence: No known listing found."
            )

        if pre_scan.get("summary"):
            lines.append(
                f"Pre-scan summary: {pre_scan['summary']}"
            )

        if sandbox is None:
            lines += [
                "",
                "--- SANDBOX ---",
                "Sandbox was NOT triggered (risk score below threshold).",
            ]
        else:
            lines += [
                "",
                "--- SANDBOX ---",
                (
                    f"Sandbox attempted navigation in an isolated "
                    f"headless browser context."
                ),
                f"Redirects: {sandbox.get('redirect_count', 0)}",
                f"Terminated early: {sandbox.get('terminated_early', False)}",
                f"Page title: {sandbox.get('page_title') or 'N/A'}",
                f"Cumulative threat score: "
                f"{sandbox.get('cumulative_threat_score', 0)}",
            ]

            if sandbox.get("terminated_early"):
                lines.append(
                    "TERMINATION REASON: "
                    f"{sandbox.get('termination_reason', '')}"
                )

        if behavior:
            findings = behavior.get("rule_findings", [])
            lines += [
                "",
                "--- BEHAVIORAL ANALYSIS ---",
                f"Rule findings: {len(findings)}",
                f"Rule score: {behavior.get('rule_score', 0)}/100",
                f"Behavior verdict: {behavior.get('verdict', 'unknown')}",
                f"Summary: {behavior.get('summary', '')}",
            ]

            for finding in findings:
                lines.append(
                    f"  [{finding['severity'].upper()}] "
                    f"{finding['name']}: {finding['description']}"
                )

        lines += [
            "",
            "--- CONCLUSION ---",
            (
                f"Based on pre-scan analysis"
                + (" and sandbox activity" if sandbox else "")
                + f", this URL is assessed as: {final_verdict.upper()}."
            ),
        ]

        return "\n".join(lines)

    # =========================================================
    # RECOMMENDATION
    # =========================================================

    def _build_recommendation(
        self,
        verdict: str,
        risk_score: int,
    ) -> str:

        if verdict == "malicious":
            return (
                "Do NOT visit this URL. It has been identified as "
                "malicious by behavioral analysis. Block this URL "
                "and report it to your security team."
            )

        if verdict == "suspicious":
            return (
                "Exercise extreme caution. Multiple risk indicators "
                "were identified. Avoid submitting any personal "
                "information on this site."
            )

        return (
            "No strong threat indicators were detected from the "
            "available evidence. However, always verify URLs "
            "before sharing sensitive information."
        )
