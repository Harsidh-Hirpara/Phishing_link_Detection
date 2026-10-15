"""
Behavior analyzer for sandbox event output.

Architecture: two-layer analysis kept strictly separate.

Layer 1 — Deterministic rules
    Pure Python logic applied to the sandbox event log.
    Each rule is independently testable and produces a
    typed finding with a fixed severity weight.
    Rules never call the LLM.

Layer 2 — Qwen LLM reasoning
    Receives only the rule findings as structured JSON.
    The LLM interprets patterns across multiple findings,
    but it cannot override the deterministic rule outputs.
    LLM verdict and score are combined with rule scores
    at the end to produce the final assessment.
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

import requests


logger = logging.getLogger(__name__)


# ============================================================
# FINDING
# ============================================================

@dataclass
class BehaviorFinding:
    """
    A single behavioral indicator produced by a deterministic rule.
    """

    rule_id: str
    name: str
    severity: str          # "low" | "medium" | "high" | "critical"
    description: str
    evidence: dict = field(default_factory=dict)
    score_contribution: int = 0   # 0-100 contribution to behavior score


# ============================================================
# DETERMINISTIC RULE ENGINE
# ============================================================

class BehaviorRuleEngine:
    """
    Evaluates the sandbox event log using deterministic rules.

    Rules are fully independent of the LLM.  Each rule:
      1. Inspects specific event kinds in the timeline.
      2. Produces a BehaviorFinding if triggered.
      3. Contributes a fixed score to the behavior risk total.
    """

    # --------------------------------------------------------
    # PUBLIC
    # --------------------------------------------------------

    def evaluate(self, sandbox: dict) -> list[BehaviorFinding]:
        """
        Run all rules and return the list of triggered findings.
        """

        findings: list[BehaviorFinding] = []
        network = sandbox.get("network_events", [])
        browser = sandbox.get("browser_events", [])
        page = sandbox.get("page_events", [])
        all_events = network + browser + page

        # Run each rule in order
        findings += self._rule_password_field(page)
        findings += self._rule_cross_origin_form(page)
        findings += self._rule_hidden_iframe(page)
        findings += self._rule_obfuscated_script(page)
        findings += self._rule_download_attempt(network)
        findings += self._rule_redirect_chain(network)
        findings += self._rule_popup_storm(browser)
        findings += self._rule_dialog_spam(browser)
        findings += self._rule_external_resource_flood(network, sandbox)
        findings += self._rule_session_terminated_early(sandbox)

        return findings

    # --------------------------------------------------------
    # RULE IMPLEMENTATIONS
    # --------------------------------------------------------

    def _rule_password_field(
        self,
        page_events: list[dict],
    ) -> list[BehaviorFinding]:

        events = self._filter_events(
            page_events,
            "password_field_detected",
        )

        if not events:
            return []

        count = events[0]["data"].get("count", 1)

        return [BehaviorFinding(
            rule_id="RULE_PW_FIELD",
            name="Credential Harvesting Form",
            severity="high",
            description=(
                f"The page contains {count} password input field(s). "
                "This is a primary indicator of a credential-harvesting "
                "phishing page."
            ),
            evidence={"password_field_count": count},
            score_contribution=40,
        )]

    # --------------------------------------------------------

    def _rule_cross_origin_form(
        self,
        page_events: list[dict],
    ) -> list[BehaviorFinding]:

        events = self._filter_events(
            page_events,
            "cross_origin_form_detected",
        )

        if not events:
            return []

        targets = [
            ev["data"].get("form_host", "")
            for ev in events
        ]

        return [BehaviorFinding(
            rule_id="RULE_XORIGIN_FORM",
            name="Cross-Origin Form Submission",
            severity="high",
            description=(
                "A form on the page submits data to a different "
                f"domain: {', '.join(set(targets))}. "
                "This is a strong indicator of data exfiltration."
            ),
            evidence={"external_targets": list(set(targets))},
            score_contribution=45,
        )]

    # --------------------------------------------------------

    def _rule_hidden_iframe(
        self,
        page_events: list[dict],
    ) -> list[BehaviorFinding]:

        events = self._filter_events(
            page_events,
            "hidden_iframe_detected",
        )

        if not events:
            return []

        srcs = events[0]["data"].get("srcs", [])

        return [BehaviorFinding(
            rule_id="RULE_HIDDEN_IFRAME",
            name="Hidden Iframe (Clickjacking Indicator)",
            severity="high",
            description=(
                "The page contains hidden iframe(s), which may be "
                "used for clickjacking or covert content embedding."
            ),
            evidence={"iframe_srcs": srcs},
            score_contribution=35,
        )]

    # --------------------------------------------------------

    def _rule_obfuscated_script(
        self,
        page_events: list[dict],
    ) -> list[BehaviorFinding]:

        events = self._filter_events(
            page_events,
            "obfuscated_script_detected",
        )

        if not events:
            return []

        patterns = events[0]["data"].get("patterns", [])

        return [BehaviorFinding(
            rule_id="RULE_OBFUSC_SCRIPT",
            name="Obfuscated JavaScript Detected",
            severity="medium",
            description=(
                "The page uses JavaScript obfuscation techniques "
                f"({', '.join(patterns)}). This may indicate "
                "attempts to hide malicious code."
            ),
            evidence={"obfuscation_patterns": patterns},
            score_contribution=25,
        )]

    # --------------------------------------------------------

    def _rule_download_attempt(
        self,
        network_events: list[dict],
    ) -> list[BehaviorFinding]:

        events = self._filter_events(
            network_events,
            "download_attempt",
            "blocked_download",
        )

        if not events:
            return []

        urls = [ev["data"].get("url", "") for ev in events]

        return [BehaviorFinding(
            rule_id="RULE_DOWNLOAD",
            name="Drive-by Download Attempt",
            severity="critical",
            description=(
                "The site attempted to trigger a file download. "
                "This may indicate a drive-by download attack. "
                "The download was blocked by the sandbox."
            ),
            evidence={"download_urls": urls},
            score_contribution=60,
        )]

    # --------------------------------------------------------

    def _rule_redirect_chain(
        self,
        network_events: list[dict],
    ) -> list[BehaviorFinding]:

        redirect_events = self._filter_events(
            network_events,
            "redirect",
        )

        limit_events = self._filter_events(
            network_events,
            "redirect_limit_reached",
        )

        count = len(redirect_events)

        if count < 3 and not limit_events:
            return []

        hops = [
            {
                "from": ev["data"].get("from", ""),
                "to": ev["data"].get("to", ""),
                "status": ev["data"].get("status"),
            }
            for ev in redirect_events
        ]

        severity = "critical" if limit_events else "medium"
        score = 40 if limit_events else 20

        return [BehaviorFinding(
            rule_id="RULE_REDIRECT_CHAIN",
            name="Long Redirect Chain",
            severity=severity,
            description=(
                f"The URL produced {count} redirect hop(s). "
                "Long redirect chains are used to hide the final "
                "destination from URL scanners."
            ),
            evidence={"hops": hops, "count": count},
            score_contribution=score,
        )]

    # --------------------------------------------------------

    def _rule_popup_storm(
        self,
        browser_events: list[dict],
    ) -> list[BehaviorFinding]:

        events = self._filter_events(
            browser_events,
            "popup_opened",
        )

        count = len(events)

        if count < 2:
            return []

        return [BehaviorFinding(
            rule_id="RULE_POPUP_STORM",
            name="Popup Storm",
            severity="medium",
            description=(
                f"The site opened {count} popup window(s). "
                "Multiple popups are used for ad fraud or to "
                "confuse users into clicking malicious content."
            ),
            evidence={"popup_count": count},
            score_contribution=20,
        )]

    # --------------------------------------------------------

    def _rule_dialog_spam(
        self,
        browser_events: list[dict],
    ) -> list[BehaviorFinding]:

        events = self._filter_events(
            browser_events,
            "dialog_triggered",
        )

        count = len(events)

        if count < 2:
            return []

        messages = [
            ev["data"].get("message", "")
            for ev in events
        ]

        return [BehaviorFinding(
            rule_id="RULE_DIALOG_SPAM",
            name="Dialog Spam",
            severity="medium",
            description=(
                f"The site triggered {count} browser dialog(s) "
                "(alert/confirm/prompt). This is a social-engineering "
                "technique used to pressure users."
            ),
            evidence={"dialog_count": count, "messages": messages},
            score_contribution=20,
        )]

    # --------------------------------------------------------

    def _rule_external_resource_flood(
        self,
        network_events: list[dict],
        sandbox: dict,
    ) -> list[BehaviorFinding]:
        """
        Detect when a page loads many resources from domains
        that differ from the primary hostname.
        """

        original_host = ""

        try:
            from urllib.parse import urlparse
            original_host = urlparse(
                sandbox.get("url", "")
            ).hostname or ""
        except Exception:
            pass

        if not original_host:
            return []

        request_events = self._filter_events(
            network_events,
            "request",
        )

        external = [
            ev for ev in request_events
            if self._is_external(
                ev["data"].get("url", ""),
                original_host,
            )
        ]

        count = len(external)

        if count < 20:
            return []

        return [BehaviorFinding(
            rule_id="RULE_EXT_FLOOD",
            name="External Resource Flood",
            severity="low",
            description=(
                f"The page loaded {count} resources from external "
                "domains. This may indicate tracking, ad networks, "
                "or content injection."
            ),
            evidence={"external_request_count": count},
            score_contribution=10,
        )]

    # --------------------------------------------------------

    def _rule_session_terminated_early(
        self,
        sandbox: dict,
    ) -> list[BehaviorFinding]:

        if not sandbox.get("terminated_early", False):
            return []

        reason = sandbox.get("termination_reason", "")

        return [BehaviorFinding(
            rule_id="RULE_EARLY_TERM",
            name="Session Terminated by Threat Threshold",
            severity="high",
            description=(
                "The sandbox session was terminated early because "
                f"the cumulative threat score reached the configured "
                f"threshold. Reason: {reason}"
            ),
            evidence={"reason": reason},
            score_contribution=30,
        )]

    # --------------------------------------------------------
    # HELPERS
    # --------------------------------------------------------

    @staticmethod
    def _filter_events(
        events: list[dict],
        *kinds: str,
    ) -> list[dict]:
        return [
            ev for ev in events
            if ev.get("kind") in kinds
        ]

    @staticmethod
    def _is_external(url: str, original_host: str) -> bool:
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            return bool(host) and host != original_host
        except Exception:
            return False


# ============================================================
# LLM BEHAVIOR REASONER
# ============================================================

class BehaviorLLMReasoner:
    """
    Sends rule findings to the Qwen model and asks it to
    reason about the threat pattern as a whole.

    The LLM receives ONLY the rule findings as input.
    It cannot see raw browser events, reducing prompt injection risk.
    """

    ALLOWED_VERDICTS = {"safe", "suspicious", "malicious"}

    def __init__(self) -> None:

        self.model = os.getenv(
            "LLM_MODEL",
            "qwen2.5:3b",
        )

        self.base_url = os.getenv(
            "LLM_BASE_URL",
            "http://127.0.0.1:11434",
        ).rstrip("/")

        self.timeout = int(
            os.getenv("LLM_TIMEOUT", "120")
        )

    def reason(
        self,
        findings: list[BehaviorFinding],
        sandbox_meta: dict,
    ) -> dict:
        """
        Ask the LLM to interpret the behavioral findings.

        Returns a dict with:
          verdict, confidence, llm_summary, llm_indicators
        """

        if not findings:
            return self._no_findings_response()

        findings_payload = [
            {
                "rule_id": f.rule_id,
                "name": f.name,
                "severity": f.severity,
                "description": f.description,
                "score_contribution": f.score_contribution,
            }
            for f in findings
        ]

        meta_payload = {
            "url": sandbox_meta.get("url", ""),
            "page_title": sandbox_meta.get("page_title"),
            "redirect_count": sandbox_meta.get("redirect_count", 0),
            "terminated_early": sandbox_meta.get("terminated_early", False),
            "cumulative_threat_score": sandbox_meta.get(
                "cumulative_threat_score", 0
            ),
        }

        prompt = self._build_prompt(findings_payload, meta_payload)

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            raw = response.json().get("response", "")
            return self._parse_response(raw)

        except Exception as exc:
            logger.warning(
                "BehaviorLLMReasoner request failed: %s",
                exc,
            )
            return self._fallback_response(findings)

    # --------------------------------------------------------

    def _build_prompt(
        self,
        findings: list[dict],
        meta: dict,
    ) -> str:

        findings_json = json.dumps(findings, indent=2)
        meta_json = json.dumps(meta, indent=2)

        return f"""
You are a cybersecurity analyst reviewing behavioral findings from a
controlled browser sandbox that visited a potentially malicious URL.

You will receive:
1. A list of RULE FINDINGS — each produced by an independent deterministic rule.
2. Session metadata.

Your task:
- Reason about the COMBINATION of findings.
- Determine whether the URL is behaviorally: safe, suspicious, or malicious.
- Provide a concise summary.

IMPORTANT CONSTRAINTS:
1. You cannot override or dismiss individual rule findings.
2. Your verdict must be one of exactly: "safe", "suspicious", "malicious"
3. A page with a password field AND a cross-origin form MUST be at minimum "suspicious".
4. A page with a drive-by download attempt MUST be "malicious".
5. Base your reasoning strictly on the supplied findings.
6. Do NOT use pretrained knowledge about specific domains.

Return ONLY valid JSON, no Markdown, no code fences:

{{
  "verdict": "malicious",
  "confidence": 0.9,
  "llm_summary": "Short explanation based only on the findings",
  "llm_indicators": [
    {{
      "name": "Pattern name",
      "reason": "Why this combination is significant"
    }}
  ]
}}

SESSION METADATA:
{meta_json}

RULE FINDINGS:
{findings_json}
"""

    # --------------------------------------------------------

    def _parse_response(self, raw: str) -> dict:

        raw = raw.strip()

        # Direct JSON
        try:
            return self._validate(json.loads(raw))
        except (json.JSONDecodeError, ValueError):
            pass

        # Strip Markdown fences
        cleaned = re.sub(
            r"^```(?:json)?\s*",
            "",
            raw,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()

        try:
            return self._validate(json.loads(cleaned))
        except (json.JSONDecodeError, ValueError):
            pass

        # Extract outermost {}
        start = cleaned.find("{")
        end = cleaned.rfind("}")

        if start != -1 and end > start:
            try:
                return self._validate(
                    json.loads(cleaned[start:end + 1])
                )
            except (json.JSONDecodeError, ValueError):
                pass

        logger.warning("BehaviorLLMReasoner: unparseable response")
        return self._no_findings_response()

    def _validate(self, data: dict) -> dict:

        verdict = str(
            data.get("verdict", "suspicious")
        ).lower().strip()

        if verdict not in self.ALLOWED_VERDICTS:
            verdict = "suspicious"

        confidence = max(
            0.0,
            min(1.0, float(data.get("confidence", 0.5))),
        )

        return {
            "verdict": verdict,
            "confidence": confidence,
            "llm_summary": str(data.get("llm_summary", "")).strip(),
            "llm_indicators": data.get("llm_indicators", []),
        }

    # --------------------------------------------------------

    def _no_findings_response(self) -> dict:
        return {
            "verdict": "safe",
            "confidence": 0.5,
            "llm_summary": (
                "No behavioral findings were triggered by the sandbox."
            ),
            "llm_indicators": [],
        }

    def _fallback_response(
        self,
        findings: list[BehaviorFinding],
    ) -> dict:
        """
        If the LLM is unavailable, derive a safe fallback verdict
        from the deterministic findings alone.
        """
        total = sum(f.score_contribution for f in findings)
        critical = any(
            f.severity == "critical" for f in findings
        )
        high = any(f.severity == "high" for f in findings)

        if critical or total >= 60:
            verdict = "malicious"
            confidence = 0.8
        elif high or total >= 30:
            verdict = "suspicious"
            confidence = 0.7
        else:
            verdict = "safe"
            confidence = 0.6

        return {
            "verdict": verdict,
            "confidence": confidence,
            "llm_summary": (
                "LLM unavailable. Verdict derived from deterministic "
                "rule scores only."
            ),
            "llm_indicators": [],
        }


# ============================================================
# PUBLIC ANALYZER
# ============================================================

class BehaviorAnalyzer:
    """
    Orchestrates Layer 1 (rules) and Layer 2 (LLM) analysis
    of a sandbox result and produces a combined assessment.
    """

    def __init__(
        self,
        rule_engine: Optional[BehaviorRuleEngine] = None,
        llm_reasoner: Optional[BehaviorLLMReasoner] = None,
    ) -> None:

        self.rule_engine = rule_engine or BehaviorRuleEngine()
        self.llm_reasoner = llm_reasoner or BehaviorLLMReasoner()

    def analyze(self, sandbox: dict) -> dict:
        """
        Analyze sandbox output and return a behavioral assessment.
        """

        # ---- Layer 1: deterministic rules -------------------

        findings = self.rule_engine.evaluate(sandbox)

        rule_score = min(
            100,
            sum(f.score_contribution for f in findings),
        )

        # ---- Layer 2: LLM reasoning -------------------------

        sandbox_meta = {
            "url": sandbox.get("url", ""),
            "page_title": sandbox.get("page_title"),
            "redirect_count": sandbox.get("redirect_count", 0),
            "terminated_early": sandbox.get("terminated_early", False),
            "cumulative_threat_score": sandbox.get(
                "cumulative_threat_score", 0
            ),
        }

        llm_result = self.llm_reasoner.reason(findings, sandbox_meta)

        # ---- Combined verdict --------------------------------

        final_verdict = self._combine_verdicts(
            findings,
            rule_score,
            llm_result,
        )

        # ---- Serialize findings ------------------------------

        serialized_findings = [
            {
                "rule_id": f.rule_id,
                "name": f.name,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "score_contribution": f.score_contribution,
            }
            for f in findings
        ]

        return {
            # Layer 1 output
            "rule_findings": serialized_findings,
            "rule_score": rule_score,

            # Layer 2 output
            "llm_verdict": llm_result["verdict"],
            "llm_confidence": llm_result["confidence"],
            "llm_summary": llm_result["llm_summary"],
            "llm_indicators": llm_result.get("llm_indicators", []),

            # Combined
            "verdict": final_verdict["verdict"],
            "confidence": final_verdict["confidence"],
            "behavior_score": final_verdict["behavior_score"],
            "summary": final_verdict["summary"],
        }

    # --------------------------------------------------------

    def _combine_verdicts(
        self,
        findings: list[BehaviorFinding],
        rule_score: int,
        llm_result: dict,
    ) -> dict:
        """
        Deterministic rules act as a floor.
        The LLM can raise the verdict but cannot lower it.
        """

        # Compute a combined behavior score
        # (weighted average, rules carry more weight)
        llm_score = int(llm_result["confidence"] * 100)
        behavior_score = min(
            100,
            int(rule_score * 0.65 + llm_score * 0.35),
        )

        # Deterministic floor verdict
        critical = any(f.severity == "critical" for f in findings)
        high_count = sum(
            1 for f in findings if f.severity == "high"
        )

        if critical or rule_score >= 60:
            floor_verdict = "malicious"
        elif high_count >= 1 or rule_score >= 30:
            floor_verdict = "suspicious"
        else:
            floor_verdict = "safe"

        # LLM can raise verdict level
        verdict_rank = {"safe": 0, "suspicious": 1, "malicious": 2}
        llm_rank = verdict_rank.get(llm_result["verdict"], 0)
        floor_rank = verdict_rank.get(floor_verdict, 0)
        final_rank = max(llm_rank, floor_rank)

        verdict_names = {0: "safe", 1: "suspicious", 2: "malicious"}
        final_verdict = verdict_names[final_rank]

        # Confidence: average of rule confidence and LLM confidence
        rule_confidence = min(1.0, rule_score / 100)
        final_confidence = round(
            (rule_confidence * 0.6 + llm_result["confidence"] * 0.4),
            3,
        )

        # Summary
        if findings:
            top_finding = sorted(
                findings,
                key=lambda f: f.score_contribution,
                reverse=True,
            )[0]
            summary = (
                f"{len(findings)} behavioral indicator(s) detected. "
                f"Most significant: {top_finding.name}. "
                f"{llm_result['llm_summary']}"
            )
        else:
            summary = llm_result["llm_summary"]

        return {
            "verdict": final_verdict,
            "confidence": final_confidence,
            "behavior_score": behavior_score,
            "summary": summary,
        }
