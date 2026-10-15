"""
LLM-powered phishing analysis service.

Uses Ollama locally and expects a structured JSON response
from the language model.
"""

import json
import logging
import os
import re

import requests


logger = logging.getLogger(__name__)


class LLMService:
    """
    Analyze structured URL security evidence using a local Ollama model.
    """

    ALLOWED_VERDICTS = {
        "safe",
        "suspicious",
        "phishing",
    }

    ALLOWED_SEVERITIES = {
        "low",
        "medium",
        "high",
    }

    def __init__(self):
        self.provider = os.getenv(
            "LLM_PROVIDER",
            "ollama",
        ).lower()

        self.model = os.getenv(
            "LLM_MODEL",
            "qwen2.5:3b",
        )

        self.base_url = os.getenv(
            "LLM_BASE_URL",
            "http://127.0.0.1:11434",
        ).rstrip("/")

        self.timeout = int(
            os.getenv(
                "LLM_TIMEOUT",
                "120",
            )
        )

    def analyze(self, evidence: dict) -> dict:
        """
        Analyze security evidence and return a validated result.
        """

        if self.provider != "ollama":
            raise RuntimeError(
                f"Unsupported LLM provider: {self.provider}"
            )

        prompt = self._build_prompt(evidence)

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

            if response.status_code != 200:
                logger.error(
                    "Ollama returned HTTP %s: %s",
                    response.status_code,
                    response.text,
                )

            response.raise_for_status()

            data = response.json()

            raw_response = data.get(
                "response",
                "",
            )

            if not raw_response:
                raise ValueError(
                    "Ollama returned an empty response"
                )

            result = self._parse_response(
                raw_response
            )

            return self._validate_result(
                result,
                evidence=evidence,
            )

        except requests.RequestException as exc:
            logger.exception(
                "Ollama request failed"
            )

            raise RuntimeError(
                f"LLM service unavailable: {exc}"
            ) from exc

        except (
            ValueError,
            json.JSONDecodeError,
        ) as exc:

            logger.exception(
                "Invalid LLM response"
            )

            raise RuntimeError(
                f"Invalid LLM analysis response: {exc}"
            ) from exc

    def _build_prompt(
        self,
        evidence: dict,
    ) -> str:
        """
        Build a strict cybersecurity analysis prompt.
        """

        evidence_json = json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        )

        return f"""
You are a cybersecurity URL analysis assistant.

Your task is to analyze ONLY the supplied URL security
evidence and determine whether the URL is:

- safe
- suspicious
- phishing

You must make an evidence-based assessment.

IMPORTANT SECURITY RULES:

1. Use ONLY the supplied evidence.

2. Do NOT use your pretrained knowledge to determine whether
   a domain is famous, trusted, legitimate, popular, or owned
   by a particular organization.

3. Do NOT claim that a domain is "well-known", "trusted",
   "legitimate", or "safe" unless the supplied evidence
   explicitly establishes that fact.

4. A URL not appearing in a threat-intelligence database
   does NOT prove that the URL is safe.

5. HTTPS does NOT prove that a website is legitimate.
   HTTPS only indicates encrypted transport.

6. An IP address alone does NOT prove that a URL is malicious.

7. Evaluate combinations of indicators rather than relying
   on a single indicator.

8. Treat confirmed threat-intelligence results as strong
   evidence.

9. Clearly distinguish observable facts from your assessment.

10. Do NOT invent:
    - domain reputation
    - domain ownership
    - brand affiliation
    - WHOIS information
    - DNS information
    - malware history
    - popularity
    - external reputation
    - external facts not present in the evidence

11. If the evidence does not establish legitimacy, use
    wording such as:
    "No strong phishing indicators were identified from
    the available evidence."

12. Do not say that a URL is guaranteed safe.

13. Recommendations must be based only on the supplied evidence.

RISK ASSESSMENT RULES:

- Do not classify a URL as suspicious solely because threat intelligence does not list it.
- Do not treat HTTPS, a normal URL structure, or missing threat-intelligence matches as suspicious indicators by themselves.
- Assign risk points only to concrete suspicious or malicious indicators present in the supplied evidence.
- If the evidence contains no strong phishing indicators, do not invent suspicious indicators or raise the risk score without evidence.
- Use "suspicious" when actual suspicious indicators are present but evidence is insufficient for a phishing verdict.
- Use "phishing" only when the supplied evidence supports that assessment.
- The verdict, risk score, indicators, and summary must be consistent with one another.

RISK GUIDANCE:

Use the following general interpretation:

0-29:
Low apparent risk.

30-59:
Suspicious indicators are present, but evidence is not
strong enough to classify the URL as phishing.

60-79:
Multiple strong indicators suggest significant risk.

80-100:
Very strong evidence of phishing or malicious activity,
especially when supported by threat intelligence.

These ranges are guidance only. Use the supplied evidence
to determine the final assessment.

Return ONLY valid JSON.

Do not use Markdown.
Do not use code fences.
Do not add explanations outside the JSON object.

Return EXACTLY this structure:

{{
  "verdict": "safe",
  "risk_score": 0,
  "confidence": 0.0,
  "summary": "Short evidence-based explanation",
  "indicators": [
    {{
      "name": "Indicator name",
      "severity": "low",
      "reason": "Why this indicator matters"
    }}
  ],
  "recommendation": "Recommended user action"
}}

CONFIDENCE ASSESSMENT RULES:

- Assess confidence independently from the risk score and verdict.
- Base confidence on the strength, consistency, and completeness of the supplied evidence.
- Use lower confidence when evidence is missing, ambiguous, conflicting, or based only on weak indicators.
- Use higher confidence only when multiple reliable indicators support the assessment.
- An unlisted URL in threat intelligence is not proof of safety.
- HTTPS alone is not proof of legitimacy.
- Do not automatically return 0.0 or 1.0; choose the value justified by the evidence.
- Do not invent evidence to justify a confidence value.

SUMMARY RULES:

- Never describe a URL as safe, legitimate, trusted, or well-known based only on HTTPS or an unlisted threat-intelligence result.
- Describe HTTPS and threat-intelligence lookup results as observations, not proof of legitimacy.
- When evidence is limited, state that no strong phishing indicators were identified in the available evidence; do not claim the website is safe.
- Keep the summary consistent with the supplied evidence and the assigned verdict.

OUTPUT RULES:

- verdict must be exactly one of:
  "safe", "suspicious", "phishing"

- risk_score must be an integer from 0 to 100.

- confidence must be a number from 0.0 to 1.0.

- severity must be exactly one of:
  "low", "medium", "high"

- indicators must be a JSON array.

- Each indicator must contain:
  "name"
  "severity"
  "reason"

- recommendation must be concise.

- summary must be based only on the supplied evidence.

SECURITY EVIDENCE:

{evidence_json}
"""

    def _parse_response(
        self,
        raw_response: str,
    ) -> dict:
        """
        Parse JSON returned by Ollama.

        Handles both pure JSON and accidental Markdown
        code fences.
        """

        raw_response = raw_response.strip()

        # First attempt: direct JSON
        try:
            return json.loads(
                raw_response
            )

        except json.JSONDecodeError:
            pass

        # Remove Markdown code fences if present.
        cleaned_response = re.sub(
            r"^```(?:json)?\s*",
            "",
            raw_response,
            flags=re.IGNORECASE,
        )

        cleaned_response = re.sub(
            r"\s*```$",
            "",
            cleaned_response,
        ).strip()

        try:
            return json.loads(
                cleaned_response
            )

        except json.JSONDecodeError:
            pass

        # Final defensive fallback:
        # extract the outermost JSON object.
        start = cleaned_response.find(
            "{"
        )

        end = cleaned_response.rfind(
            "}"
        )

        if start == -1 or end == -1 or end <= start:
            raise ValueError(
                "LLM did not return a valid JSON object"
            )

        json_text = cleaned_response[
            start:end + 1
        ]

        return json.loads(
            json_text
        )

    def _validate_result(
        self,
        result: dict,
        evidence: dict | None = None,
    ) -> dict:
        """
        Validate and normalize the model response.
        """

        if not isinstance(result, dict):
            raise ValueError(
                "LLM response must be a JSON object"
            )

        # ==========================================
        # Verdict
        # ==========================================

        verdict = str(
            result.get(
                "verdict",
                "",
            )
        ).lower().strip()

        if verdict not in self.ALLOWED_VERDICTS:
            raise ValueError(
                f"Invalid verdict: {verdict}"
            )

        # ==========================================
        # Risk Score
        # ==========================================

        try:
            risk_score = int(
                result.get(
                    "risk_score"
                )
            )

        except (
            TypeError,
            ValueError,
        ) as exc:

            raise ValueError(
                "risk_score must be an integer"
            ) from exc

        risk_score = max(
            0,
            min(
                100,
                risk_score,
            ),
        )

        # ==========================================
        # Confidence
        # ==========================================

        try:
            confidence = float(
                result.get(
                    "confidence"
                )
            )

        except (
            TypeError,
            ValueError,
        ) as exc:

            raise ValueError(
                "confidence must be a number"
            ) from exc

        confidence = max(
            0.0,
            min(
                1.0,
                confidence,
            ),
        )

        # ==========================================
        # Summary
        # ==========================================

        summary = str(
            result.get(
                "summary",
                "",
            )
        ).strip()

        if not summary:
            summary = (
                "No detailed explanation was provided."
            )

        # ==========================================
        # Recommendation
        # ==========================================

        recommendation = str(
            result.get(
                "recommendation",
                "",
            )
        ).strip()

        if not recommendation:
            recommendation = (
                "Review the URL carefully before proceeding."
            )

        # ==========================================
        # Indicators
        # ==========================================

        indicators = result.get(
            "indicators",
            [],
        )

        if not isinstance(
            indicators,
            list,
        ):
            raise ValueError(
                "indicators must be a list"
            )

        threat = (evidence or {}).get("threat_intelligence") or {}
        unlisted_ti_is_not_evidence = (
            isinstance(threat, dict)
            and threat.get("checked") is True
            and threat.get("listed") is False
            and not threat.get("api_error", False)
        )

        validated_indicators = []

        for indicator in indicators:

            if not isinstance(
                indicator,
                dict,
            ):
                continue

            name = str(
                indicator.get(
                    "name",
                    "",
                )
            ).strip()

            severity = str(
                indicator.get(
                    "severity",
                    "low",
                )
            ).lower().strip()

            reason = str(
                indicator.get(
                    "reason",
                    "",
                )
            ).strip()

            indicator_text = f"{name} {reason}".lower()
            is_ti_indicator = "threat intelligence" in indicator_text
            describes_unlisted_result = any(
                phrase in indicator_text
                for phrase in (
                    "unlisted",
                    "not listed",
                    "not found",
                    "no match",
                    "was not listed",
                    "wasn't listed",
                    "no listing",
                    "not present in",
                )
            )

            if (
                unlisted_ti_is_not_evidence
                and is_ti_indicator
                and describes_unlisted_result
            ):
                continue

            if not name:
                continue

            if severity not in self.ALLOWED_SEVERITIES:
                severity = "low"

            validated_indicators.append(
                {
                    "name": name,
                    "severity": severity,
                    "reason": reason,
                }
            )

        # ==========================================
        # Final validated response
        # ==========================================

        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "summary": summary,
            "indicators": validated_indicators,
            "recommendation": recommendation,
        }