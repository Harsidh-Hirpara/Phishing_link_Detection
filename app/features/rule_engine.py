"""
Seven-layer phishing detection rule engine.

Layers:
1. SSL/TLS Encryption
2. Subdomain Count
3. IP Address Detection
4. Domain Length
5. Special Characters
6. Suspicious Keywords
7. URL Length
"""

import ipaddress
import re


class RuleEngine:
    """
    Seven-layer URL security analysis engine.
    """

    SUSPICIOUS_KEYWORDS = [
        "verify",
        "confirm",
        "update",
        "login",
        "signin",
        "sign-in",
        "account",
        "secure",
        "security",
        "urgent",
        "click",
        "validate",
        "password",
        "credential",
        "wallet",
        "payment",
        "bank",
        "invoice",
    ]

    def analyze(
        self,
        parsed_url: dict,
        original_url: str,
    ) -> dict:
        """
        Perform seven security checks against a URL.
        """

        checks = []
        risk_score = 0

        hostname = (
            parsed_url.get("hostname") or ""
        ).lower()

        protocol = (
            parsed_url.get("protocol") or ""
        ).lower()

        full_url = (
            parsed_url.get("full")
            or original_url
            or ""
        )

        # ==================================================
        # LAYER 1: SSL/TLS ENCRYPTION
        # ==================================================

        if protocol == "https":

            checks.append({
                "name": "SSL/TLS Encryption",
                "status": "pass",
                "description": (
                    "URL uses secure HTTPS protocol"
                ),
            })

        elif protocol == "http":

            checks.append({
                "name": "SSL/TLS Encryption",
                "status": "fail",
                "description": (
                    "URL uses unencrypted HTTP protocol"
                ),
            })

            risk_score += 15

        else:

            checks.append({
                "name": "SSL/TLS Encryption",
                "status": "warn",
                "description": (
                    "URL does not use a recognized "
                    "HTTP or HTTPS protocol"
                ),
            })

            risk_score += 10

        # ==================================================
        # LAYER 2: SUBDOMAIN COUNT
        # ==================================================

        hostname_parts = [
            part
            for part in hostname.split(".")
            if part
        ]

        hostname_type = self._hostname_type(
            hostname
        )

        if hostname_type in ["ipv4", "ipv6"]:

            subdomain_count = 0

        else:

            subdomain_count = max(
                0,
                len(hostname_parts) - 2,
            )

        if subdomain_count >= 2:

            checks.append({
                "name": "Subdomain Count",
                "status": "warn",
                "description": (
                    f"URL contains {subdomain_count} "
                    "subdomains, which may indicate "
                    "suspicious hosting"
                ),
            })

            risk_score += 8

        else:

            checks.append({
                "name": "Subdomain Count",
                "status": "pass",
                "description": (
                    "Normal subdomain structure"
                ),
            })

        # ==================================================
        # LAYER 3: IP ADDRESS DETECTION
        # ==================================================

        if hostname_type in ["ipv4", "ipv6"]:

            checks.append({
                "name": "IP Address Domain",
                "status": "fail",
                "description": (
                    "URL uses a direct IP address "
                    "instead of a standard domain name"
                ),
            })

            risk_score += 20

        else:

            checks.append({
                "name": "IP Address Domain",
                "status": "pass",
                "description": (
                    "Uses a standard domain name"
                ),
            })

        # ==================================================
        # LAYER 4: DOMAIN LENGTH
        # ==================================================

        hostname_length = len(hostname)

        if hostname_length < 4:

            checks.append({
                "name": "Domain Length",
                "status": "warn",
                "description": (
                    "Very short domain name"
                ),
            })

            risk_score += 5

        elif hostname_length > 50:

            checks.append({
                "name": "Domain Length",
                "status": "warn",
                "description": (
                    "Very long domain name may be suspicious"
                ),
            })

            risk_score += 5

        else:

            checks.append({
                "name": "Domain Length",
                "status": "pass",
                "description": (
                    "Domain length appears normal"
                ),
            })

        # ==================================================
        # LAYER 5: SPECIAL CHARACTERS
        # ==================================================

        special_character_found = False

        if hostname_type == "domain":

            if re.search(
                r"[^a-zA-Z0-9.\-_]",
                hostname,
            ):
                special_character_found = True

        if special_character_found:

            checks.append({
                "name": "Special Characters",
                "status": "fail",
                "description": (
                    "Domain contains suspicious "
                    "special characters"
                ),
            })

            risk_score += 15

        else:

            checks.append({
                "name": "Special Characters",
                "status": "pass",
                "description": (
                    "No suspicious characters "
                    "detected in domain"
                ),
            })

        # ==================================================
        # LAYER 6: SUSPICIOUS KEYWORDS
        # ==================================================

        url_lower = full_url.lower()

        found_keywords = []

        for keyword in self.SUSPICIOUS_KEYWORDS:

            pattern = (
                rf"(?<![a-z0-9])"
                rf"{re.escape(keyword)}"
                rf"(?![a-z0-9])"
            )

            if re.search(
                pattern,
                url_lower,
            ):
                found_keywords.append(
                    keyword
                )

        if len(found_keywords) >= 2:

            checks.append({
                "name": "Suspicious Keywords",
                "status": "warn",
                "description": (
                    "Found suspicious phishing-related "
                    f"keywords: "
                    f"{', '.join(found_keywords)}"
                ),
            })

            risk_score += min(
                25,
                len(found_keywords) * 3,
            )

        elif len(found_keywords) == 1:

            checks.append({
                "name": "Suspicious Keywords",
                "status": "warn",
                "description": (
                    "Found suspicious keyword: "
                    f"{found_keywords[0]}"
                ),
            })

            risk_score += 5

        else:

            checks.append({
                "name": "Suspicious Keywords",
                "status": "pass",
                "description": (
                    "No common phishing keywords detected"
                ),
            })

        # ==================================================
        # LAYER 7: URL LENGTH
        # ==================================================

        url_length = len(full_url)

        if url_length > 100:

            checks.append({
                "name": "URL Length",
                "status": "warn",
                "description": (
                    "Very long URL may contain "
                    "hidden parameters or redirects"
                ),
            })

            risk_score += 8

        else:

            checks.append({
                "name": "URL Length",
                "status": "pass",
                "description": (
                    "URL length is reasonable"
                ),
            })

        # ==================================================
        # FINAL SCORE
        # ==================================================

        risk_score = max(
            0,
            min(
                100,
                risk_score,
            ),
        )

        safety_score = max(
            0,
            100 - risk_score,
        )

        # --------------------------------------------------
        # VERDICT
        # --------------------------------------------------

        if risk_score == 0:

            verdict = "safe"

        elif risk_score < 50:

            verdict = "risky"

        else:

            verdict = "unsafe"

        # ==================================================
        # RETURN
        # ==================================================

        return {
            "safety_score": safety_score,
            "risk_score": risk_score,
            "checks": checks,
            "verdict": verdict,
        }

    # ======================================================
    # HOSTNAME TYPE
    # ======================================================

    def _hostname_type(
        self,
        hostname: str,
    ) -> str:
        """
        Detect IPv4, IPv6, or normal domain.
        """

        if not hostname:
            return "unknown"

        try:

            address = ipaddress.ip_address(
                hostname
            )

            if address.version == 4:
                return "ipv4"

            if address.version == 6:
                return "ipv6"

        except ValueError:
            pass

        return "domain"