"""
Security evidence builder.

Collects technical, structural, and lexical facts about a URL.
This component does not decide whether a URL is phishing.
"""

import ipaddress
import re
from urllib.parse import parse_qs


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


class EvidenceBuilder:
    """
    Builds factual security evidence from a parsed URL.
    """

    def build(
        self,
        parsed_url: dict,
        threat_intelligence: dict | None = None,
    ) -> dict:

        hostname = parsed_url.get("hostname", "")
        protocol = parsed_url.get("protocol", "")
        pathname = parsed_url.get("pathname", "")
        search = parsed_url.get("search", "")
        full_url = parsed_url.get("full", "")

        hostname_type = self._get_hostname_type(hostname)

        subdomain_count = self._get_subdomain_count(
            hostname,
            hostname_type,
        )

        suspicious_keywords = self._find_keywords(full_url)

        query_parameters = self._get_query_parameters(search)

        special_character_indicators = (
            self._get_special_character_indicators(
                hostname,
                full_url,
            )
        )

        threat_intelligence = (
            threat_intelligence
            if threat_intelligence is not None
            else {
                "checked": False,
                "listed": False,
                "source": None,
                "api_error": False,
            }
        )

        # =====================================================
        # RAW SECURITY EVIDENCE
        # =====================================================

        evidence = {
            "url": full_url,

            "protocol": {
                "value": protocol,
                "is_https": protocol == "https",
                "is_http": protocol == "http",
            },

            "hostname": {
                "value": hostname,
                "type": hostname_type,
                "length": len(hostname),
                "subdomain_count": subdomain_count,
            },

            "path": {
                "value": pathname,
                "length": len(pathname),
            },

            "query": {
                "value": search,
                "parameter_count": len(query_parameters),
                "parameters": list(
                    query_parameters.keys()
                ),
            },

            "url_length": len(full_url),

            "suspicious_keywords": suspicious_keywords,

            "special_character_indicators": (
                special_character_indicators
            ),

            "threat_intelligence": threat_intelligence,
        }

        # =====================================================
        # NORMALIZED SECURITY CHECKS
        # =====================================================

        evidence["checks"] = self._build_checks(
            evidence
        )

        return evidence

    # =========================================================
    # SECURITY CHECKS
    # =========================================================

    def _build_checks(
        self,
        evidence: dict,
    ) -> list[dict]:

        checks = []

        protocol = evidence["protocol"]
        hostname = evidence["hostname"]
        path = evidence["path"]
        query = evidence["query"]
        keywords = evidence["suspicious_keywords"]
        special = evidence["special_character_indicators"]
        threat = evidence["threat_intelligence"]

        # -----------------------------------------------------
        # 1. HTTPS
        # -----------------------------------------------------

        if protocol["is_https"]:
            checks.append({
                "name": "HTTPS encryption",
                "status": "pass",
                "severity": "low",
                "description": (
                    "The URL uses HTTPS encryption."
                ),
            })
        else:
            checks.append({
                "name": "HTTPS encryption",
                "status": "warning",
                "severity": "medium",
                "description": (
                    "The URL does not use HTTPS encryption."
                ),
            })

        # -----------------------------------------------------
        # 2. Hostname
        # -----------------------------------------------------

        if hostname["type"] in ("ipv4", "ipv6"):
            checks.append({
                "name": "Hostname type",
                "status": "warning",
                "severity": "medium",
                "description": (
                    f"The hostname is an {hostname['type']} "
                    "address instead of a normal domain."
                ),
            })
        elif hostname["type"] == "domain":
            checks.append({
                "name": "Hostname type",
                "status": "pass",
                "severity": "low",
                "description": (
                    f"The hostname '{hostname['value']}' "
                    "is a normal domain."
                ),
            })
        else:
            checks.append({
                "name": "Hostname type",
                "status": "warning",
                "severity": "medium",
                "description": (
                    "The hostname type could not be determined."
                ),
            })

        # -----------------------------------------------------
        # 3. Hostname length / subdomains
        # -----------------------------------------------------

        if hostname["length"] > 50:
            checks.append({
                "name": "Hostname structure",
                "status": "warning",
                "severity": "medium",
                "description": (
                    f"The hostname is unusually long "
                    f"({hostname['length']} characters)."
                ),
            })
        elif hostname["subdomain_count"] >= 3:
            checks.append({
                "name": "Hostname structure",
                "status": "warning",
                "severity": "medium",
                "description": (
                    f"The hostname contains "
                    f"{hostname['subdomain_count']} subdomains."
                ),
            })
        else:
            checks.append({
                "name": "Hostname structure",
                "status": "pass",
                "severity": "low",
                "description": (
                    f"The hostname '{hostname['value']}' "
                    f"has a standard structure."
                ),
            })

        # -----------------------------------------------------
        # 4. Suspicious keywords
        # -----------------------------------------------------

        if keywords:
            checks.append({
                "name": "Suspicious keywords",
                "status": "warning",
                "severity": "medium",
                "description": (
                    "The URL contains suspicious keywords: "
                    + ", ".join(keywords)
                    + "."
                ),
            })
        else:
            checks.append({
                "name": "Suspicious keywords",
                "status": "pass",
                "severity": "low",
                "description": (
                    "No suspicious keywords were identified "
                    "in the URL."
                ),
            })

        # -----------------------------------------------------
        # 5. URL structure
        # -----------------------------------------------------

        if special:
            checks.append({
                "name": "URL structure",
                "status": "warning",
                "severity": "medium",
                "description": (
                    "The URL contains notable structural "
                    "indicators: "
                    + ", ".join(special)
                    + "."
                ),
            })
        else:
            checks.append({
                "name": "URL structure",
                "status": "pass",
                "severity": "low",
                "description": (
                    "No unusual URL structural indicators "
                    "were identified."
                ),
            })

        # -----------------------------------------------------
        # 6. Query parameters
        # -----------------------------------------------------

        if query["parameter_count"] >= 5:
            checks.append({
                "name": "Query parameters",
                "status": "warning",
                "severity": "medium",
                "description": (
                    f"The URL contains "
                    f"{query['parameter_count']} query parameters."
                ),
            })
        elif query["parameter_count"] > 0:
            checks.append({
                "name": "Query parameters",
                "status": "pass",
                "severity": "low",
                "description": (
                    f"The URL contains "
                    f"{query['parameter_count']} query parameter(s)."
                ),
            })
        else:
            checks.append({
                "name": "Query parameters",
                "status": "pass",
                "severity": "low",
                "description": (
                    "No query parameters were identified."
                ),
            })

        # -----------------------------------------------------
        # 7. Threat intelligence
        # -----------------------------------------------------

        if threat.get("listed"):
            checks.append({
                "name": "Threat intelligence",
                "status": "fail",
                "severity": "high",
                "description": (
                    "The URL was identified by the threat "
                    "intelligence source as malicious."
                ),
            })

        elif threat.get("api_error"):
            checks.append({
                "name": "Threat intelligence",
                "status": "warning",
                "severity": "medium",
                "description": (
                    "Threat intelligence could not be "
                    "fully verified because the service "
                    "returned an error."
                ),
            })

        elif threat.get("checked"):
            checks.append({
                "name": "Threat intelligence",
                "status": "pass",
                "severity": "low",
                "description": (
                    "No malicious listing was found in "
                    "the checked threat intelligence source."
                ),
            })

        else:
            checks.append({
                "name": "Threat intelligence",
                "status": "warning",
                "severity": "medium",
                "description": (
                    "Threat intelligence was not checked."
                ),
            })

        return checks

    # =========================================================
    # HOSTNAME
    # =========================================================

    def _get_hostname_type(
        self,
        hostname: str,
    ) -> str:

        if not hostname:
            return "unknown"

        try:
            address = ipaddress.ip_address(hostname)

            if address.version == 4:
                return "ipv4"

            if address.version == 6:
                return "ipv6"

        except ValueError:
            pass

        return "domain"

    # =========================================================
    # SUBDOMAINS
    # =========================================================

    def _get_subdomain_count(
        self,
        hostname: str,
        hostname_type: str,
    ) -> int:

        if hostname_type != "domain":
            return 0

        parts = [
            part
            for part in hostname.split(".")
            if part
        ]

        return max(
            0,
            len(parts) - 2,
        )

    # =========================================================
    # KEYWORDS
    # =========================================================

    def _find_keywords(
        self,
        url: str,
    ) -> list[str]:

        url_lower = url.lower()

        found = []

        for keyword in SUSPICIOUS_KEYWORDS:

            pattern = (
                rf"(?<![a-z0-9])"
                rf"{re.escape(keyword)}"
                rf"(?![a-z0-9])"
            )

            if re.search(
                pattern,
                url_lower,
            ):
                found.append(keyword)

        return found

    # =========================================================
    # QUERY PARAMETERS
    # =========================================================

    def _get_query_parameters(
        self,
        search: str,
    ) -> dict:

        if not search:
            return {}

        return parse_qs(
            search,
            keep_blank_values=True,
        )

    # =========================================================
    # SPECIAL CHARACTERS
    # =========================================================

    def _get_special_character_indicators(
        self,
        hostname: str,
        full_url: str,
    ) -> list[str]:

        indicators = []

        if "@" in full_url:
            indicators.append(
                "at_symbol"
            )

        if "\\" in full_url:
            indicators.append(
                "backslash"
            )

        if "%" in full_url:
            indicators.append(
                "percent_encoding"
            )

        if hostname.count("-") >= 3:
            indicators.append(
                "multiple_hyphens"
            )

        if hostname.count(".") >= 4:
            indicators.append(
                "many_hostname_labels"
            )

        return indicators