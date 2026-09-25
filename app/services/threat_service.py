"""
External threat intelligence service.

Currently integrates with URLhaus.
"""

import logging
import os

import requests
from dotenv import load_dotenv


# Load variables from .env
load_dotenv()


logger = logging.getLogger(__name__)


class ThreatService:
    """
    Threat intelligence service using URLhaus.
    """

    def __init__(self):

        self.api_url = os.getenv(
            "URLHAUS_API_URL",
            "https://urlhaus-api.abuse.ch/v1/url/",
        )

        self.auth_key = os.getenv(
            "URLHAUS_AUTH_KEY"
        )

    def check_url(self, url: str) -> dict:
        """
        Check URL against URLhaus.
        """

        # ==========================================
        # 1. Check API key configuration
        # ==========================================

        if not self.auth_key:

            logger.error(
                "URLhaus Auth Key is not configured."
            )

            return {
                "is_phishing": False,
                "threat": None,
                "last_analysis": None,
                "api_error": True,
                "error": (
                    "URLHAUS_AUTH_KEY is not configured"
                ),
            }

        # ==========================================
        # 2. Prepare request
        # ==========================================

        headers = {
            "Auth-Key": self.auth_key,
        }

        data = {
            "url": url,
        }

        # ==========================================
        # 3. Send request to URLhaus
        # ==========================================

        try:

            response = requests.post(
                self.api_url,
                headers=headers,
                data=data,
                timeout=30,
            )

            # ======================================
            # 4. Handle HTTP errors
            # ======================================

            if response.status_code != 200:

                logger.error(
                    "URLhaus API returned HTTP %s: %s",
                    response.status_code,
                    response.text,
                )

            response.raise_for_status()

            # ======================================
            # 5. Parse response
            # ======================================

            result = response.json()

            query_status = result.get(
                "query_status"
            )

            # ======================================
            # 6. URL found in URLhaus
            # ======================================

            if query_status == "ok":

                return {
                    "is_phishing": True,
                    "threat": result,
                    "last_analysis": result.get(
                        "last_analysis_date"
                    ),
                    "api_error": False,
                }

            # ======================================
            # 7. URL not found
            # ======================================

            if query_status == "no_results":

                return {
                    "is_phishing": False,
                    "threat": None,
                    "last_analysis": None,
                    "api_error": False,
                }

            # ======================================
            # 8. Unknown API response
            # ======================================

            logger.warning(
                "Unexpected URLhaus response: %s",
                result,
            )

            return {
                "is_phishing": False,
                "threat": None,
                "last_analysis": None,
                "api_error": False,
            }

        # ==========================================
        # 9. Request/API error
        # ==========================================

        except requests.RequestException as exc:

            logger.error(
                "URLhaus API error: %s",
                exc,
            )

            return {
                "is_phishing": False,
                "threat": None,
                "last_analysis": None,
                "api_error": True,
            }

        # ==========================================
        # 10. JSON/other unexpected error
        # ==========================================

        except Exception as exc:

            logger.exception(
                "Unexpected URLhaus error: %s",
                exc,
            )

            return {
                "is_phishing": False,
                "threat": None,
                "last_analysis": None,
                "api_error": True,
            }