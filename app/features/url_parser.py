"""
URL parsing and validation utilities.
"""

import re
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    """
    Normalize URL by adding HTTPS when no protocol is supplied.
    """

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def is_valid_url(url_string: str) -> bool:
    """
    Validate whether the supplied string is a structurally valid URL.
    """

    if not url_string or not url_string.strip():
        return False

    url_string = url_string.strip()

    normalized = normalize_url(url_string)
    result = urlparse(normalized)

    # Must contain a valid scheme and hostname
    if result.scheme not in ("http", "https"):
        return False

    if not result.hostname:
        return False

    hostname = result.hostname

    # Reject whitespace
    if re.search(r"\s", hostname):
        return False

    # Reject malformed hostname characters
    if not re.match(
        r"^[A-Za-z0-9.-]+$",
        hostname,
    ):
        return False

    # Reject invalid hostname structures
    if hostname.startswith(".") or hostname.endswith("."):
        return False

    if ".." in hostname:
        return False

    # IP address validation
    if re.match(
        r"^\d{1,3}(\.\d{1,3}){3}$",
        hostname,
    ):
        parts = hostname.split(".")

        if any(
            int(part) > 255
            for part in parts
        ):
            return False

        return True

    # Normal domain validation
    if "." not in hostname:
        return False

    return True


def parse_url(url_string: str) -> dict:
    """
    Parse URL into normalized components.
    """

    normalized_url = normalize_url(url_string)

    url = urlparse(normalized_url)

    return {
        "full": url.geturl(),
        "hostname": url.hostname or "",
        "protocol": url.scheme or "",
        "pathname": url.path or "",
        "search": url.query or "",
    }