"""
Compatibility layer for the original URL analyzer.

The actual implementation now lives inside app/.
"""

from app.features.url_parser import (
    is_valid_url,
    normalize_url,
    parse_url,
)

from app.services.analysis_service import (
    AnalysisService,
)


_analysis_service = AnalysisService()


def analyze_url(url: str) -> dict:
    """
    Backward-compatible wrapper around AnalysisService.
    """

    result = _analysis_service.analyze(url)

    result.pop("url", None)

    return result