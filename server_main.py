from app.features.url_parser import is_valid_url
"""
URL Phishing Detector Server

Frontend
   ↓
Flask API
   ↓
AIAnalysisService
   ↓
Evidence Builder
   ↓
URLhaus
   ↓
Ollama LLM
   ↓
AI Safety Validator
   ↓
AI Output Sanitizer
"""

import logging
import os
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from app.services.ai_analysis_service import AIAnalysisService


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

CORS(app)

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    "dev-key-change-in-production",
)

app.config["JSON_SORT_KEYS"] = False


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


# ============================================================
# AI SERVICE
# ============================================================

ai_analysis_service = AIAnalysisService()


# ============================================================
# FRONTEND
# ============================================================

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_verdict(value):
    """
    Normalize AI verdict so frontend CSS/JS
    receives predictable values.
    """

    if not isinstance(value, str):
        return "suspicious"

    verdict = value.strip().lower()

    # Keep the canonical AI verdicts.
    # The frontend maps "phishing" to its unsafe presentation.
    allowed = {
        "safe",
        "suspicious",
        "phishing",
    }

    if verdict == "malicious":
        return "phishing"

    if verdict not in allowed:
        return "suspicious"

    return verdict


def normalize_risk_score(value):
    """
    Convert risk score into integer 0-100.
    """

    try:
        value = int(float(value))
    except (TypeError, ValueError):
        value = 0

    return max(
        0,
        min(
            100,
            value,
        ),
    )


def normalize_confidence(value):
    """
    Convert confidence into float 0.0-1.0.
    """

    try:
        value = float(value)
    except (TypeError, ValueError):
        value = 0.0

    return max(
        0.0,
        min(
            1.0,
            value,
        ),
    )


def build_frontend_checks(
    evidence,
    analysis,
):
    """
    Convert backend evidence into the seven core
    security checks displayed by the frontend.

    Seven security layers:

        1. SSL/TLS Encryption
        2. Subdomain Count
        3. IP Address Detection
        4. Domain Length
        5. Special Characters
        6. Suspicious Keywords
        7. URL Length

    Threat intelligence remains available separately
    in the API response and evidence.
    """

    checks = []

    # ========================================================
    # DATA
    # ========================================================

    protocol = evidence.get(
        "protocol",
        {},
    )

    hostname = evidence.get(
        "hostname",
        {},
    )

    hostname_value = hostname.get(
        "value",
        "",
    )

    hostname_length = hostname.get(
        "length",
        0,
    )

    hostname_type = hostname.get(
        "type",
        "unknown",
    )

    subdomain_count = hostname.get(
        "subdomain_count",
        0,
    )

    suspicious_keywords = evidence.get(
        "suspicious_keywords",
        [],
    )

    special_indicators = evidence.get(
        "special_character_indicators",
        [],
    )

    url_length = evidence.get(
        "url_length",
        0,
    )

    # ========================================================
    # CHECK 1 — SSL/TLS ENCRYPTION
    # ========================================================

    if protocol.get("is_https"):

        checks.append({
            "name": "SSL/TLS Encryption",
            "description": (
                "The URL uses HTTPS encryption."
            ),
            "status": "pass",
        })

    elif protocol.get("is_http"):

        checks.append({
            "name": "SSL/TLS Encryption",
            "description": (
                "The URL uses unencrypted HTTP "
                "instead of HTTPS."
            ),
            "status": "fail",
        })

    else:

        checks.append({
            "name": "SSL/TLS Encryption",
            "description": (
                "The URL does not use a recognized "
                "secure HTTPS protocol."
            ),
            "status": "warn",
        })

    # ========================================================
    # CHECK 2 — SUBDOMAIN COUNT
    # ========================================================

    if hostname_type in {
        "ipv4",
        "ipv6",
    }:

        checks.append({
            "name": "Subdomain Count",
            "description": (
                "Subdomain analysis is not applicable "
                "because the hostname is an IP address."
            ),
            "status": "pass",
        })

    elif subdomain_count >= 3:

        checks.append({
            "name": "Subdomain Count",
            "description": (
                f"The hostname contains "
                f"{subdomain_count} subdomain levels, "
                "which may indicate suspicious hosting."
            ),
            "status": "warn",
        })

    else:

        checks.append({
            "name": "Subdomain Count",
            "description": (
                f"The hostname contains "
                f"{subdomain_count} subdomain level(s), "
                "which is within a normal range."
            ),
            "status": "pass",
        })

    # ========================================================
    # CHECK 3 — IP ADDRESS DETECTION
    # ========================================================

    if hostname_type in {
        "ipv4",
        "ipv6",
    }:

        checks.append({
            "name": "IP Address Detection",
            "description": (
                f"The hostname '{hostname_value}' "
                "is an IP address instead of a "
                "conventional domain name."
            ),
            "status": "fail",
        })

    else:

        checks.append({
            "name": "IP Address Detection",
            "description": (
                f"The hostname '{hostname_value}' "
                "uses a conventional domain name."
            ),
            "status": "pass",
        })

    # ========================================================
    # CHECK 4 — DOMAIN LENGTH
    # ========================================================

    if hostname_length < 4:

        checks.append({
            "name": "Domain Length",
            "description": (
                f"The hostname is only "
                f"{hostname_length} characters long, "
                "which is unusually short."
            ),
            "status": "warn",
        })

    elif hostname_length > 50:

        checks.append({
            "name": "Domain Length",
            "description": (
                f"The hostname is "
                f"{hostname_length} characters long, "
                "which is unusually long."
            ),
            "status": "warn",
        })

    else:

        checks.append({
            "name": "Domain Length",
            "description": (
                f"The hostname '{hostname_value}' "
                f"has a standard length of "
                f"{hostname_length} characters."
            ),
            "status": "pass",
        })

    # ========================================================
    # CHECK 5 — SPECIAL CHARACTERS / URL STRUCTURE
    # ========================================================

    if special_indicators:

        readable = ", ".join(
            special_indicators
        )

        checks.append({
            "name": "Special Characters",
            "description": (
                "The URL contains notable structural "
                f"indicators: {readable}."
            ),
            "status": "warn",
        })

    else:

        checks.append({
            "name": "Special Characters",
            "description": (
                "No unusual special-character or "
                "structural indicators were identified."
            ),
            "status": "pass",
        })

    # ========================================================
    # CHECK 6 — SUSPICIOUS KEYWORDS
    # ========================================================

    if suspicious_keywords:

        keywords_text = ", ".join(
            suspicious_keywords
        )

        if len(suspicious_keywords) >= 2:
            status = "warn"
        else:
            status = "warn"

        checks.append({
            "name": "Suspicious Keywords",
            "description": (
                "The URL contains suspicious keywords: "
                f"{keywords_text}."
            ),
            "status": status,
        })

    else:

        checks.append({
            "name": "Suspicious Keywords",
            "description": (
                "No common phishing-related "
                "keywords were identified in the URL."
            ),
            "status": "pass",
        })

    # ========================================================
    # CHECK 7 — URL LENGTH
    # ========================================================

    if url_length > 100:

        checks.append({
            "name": "URL Length",
            "description": (
                f"The URL is {url_length} characters long, "
                "which may indicate hidden parameters "
                "or obfuscated content."
            ),
            "status": "warn",
        })

    else:

        checks.append({
            "name": "URL Length",
            "description": (
                f"The URL length is {url_length} characters, "
                "which is within a reasonable range."
            ),
            "status": "pass",
        })

    # ========================================================
    # SAFETY: GUARANTEE EXACTLY 7 CORE CHECKS
    # ========================================================

    return checks[:7]

# ============================================================
# AI ANALYSIS API
# ============================================================

@app.route("/api/analyze", methods=["POST"])
def api_analyze():

    try:

        # ----------------------------------------------------
        # REQUEST DATA
        # ----------------------------------------------------

        data = request.get_json(
            silent=True
        ) or {}

        url = str(
            data.get(
                "url",
                "",
            )
        ).strip()

        # ----------------------------------------------------
        # INPUT VALIDATION
        # ----------------------------------------------------

        if not url:

            return jsonify({
                "status": "error",
                "error": "Please enter a URL",
            }), 400

        if not is_valid_url(url):

            return jsonify({
                "status": "error",
                "error": "Invalid URL",
            }), 400

        logger.info(
            "Starting AI analysis: %s",
            url,
        )

        # ----------------------------------------------------
        # AI PIPELINE
        # ----------------------------------------------------

        result = ai_analysis_service.analyze(
            url,
            check_threat_intelligence=True,
        )

        # ----------------------------------------------------
        # EXTRACT RESULTS
        # ----------------------------------------------------

        analysis = result.get(
            "analysis",
            {},
        )

        evidence = result.get(
            "evidence",
            {},
        )

        threat_intelligence = result.get(
            "threat_intelligence",
            {},
        )

        # ----------------------------------------------------
        # NORMALIZE VALUES
        # ----------------------------------------------------

        verdict = normalize_verdict(
            analysis.get(
                "verdict",
                "suspicious",
            )
        )

        risk_score = normalize_risk_score(
            analysis.get(
                "risk_score",
                0,
            )
        )

        confidence = normalize_confidence(
            analysis.get(
                "confidence",
                0,
            )
        )

        summary = analysis.get(
            "summary",
            "",
        )

        recommendation = analysis.get(
            "recommendation",
            "",
        )

        indicators = analysis.get(
            "indicators",
            [],
        )

        validation = analysis.get(
            "validation",
            {},
        )

        # ----------------------------------------------------
        # FRONTEND SECURITY CHECKS
        # ----------------------------------------------------

        checks = build_frontend_checks(
            evidence,
            analysis,
        )

        # ----------------------------------------------------
        # FINAL RESPONSE
        # ----------------------------------------------------

        response_data = {

            "status": "ok",

            # ------------------------------------------------
            # URL
            # ------------------------------------------------

            "url": result.get(
                "url",
                url,
            ),

            # ------------------------------------------------
            # Safety is the inverse of risk.
            "safety_score": 100 - risk_score,

            "risk_score": risk_score,

            # ------------------------------------------------
            # Verdict
            # ------------------------------------------------

            "verdict": verdict,

            # ------------------------------------------------
            # AI confidence
            # ------------------------------------------------

            "confidence": confidence,

            # ------------------------------------------------
            # AI explanation
            # ------------------------------------------------

            "summary": summary,

            "recommendation": recommendation,

            "indicators": indicators,

            "validation": validation,

            # ------------------------------------------------
            # Frontend checks
            # ------------------------------------------------

            "checks": checks,

            # ------------------------------------------------
            # Full analysis
            # ------------------------------------------------

            "analysis": {

                "verdict": verdict,

                "risk_score": risk_score,

                "safety_score": 100 - risk_score,

                "confidence": confidence,

                "summary": summary,

                "recommendation": recommendation,

                "indicators": indicators,

                "validation": validation,
            },

            # ------------------------------------------------
            # Evidence
            # ------------------------------------------------

            "evidence": evidence,

            # ------------------------------------------------
            # Threat intelligence
            # ------------------------------------------------

            "threat_intelligence": (
                threat_intelligence
            ),

            # ------------------------------------------------
            # Timestamp
            # ------------------------------------------------

            "timestamp": (
                datetime.now().isoformat()
            ),
        }

        logger.info(
            "Analysis completed | "
            "verdict=%s | "
            "risk_score=%s | "
            "confidence=%s",
            verdict,
            risk_score,
            confidence,
        )

        return jsonify(
            response_data
        )

    # ========================================================
    # INVALID URL
    # ========================================================

    except ValueError as exc:

        logger.warning(
            "Invalid URL: %s",
            exc,
        )

        return jsonify({
            "status": "error",
            "error": str(exc),
        }), 400

    # ========================================================
    # AI SERVICE ERROR
    # ========================================================

    except RuntimeError as exc:

        logger.exception(
            "AI service error",
        )

        return jsonify({
            "status": "error",
            "error": str(exc),
        }), 503

    # ========================================================
    # UNKNOWN ERROR
    # ========================================================

    except Exception as exc:

        logger.exception(
            "Unexpected analysis error",
        )

        return jsonify({
            "status": "error",
            "error": "Analysis service failed",
        }), 500


# ============================================================
# HEALTH
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"],
)
def api_health():

    return jsonify({

        "status": "ok",

        "service": "URL Phishing Detector",

        "version": "2.0.0",

        "ai_pipeline": True,

        "ollama": check_ollama_health(),

        "threat_intelligence": bool(
            ai_analysis_service.threat_service.auth_key
        ),

        "timestamp": (
            datetime.now().isoformat()
        ),
    })


# ============================================================
# STATS
# ============================================================

@app.route(
    "/api/stats",
    methods=["GET"],
)
def api_stats():

    return jsonify({

        "status": "ok",

        "app": "URL Phishing Detector",

        "version": "2.0.0",

        "features": {

            "ai_analysis": True,

            "ollama": True,

            "evidence_builder": True,

            "ai_safety_validation": True,

            "ai_output_sanitization": True,

            "threat_intelligence": True,

            "frontend": True,

            "history_tracking": False,

            "batch_processing": False,
        },
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "status": "error",
        "error": "Endpoint not found",
    }), 404


@app.errorhandler(500)
def server_error(error):

    logger.exception(
        "Internal server error"
    )

    return jsonify({
        "status": "error",
        "error": "Internal server error",
    }), 500


def check_ollama_health():
    """Return True only when the configured Ollama endpoint responds."""
    import requests

    base_url = ai_analysis_service.llm_service.base_url

    try:
        response = requests.get(
            f"{base_url}/api/tags",
            timeout=2,
        )
        return response.ok
    except requests.RequestException:
        return False


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    host = os.getenv(
        "HOST",
        "127.0.0.1",
    )

    port = int(
        os.getenv(
            "PORT",
            "5000",
        )
    )

    debug = (
        os.getenv(
            "FLASK_DEBUG",
            "True",
        ).lower()
        == "true"
    )

    logger.info(
        "Starting URL Phishing Detector"
    )

    logger.info(
        "Host: %s",
        host,
    )

    logger.info(
        "Port: %s",
        port,
    )

    logger.info(
        "AI Pipeline: ENABLED"
    )

    app.run(
        host=host,
        port=port,
        debug=debug,
    )