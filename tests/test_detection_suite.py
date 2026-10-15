"""
Comprehensive detection test suite.

Tests the complete AI phishing detection pipeline
against multiple URL categories.
"""

from pprint import pprint

from app.services.ai_analysis_service import AIAnalysisService


service = AIAnalysisService()


TEST_CASES = [
    {
        "name": "Known Safe Domain",
        "url": "https://google.com",
        "expected": "safe",
    },
    {
        "name": "Safe Example Domain",
        "url": "https://example.com",
        "expected": "safe",
    },
    {
        "name": "HTTP Login Page",
        "url": "http://example.com/login",
        "expected": "suspicious",
    },
    {
        "name": "IP Address + Phishing Keywords",
        "url": (
            "http://192.168.1.10/"
            "verify-login-urgent-confirm"
        ),
        "expected": "suspicious",
    },
    {
        "name": "Suspicious Verification Domain",
        "url": (
            "https://secure-login-verification-example.com/"
            "verify-account"
        ),
        "expected": "suspicious",
    },
    {
        "name": "Multiple Subdomains",
        "url": (
            "https://login.account.security.example.com/"
            "confirm"
        ),
        "expected": "suspicious",
    },
    {
        "name": "Long URL With Query Parameters",
        "url": (
            "https://example.com/"
            "verify-account?"
            "user=test&"
            "session=123456789&"
            "redirect=https://example.com/login"
        ),
        "expected": "suspicious",
    },
]


INVALID_URLS = [
    "",
    "not-a-url",
    "http://",
    "https://",
    "example",
]


def print_separator():
    print("=" * 90)


def run_detection_tests():

    print()
    print_separator()
    print("AI PHISHING DETECTION TEST SUITE")
    print_separator()

    total = len(TEST_CASES)
    passed = 0
    failed = 0

    for index, case in enumerate(TEST_CASES, start=1):

        print()
        print(f"TEST {index}/{total}")
        print("-" * 90)
        print(f"NAME     : {case['name']}")
        print(f"URL      : {case['url']}")
        print(f"EXPECTED : {case['expected']}")

        try:

            result = service.analyze(
                case["url"],
                check_threat_intelligence=True,
            )

            analysis = result["analysis"]

            actual = analysis["verdict"]
            risk_score = analysis["risk_score"]
            confidence = analysis["confidence"]

            print(f"ACTUAL   : {actual}")
            print(f"RISK     : {risk_score}/100")
            print(f"CONFIDENCE: {confidence}")

            # --------------------------------------
            # Flexible validation
            # --------------------------------------

            if case["expected"] == "safe":

                test_passed = actual == "safe"

            elif case["expected"] == "suspicious":

                test_passed = actual in {
                    "suspicious",
                    "phishing",
                }

            else:

                test_passed = False

            if test_passed:

                print("RESULT   : PASS")
                passed += 1

            else:

                print("RESULT   : FAIL")
                failed += 1

            print()
            print("SUMMARY")
            print(analysis["summary"])

            print()
            print("INDICATORS")

            for indicator in analysis.get(
                "indicators",
                [],
            ):

                print(
                    f"  [{indicator['severity'].upper()}] "
                    f"{indicator['name']}: "
                    f"{indicator['reason']}"
                )

            print()
            print("THREAT INTELLIGENCE")

            pprint(
                result.get(
                    "threat_intelligence"
                )
            )

        except Exception as exc:

            print("RESULT   : ERROR")
            print(
                f"{type(exc).__name__}: {exc}"
            )

            failed += 1

    # ==========================================
    # Invalid URL tests
    # ==========================================

    print()
    print_separator()
    print("INVALID URL VALIDATION TESTS")
    print_separator()

    invalid_passed = 0
    invalid_failed = 0

    for url in INVALID_URLS:

        print()
        print(f"URL: {repr(url)}")

        try:

            service.analyze(
                url,
                check_threat_intelligence=False,
            )

            print(
                "RESULT: FAIL "
                "(invalid URL was accepted)"
            )

            invalid_failed += 1

        except ValueError:

            print(
                "RESULT: PASS "
                "(invalid URL rejected)"
            )

            invalid_passed += 1

        except Exception as exc:

            print(
                "RESULT: ERROR "
                f"({type(exc).__name__})"
            )

            invalid_failed += 1

    # ==========================================
    # Final report
    # ==========================================

    print()
    print_separator()
    print("FINAL TEST REPORT")
    print_separator()

    print(
        f"Detection tests : "
        f"{passed} passed / {failed} failed"
    )

    print(
        f"Validation tests: "
        f"{invalid_passed} passed / "
        f"{invalid_failed} failed"
    )

    total_passed = (
        passed +
        invalid_passed
    )

    total_failed = (
        failed +
        invalid_failed
    )

    print()
    print(
        f"TOTAL PASSED: {total_passed}"
    )

    print(
        f"TOTAL FAILED: {total_failed}"
    )

    if total_failed == 0:

        print()
        print("STATUS: ALL TESTS PASSED")

    else:

        print()
        print(
            "STATUS: SOME TESTS REQUIRE REVIEW"
        )

    print_separator()


if __name__ == "__main__":
    run_detection_tests()