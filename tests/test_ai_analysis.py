from pprint import pprint

from app.services.ai_analysis_service import (
    AIAnalysisService,
)


service = AIAnalysisService()


test_urls = [
    "https://google.com",
    "http://192.168.1.10/verify-login-urgent-confirm",
]


for url in test_urls:

    print("\n")
    print("=" * 80)
    print("ANALYZING:")
    print(url)
    print("=" * 80)

    try:

        result = service.analyze(
            url,
            check_threat_intelligence=True,
        )

        print("\nAI ANALYSIS")
        print("-" * 80)

        pprint(
            result["analysis"]
        )

        print("\nEVIDENCE")
        print("-" * 80)

        pprint(
            result["evidence"]
        )

        print("\nTHREAT INTELLIGENCE")
        print("-" * 80)

        pprint(
            result["threat_intelligence"]
        )

    except Exception as exc:

        print("\nERROR")
        print("-" * 80)
        print(type(exc).__name__)
        print(str(exc))