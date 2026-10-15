from app.features.url_parser import (
    normalize_url,
    parse_url,
)

from app.features.evidence_builder import (
    EvidenceBuilder,
)


builder = EvidenceBuilder()

test_urls = [
    "https://google.com",
    "http://192.168.1.10/verify-login-urgent-confirm",
]

for original_url in test_urls:

    print("\n" + "=" * 70)
    print("URL:", original_url)
    print("=" * 70)

    normalized = normalize_url(
        original_url
    )

    parsed = parse_url(
        normalized
    )

    evidence = builder.build(
        parsed,
        {
            "checked": True,
            "listed": False,
            "source": "URLhaus",
        },
    )

    print(evidence)
    