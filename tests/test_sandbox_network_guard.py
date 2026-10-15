
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from app.services.sandbox_service import _guard_network_route


def test_unsafe_url_is_blocked_by_real_guard(monkeypatch):
    monkeypatch.setattr(
        "app.services.sandbox_service._is_safe_public_http_url",
        lambda url: False,
    )

    route = SimpleNamespace(
        request=SimpleNamespace(
            url="http://127.0.0.1",
            resource_type="document",
        ),
        abort=AsyncMock(),
        continue_=AsyncMock(),
    )
    session = SimpleNamespace(add_network_event=Mock())

    asyncio.run(_guard_network_route(route, session))

    route.abort.assert_awaited_once_with("blockedbyclient")
    route.continue_.assert_not_awaited()
    session.add_network_event.assert_called_once_with(
        "blocked_non_public_network_request",
        {
            "url": "http://127.0.0.1",
            "resource_type": "document",
        },
        threat_weight=0,
    )


def test_safe_url_is_allowed_by_real_guard(monkeypatch):
    monkeypatch.setattr(
        "app.services.sandbox_service._is_safe_public_http_url",
        lambda url: True,
    )

    route = SimpleNamespace(
        request=SimpleNamespace(
            url="https://example.com",
            resource_type="document",
        ),
        abort=AsyncMock(),
        continue_=AsyncMock(),
    )
    session = SimpleNamespace(add_network_event=Mock())

    asyncio.run(_guard_network_route(route, session))

    route.continue_.assert_awaited_once()
    route.abort.assert_not_awaited()
    session.add_network_event.assert_not_called()
