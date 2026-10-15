import socket

from coverage import context
from requests import session
"""
Controlled browser sandbox for phishing URL analysis.

Uses Playwright (headless Chromium) to visit a URL in a browser context
and collect behavioral evidence.

IMPORTANT: This module provides application-level safeguards only.
Playwright routing and DNS checks do NOT provide complete network or
OS-level isolation and cannot fully prevent DNS-rebinding/TOCTOU attacks.
For untrusted URLs, run this service in a dedicated container or VM with
outbound network restrictions that block private, loopback, link-local,
and metadata-service destinations.

Limits enforced:
- Navigation timeout
- Maximum redirect hops
- Maximum number of requests captured
- Network requests to non-public destinations are blocked as a defense-in-depth check
- Downloads are restricted
- Session terminated when cumulative threat score reaches threshold
"""

import asyncio
import base64
import ipaddress
import logging
import os
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    Route,
    async_playwright,
)


logger = logging.getLogger(__name__)


# ============================================================
# LIMITS
# ============================================================

# Seconds before the browser session is force-terminated.
DEFAULT_TIMEOUT_SECONDS = int(
    os.getenv("SANDBOX_TIMEOUT", "15")
)

# Maximum redirect hops before terminating.
MAX_REDIRECTS = int(
    os.getenv("SANDBOX_MAX_REDIRECTS", "5")
)

# Maximum network requests captured (prevents runaway sites).
MAX_REQUESTS = int(
    os.getenv("SANDBOX_MAX_REQUESTS", "150")
)

# Cumulative threat-score threshold: terminate session immediately.
TERMINATE_THRESHOLD = int(
    os.getenv("SANDBOX_TERMINATE_THRESHOLD", "80")
)

# Screen dimensions for the headless browser.
VIEWPORT_WIDTH = 1280
VIEWPORT_HEIGHT = 800


class SandboxTerminated(Exception):
    """Raised when the sandbox terminates a session early."""


def _is_non_public_ip(address: str) -> bool:
    """Return True for IP addresses that should not be publicly reachable."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False

    return not ip.is_global



def _is_safe_public_http_url(url: str) -> bool:
    """Return whether an HTTP(S) URL currently resolves only to public IPs.

    This is a defense-in-depth check, not a complete SSRF/DNS-rebinding
    defense: the browser resolves the hostname separately after this check.
    Enforce outbound network restrictions at the OS/container/firewall layer
    when visiting untrusted URLs.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return False

        hostname = parsed.hostname.rstrip(".").lower()
        if not hostname or hostname == "localhost" or hostname.endswith((".localhost", ".local")):
            return False

        # If it is an IP literal, classify it directly without DNS.
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            try:
                records = socket.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                )
            except (OSError, UnicodeError, ValueError):
                # Fail closed if DNS cannot be resolved.
                return False

            addresses = {record[4][0] for record in records if record and record[4]}
            if not addresses:
                return False
            return all(not _is_non_public_ip(address) for address in addresses)

        return not _is_non_public_ip(hostname)
    except (TypeError, ValueError, UnicodeError):
        return False


async def _guard_network_route(route: Route, session) -> None:
    """Block requests to non-public destinations."""
    request = route.request

    is_safe = await asyncio.to_thread(
        _is_safe_public_http_url,
        request.url,
    )

    if not is_safe:
        session.add_network_event(
            "blocked_non_public_network_request",
            {
                "url": request.url,
                "resource_type": request.resource_type,
            },
            threat_weight=0,
        )
        await route.abort("blockedbyclient")
        return

    await route.continue_()



class SandboxService:
    """
    Visits a URL inside an isolated Playwright browser context
    and returns a structured event log with screenshots.

    The caller is responsible for deciding whether to run
    the sandbox (based on the pre-scan risk score).
    """

    def run(self, url: str) -> dict:
        """
        Synchronous entry point — runs the async sandbox in
        a dedicated event loop so Flask (sync) can call it.
        """
        return asyncio.run(self._run_async(url))

    # =========================================================
    # ASYNC CORE
    # =========================================================

    async def _run_async(self, url: str) -> dict:

        session = _SandboxSession(url)

        async with async_playwright() as playwright:
            browser: Browser = (
                await playwright.chromium.launch(
                    headless=True,
                    args=[
                        # Disable features that can leak resources
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-extensions",
                        "--disable-background-networking",
                        "--disable-sync",
                        "--disable-translate",
                        "--disable-default-apps",
                        "--mute-audio",
                        "--no-first-run",
                        "--safebrowsing-disable-auto-update",
                    ],
                )
            )

            context: BrowserContext = (
                await browser.new_context(
                    viewport={
                        "width": VIEWPORT_WIDTH,
                        "height": VIEWPORT_HEIGHT,
                    },
                    # Spoof a realistic user-agent
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    ),
                    # Block all downloads unconditionally
                    accept_downloads=False,
                    # Restrict permissions
                    permissions=[],
                    # Disable geolocation
                    geolocation=None,
                    # No stored credentials
                    http_credentials=None,
                    # Strict same-origin JavaScript API
                    java_script_enabled=True,
                    bypass_csp=False,
                )
            )

            # Defense-in-depth request guard. It checks every HTTP(S) request,
            # including redirects and subresources, before allowing it through.
            
            async def guard_network_route(route: Route) -> None:
                await _guard_network_route(route, session)

            await context.route("**/*", guard_network_route)


            page: Page = await context.new_page()

            # -------------------------------------------------
            # Attach event listeners
            # -------------------------------------------------

            self._attach_listeners(page, context, session)

            # -------------------------------------------------
            # Navigate with timeout guard
            # -------------------------------------------------

            try:
                await asyncio.wait_for(
                    self._navigate_and_observe(
                        page,
                        context,
                        session,
                        url,
                    ),
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )

            except asyncio.TimeoutError:
                session.add_browser_event(
                    "session_timeout",
                    {
                        "message": (
                            f"Session terminated after "
                            f"{DEFAULT_TIMEOUT_SECONDS}s timeout."
                        )
                    },
                    threat_weight=0,
                )

            except SandboxTerminated as exc:
                session.add_browser_event(
                    "session_terminated",
                    {"reason": str(exc)},
                    threat_weight=0,
                )

            except Exception as exc:
                logger.warning(
                    "Sandbox navigation error: %s",
                    exc,
                )
                session.add_browser_event(
                    "navigation_error",
                    {"error": str(exc)},
                    threat_weight=0,
                )

            finally:
                # Always capture a final screenshot
                try:
                    screenshot_b64 = await page.screenshot(
                        type="png",
                        full_page=False,
                    )
                    session.screenshot_b64 = base64.b64encode(
                        screenshot_b64
                    ).decode("utf-8")

                except Exception as exc:
                    logger.warning(
                        "Screenshot capture failed: %s",
                        exc,
                    )

                try:
                    await context.close()
                except Exception as exc:
                    logger.warning("Browser context cleanup failed: %s", exc)
                finally:
                    try:
                        await browser.close()
                    except Exception as exc:
                        logger.warning("Browser cleanup failed: %s", exc)

        return session.to_dict()

    # =========================================================
    # NAVIGATION
    # =========================================================

    async def _navigate_and_observe(
        self,
        page: Page,
        context: BrowserContext,
        session: "_SandboxSession",
        url: str,
    ) -> None:

        try:
            response = await page.goto(
                url,
                timeout=DEFAULT_TIMEOUT_SECONDS * 1000,
                wait_until="domcontentloaded",
            )

            if response:
                session.add_network_event(
                    "initial_response",
                    {
                        "status": response.status,
                        "url": response.url,
                        "headers": dict(
                            response.headers
                        ),
                    },
                    threat_weight=0,
                )

        except Exception as exc:
            session.add_page_event(
                "navigation_failed",
                {"error": str(exc)},
                threat_weight=5,
            )
            return

        # Let the page settle briefly
        await asyncio.sleep(2)

        # Inspect page content for suspicious patterns
        await self._inspect_page(page, session)

    # =========================================================
    # PAGE INSPECTION
    # =========================================================

    async def _inspect_page(
        self,
        page: Page,
        session: "_SandboxSession",
    ) -> None:
        """
        Inspect the rendered page for phishing indicators.
        All detections here are deterministic rule checks.
        """

        try:
            title = await page.title()
            session.page_title = title

            if title:
                session.add_page_event(
                    "page_title",
                    {"title": title},
                    threat_weight=0,
                )

        except Exception:
            pass

        # --------------------------------------------------
        # Rule: password input on page
        # --------------------------------------------------

        try:
            password_fields = await page.query_selector_all(
                "input[type='password']"
            )

            if password_fields:
                session.add_page_event(
                    "password_field_detected",
                    {"count": len(password_fields)},
                    threat_weight=30,
                )

        except Exception:
            pass

        # --------------------------------------------------
        # Rule: hidden iframes (clickjacking)
        # --------------------------------------------------

        try:
            iframes = await page.query_selector_all("iframe")
            hidden_iframes = []

            for iframe in iframes:
                style = await iframe.get_attribute("style") or ""
                src = await iframe.get_attribute("src") or ""

                if (
                    "display:none" in style.replace(" ", "")
                    or "visibility:hidden" in style.replace(" ", "")
                    or "opacity:0" in style.replace(" ", "")
                ):
                    hidden_iframes.append(src)

            if hidden_iframes:
                session.add_page_event(
                    "hidden_iframe_detected",
                    {"srcs": hidden_iframes},
                    threat_weight=35,
                )

        except Exception:
            pass

        # --------------------------------------------------
        # Rule: suspicious form action destinations
        # --------------------------------------------------

        try:
            forms = await page.query_selector_all("form")
            original_host = urlparse(
                session.url
            ).hostname or ""

            for form in forms:
                action = await form.get_attribute("action") or ""

                if action.startswith("http"):
                    form_host = (
                        urlparse(action).hostname or ""
                    )

                    if (
                        form_host
                        and form_host != original_host
                    ):
                        session.add_page_event(
                            "cross_origin_form_detected",
                            {
                                "action": action,
                                "original_host": original_host,
                                "form_host": form_host,
                            },
                            threat_weight=40,
                        )

        except Exception:
            pass

        # --------------------------------------------------
        # Rule: obfuscated script tags (eval/atob/unescape)
        # --------------------------------------------------

        try:
            scripts = await page.query_selector_all("script")
            obfuscation_patterns = [
                "eval(",
                "unescape(",
                "atob(",
                "fromCharCode(",
                "String.fromCharCode",
            ]

            for script in scripts:
                content = await script.inner_text()
                matches = [
                    pat
                    for pat in obfuscation_patterns
                    if pat in content
                ]

                if matches:
                    session.add_page_event(
                        "obfuscated_script_detected",
                        {"patterns": matches},
                        threat_weight=25,
                    )
                    break  # One detection is enough

        except Exception:
            pass

        # --------------------------------------------------
        # Rule: clipboard access
        # --------------------------------------------------

        try:
            clipboard_access = await page.evaluate(
                """
                () => {
                    let detected = false;
                    const orig = navigator.clipboard;
                    if (orig && orig.readText) {
                        detected = true;
                    }
                    return detected;
                }
                """
            )

            if clipboard_access:
                # This is a weak signal — only note it
                session.add_page_event(
                    "clipboard_api_present",
                    {},
                    threat_weight=5,
                )

        except Exception:
            pass

        # --------------------------------------------------
        # Enforce terminate threshold
        # --------------------------------------------------

        session.check_terminate_threshold()

    # =========================================================
    # EVENT LISTENERS
    # =========================================================

    def _attach_listeners(
        self,
        page: Page,
        context: BrowserContext,
        session: "_SandboxSession",
    ) -> None:

        # ---- Network request --------------------------------

        async def on_request(req: Request) -> None:

            if len(session.network_events) >= MAX_REQUESTS:
                return

            resource_type = req.resource_type

            # Block download-type requests
            if resource_type in {
                "download",
                "blob",
            }:
                session.add_network_event(
                    "blocked_download",
                    {
                        "url": req.url,
                        "resource_type": resource_type,
                    },
                    threat_weight=50,
                )
                try:
                    await req.abort()
                except Exception:
                    pass
                return

            session.add_network_event(
                "request",
                {
                    "url": req.url,
                    "method": req.method,
                    "resource_type": resource_type,
                },
                threat_weight=0,
            )

            session.check_terminate_threshold()

        # ---- Network response --------------------------------

        async def on_response(resp: Response) -> None:

            # Track content-disposition headers (file downloads)
            cd = resp.headers.get(
                "content-disposition", ""
            ).lower()

            if "attachment" in cd:
                session.add_network_event(
                    "download_attempt",
                    {
                        "url": resp.url,
                        "content_disposition": cd,
                    },
                    threat_weight=60,
                )
                session.check_terminate_threshold()

        # ---- Redirect tracking --------------------------------

        async def on_request_finished(req: Request) -> None:

            resp = await req.response()
            if not resp:
                return

            if resp.status in (301, 302, 303, 307, 308):
                session.redirect_count += 1
                location = resp.headers.get("location", "")

                session.add_network_event(
                    "redirect",
                    {
                        "from": req.url,
                        "to": location,
                        "status": resp.status,
                        "hop": session.redirect_count,
                    },
                    threat_weight=3,
                )

                if session.redirect_count >= MAX_REDIRECTS:
                    session.add_network_event(
                        "redirect_limit_reached",
                        {
                            "count": session.redirect_count,
                            "limit": MAX_REDIRECTS,
                        },
                        threat_weight=20,
                    )
                    session.check_terminate_threshold()

        # ---- Popup / new page --------------------------------

        async def on_page(new_page: Page) -> None:
            session.add_browser_event(
                "popup_opened",
                {"url": new_page.url},
                threat_weight=20,
            )
            session.check_terminate_threshold()
            # Close immediately — do not follow popups
            try:
                await new_page.close()
            except Exception:
                pass

        # ---- Dialog (alert/confirm/prompt) ------------------

        async def on_dialog(dialog) -> None:
            session.add_browser_event(
                "dialog_triggered",
                {
                    "type": dialog.type,
                    "message": dialog.message[:200],
                },
                threat_weight=15,
            )
            # Dismiss unconditionally
            try:
                await dialog.dismiss()
            except Exception:
                pass

        # ---- Navigation (frame navigations) -----------------

        async def on_navigation(frame) -> None:
            if frame == page.main_frame:
                return  # Handled separately via goto()

            session.add_page_event(
                "sub_frame_navigation",
                {"url": frame.url},
                threat_weight=10,
            )

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfinished", on_request_finished)
        page.on("dialog", on_dialog)
        page.on("framenavigated", on_navigation)
        context.on("page", on_page)


# ============================================================
# SESSION
# ============================================================


class _SandboxSession:
    """
    Accumulates all events, scores, and metadata for one
    sandbox run. Not thread-safe — one session per run.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.ended_at: str | None = None

        self.redirect_count = 0
        self.cumulative_threat_score = 0

        self.network_events: list[dict] = []
        self.browser_events: list[dict] = []
        self.page_events: list[dict] = []

        self.screenshot_b64: str | None = None
        self.page_title: str | None = None

        self.terminated_early = False
        self.termination_reason: str | None = None

    # --------------------------------------------------------

    def _make_event(
        self,
        kind: str,
        data: dict,
        threat_weight: int,
    ) -> dict:

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "data": data,
            "threat_weight": threat_weight,
        }

    # --------------------------------------------------------

    def add_network_event(
        self,
        kind: str,
        data: dict,
        threat_weight: int = 0,
    ) -> None:

        self.cumulative_threat_score += threat_weight
        self.network_events.append(
            self._make_event(kind, data, threat_weight)
        )

    def add_browser_event(
        self,
        kind: str,
        data: dict,
        threat_weight: int = 0,
    ) -> None:

        self.cumulative_threat_score += threat_weight
        self.browser_events.append(
            self._make_event(kind, data, threat_weight)
        )

    def add_page_event(
        self,
        kind: str,
        data: dict,
        threat_weight: int = 0,
    ) -> None:

        self.cumulative_threat_score += threat_weight
        self.page_events.append(
            self._make_event(kind, data, threat_weight)
        )

    # --------------------------------------------------------

    def check_terminate_threshold(self) -> None:
        """
        Raise SandboxTerminated if cumulative threat score
        has reached or exceeded the configured threshold.
        """

        if (
            self.cumulative_threat_score >= TERMINATE_THRESHOLD
            and not self.terminated_early
        ):
            self.terminated_early = True
            self.termination_reason = (
                f"Cumulative threat score "
                f"{self.cumulative_threat_score} reached "
                f"the termination threshold "
                f"{TERMINATE_THRESHOLD}."
            )

            raise SandboxTerminated(self.termination_reason)

    # --------------------------------------------------------

    def to_dict(self) -> dict:

        self.ended_at = datetime.now(timezone.utc).isoformat()

        all_threat_events = [
            ev
            for ev in (
                self.network_events
                + self.browser_events
                + self.page_events
            )
            if ev["threat_weight"] > 0
        ]

        return {
            # ------------------------------------------------
            # Session metadata
            # ------------------------------------------------
            "url": self.url,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "page_title": self.page_title,

            # ------------------------------------------------
            # Execution limits
            # ------------------------------------------------
            "redirect_count": self.redirect_count,
            "max_redirects": MAX_REDIRECTS,
            "max_requests": MAX_REQUESTS,
            "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,

            # ------------------------------------------------
            # Termination
            # ------------------------------------------------
            "terminated_early": self.terminated_early,
            "termination_reason": self.termination_reason,

            # ------------------------------------------------
            # Threat scoring
            # ------------------------------------------------
            "cumulative_threat_score": (
                self.cumulative_threat_score
            ),
            "terminate_threshold": TERMINATE_THRESHOLD,

            # ------------------------------------------------
            # Evidence
            # ------------------------------------------------
            "network_events": self.network_events,
            "browser_events": self.browser_events,
            "page_events": self.page_events,
            "threat_events": all_threat_events,

            # ------------------------------------------------
            # Screenshot (base64 PNG, may be None)
            # ------------------------------------------------
            "screenshot_b64": self.screenshot_b64,
        }
