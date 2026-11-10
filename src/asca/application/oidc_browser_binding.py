"""Offline BFF browser-binding handoff for an unverified OIDC code grant.

No login or callback HTTP route is installed by this module. The hosting BFF
MUST use HTTPS, a trusted registered callback, and a server-controlled cookie.
"""

from dataclasses import dataclass, field

from asca.application.identity import OidcAuthorizationService
from asca.domain.identity import AuthorizationCodeGrant
from asca.domain.oidc_browser_cookie import (
    OidcBrowserCookie,
    OidcBrowserCookieError,
    read_browser_binding_cookie,
    validate_cookie_lifetime,
)
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration


@dataclass(frozen=True, slots=True)
class OidcBrowserAuthorizationStart:
    """Pre-authentication data for an HTTPS BFF; do not log this object."""

    authorization_url: str = field(repr=False)
    cookie: OidcBrowserCookie = field(repr=False)


def begin_web_bff_authorization(
    service: OidcAuthorizationService,
    registration: OidcClientRegistration,
    *,
    cookie_lifetime_seconds: int = 300,
) -> OidcBrowserAuthorizationStart:
    """Create a browser-bound attempt for a web BFF, not an authenticated login.

    The composition root must build ``service`` from the same registration
    through the approved CERN discovery and preflight path. No HTTP is sent.
    """
    if registration.mode is not OidcClientMode.WEB_BFF:
        raise OidcBrowserCookieError("OIDC browser cookie requires a web BFF registration")
    # Validate policy before beginning an attempt so failures cannot leave
    # orphaned in-memory transactions.
    validate_cookie_lifetime(cookie_lifetime_seconds)
    started = service.begin()
    return OidcBrowserAuthorizationStart(
        authorization_url=started.authorization_url,
        cookie=OidcBrowserCookie(
            binding=started.browser_binding,
            max_age_seconds=cookie_lifetime_seconds,
        ),
    )


def finish_web_bff_callback(
    service: OidcAuthorizationService,
    *,
    cookie_header: object,
    state: str,
    code: str | None = None,
    error: str | None = None,
    response_issuer: str | None = None,
) -> AuthorizationCodeGrant:
    """Correlate a callback; return an UNVERIFIED authorization-code grant.

    HTTP transport must reject callbacks without the initiating cookie and
    clear the cookie on both success and failure. The result must never confer
    identity, permissions or a session until full token validation is added.
    """
    binding = read_browser_binding_cookie(cookie_header)
    return service.finish(
        browser_binding=binding,
        state=state,
        code=code,
        error=error,
        response_issuer=response_issuer,
    )
