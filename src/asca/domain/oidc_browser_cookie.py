"""Immutable policy for a temporary, non-authenticating OIDC browser-binding cookie.

The cookie carries an opaque authorization-attempt binding, never a token or
verified identity. Only HTTPS web BFF deployments are supported by this policy.
"""

import re
from dataclasses import dataclass, field

COOKIE_NAME = "__Host-asca-oidc-attempt"
_BINDING_PATTERN = re.compile(r"[A-Za-z0-9_-]{43,128}\Z", re.ASCII)


class OidcBrowserCookieError(ValueError):
    """Sanitized error; never includes the cookie or binding value."""


def validate_cookie_lifetime(seconds: object) -> int:
    """Validate the maximum age before any authorization attempt is created."""
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 30 <= seconds <= 900:
        raise OidcBrowserCookieError("Invalid OIDC cookie lifetime")
    return seconds


def validate_browser_binding(binding: object) -> str:
    """Require a URL-safe opaque binding with the expected entropy-bearing shape.

    Shape alone is not authentication: the authorization-attempt store must also
    verify that this binding was issued by this process and matches the state.
    """
    if not isinstance(binding, str) or not _BINDING_PATTERN.fullmatch(binding):
        raise OidcBrowserCookieError("Invalid OIDC browser-binding cookie")
    return binding


@dataclass(frozen=True, slots=True)
class OidcBrowserCookie:
    """A short-lived, host-bound cookie for a pre-authentication OIDC attempt.

    The binding must never be logged, serialized to project files, or exposed
    to frontend JavaScript. This value is not an authenticated session.
    """

    binding: str = field(repr=False)
    max_age_seconds: int = 300

    def __post_init__(self) -> None:
        validate_browser_binding(self.binding)
        validate_cookie_lifetime(self.max_age_seconds)

    def set_cookie_header(self) -> str:
        """Return a Set-Cookie value; MUST be used only over HTTPS, never logged."""
        return (
            f"{COOKIE_NAME}={self.binding}; Max-Age={self.max_age_seconds}; "
            "Path=/; Secure; HttpOnly; SameSite=Lax"
        )

    @staticmethod
    def clear_cookie_header() -> str:
        """Clear the pre-authentication binding after either callback outcome."""
        return f"{COOKIE_NAME}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"


def read_browser_binding_cookie(cookie_header: object) -> str:
    """Parse exactly one opaque binding from an HTTP Cookie header.

    Duplicate target cookies are rejected, not resolved by framework-specific
    first/last wins behavior. The caller must still consult its attempt store.
    """
    if (
        not isinstance(cookie_header, str)
        or not cookie_header
        or len(cookie_header) > 8192
        or any(ord(char) < 32 or ord(char) >= 127 for char in cookie_header)
    ):
        raise OidcBrowserCookieError("Invalid OIDC browser-binding cookie")

    value: str | None = None
    for segment in cookie_header.split(";"):
        name, separator, candidate = segment.strip().partition("=")
        if not separator or not name:
            raise OidcBrowserCookieError("Invalid OIDC browser-binding cookie")
        if name == COOKIE_NAME:
            if value is not None:
                raise OidcBrowserCookieError("Duplicate OIDC browser-binding cookie")
            value = validate_browser_binding(candidate)

    if value is None:
        raise OidcBrowserCookieError("Missing OIDC browser-binding cookie")
    return value
