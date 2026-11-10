"""Declarative OIDC client registration data, without authentication capability.

An operator declaration is not evidence of an accepted CERN registration.
This module performs purely local checks and never accesses the network.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlsplit

_CLIENT_ID = re.compile(r"[A-Za-z0-9._~:-]{1,256}\Z", re.ASCII)
_DNS_NAME = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z",
    re.ASCII,
)
_ALLOWED_SCOPES = frozenset({"openid", "profile", "email"})


class OidcClientMode(StrEnum):
    """Deployment mode for one explicitly configured OIDC client."""

    NATIVE_LOOPBACK = "native_loopback"
    WEB_BFF = "web_bff"


class OidcRegistrationError(ValueError):
    """Safe error for an invalid operator-supplied client configuration."""


def _validate_redirect_uri(value: str, mode: OidcClientMode) -> None:
    """Reject ambiguous callbacks rather than performing URI normalization."""
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(ch) < 33 or ord(ch) == 127 for ch in value)
        or any(ch in value for ch in ("\\", "*", "%", "?", "#"))
    ):
        raise OidcRegistrationError("Redirect URI has unsafe characters")
    try:
        url = urlsplit(value)
        port = url.port
        hostname = url.hostname
    except ValueError:
        raise OidcRegistrationError("Redirect URI has invalid authority") from None
    if (
        not hostname
        or not url.netloc
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or not url.path.startswith("/")
        or url.path.startswith("//")
        or "/../" in url.path
        or "/./" in url.path
        or url.path.endswith(("/..", "/."))
    ):
        raise OidcRegistrationError("Redirect URI is not a safe absolute callback")
    if mode is OidcClientMode.NATIVE_LOOPBACK:
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            raise OidcRegistrationError("Native callback must use a loopback IP literal") from None
        if url.scheme != "http" or not address.is_loopback or port is None or port == 0:
            raise OidcRegistrationError("Native callback requires HTTP loopback with a port")
    elif mode is OidcClientMode.WEB_BFF:
        if url.scheme != "https" or not _DNS_NAME.fullmatch(hostname):
            raise OidcRegistrationError("Web callback requires a public HTTPS DNS host")
        if port == 0:
            raise OidcRegistrationError("Web callback has an invalid port")
    else:
        raise OidcRegistrationError("Unsupported OIDC client mode")


@dataclass(frozen=True, slots=True)
class OidcClientRegistration:
    """Operator-declared client settings, not proof of provider registration.

    The deployment must independently confirm the client ID and exact callback
    against its CERN Application Portal record before enabling any login.
    No client secret belongs in this structure.
    """

    client_id: str = field(repr=False)
    redirect_uri: str
    mode: OidcClientMode
    scopes: tuple[str, ...] = ("openid",)

    def __post_init__(self) -> None:
        if not isinstance(self.client_id, str) or not _CLIENT_ID.fullmatch(self.client_id):
            raise OidcRegistrationError("OIDC client identifier is invalid")
        if not isinstance(self.mode, OidcClientMode):
            raise OidcRegistrationError("Unsupported OIDC client mode")
        _validate_redirect_uri(self.redirect_uri, self.mode)
        if (
            not isinstance(self.scopes, tuple)
            or not self.scopes
            or "openid" not in self.scopes
            or any(
                not isinstance(scope, str) or scope not in _ALLOWED_SCOPES for scope in self.scopes
            )
            or len(set(self.scopes)) != len(self.scopes)
        ):
            raise OidcRegistrationError("OIDC scopes must be unique and minimally approved")
