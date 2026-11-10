"""Build an unsent CERN OIDC code-exchange request for native public clients.

No network is used. Client registration must still be verified with CERN;
this module does not support confidential web BFF client authentication.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode

from asca.application.identity import pkce_s256_challenge
from asca.application.oidc_client_preflight import build_cern_client_configuration
from asca.application.oidc_discovery import OidcDiscoveryPolicy
from asca.domain.identity import AuthorizationCodeGrant
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_registration import (
    OidcClientMode,
    OidcClientRegistration,
    OidcRegistrationError,
)
from asca.domain.oidc_token_request import OidcTokenRequestError, UnsentOidcTokenRequest

_NONCE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z", re.ASCII)
_MAX_CODE_LENGTH = 2048


def _valid_authorization_code(code: object) -> bool:
    """Accept bounded RFC 6749 visible ASCII, never control or Unicode data."""
    return bool(
        isinstance(code, str)
        and 1 <= len(code) <= _MAX_CODE_LENGTH
        and code.strip()
        and all(32 <= ord(char) <= 126 for char in code)
    )


def prepare_cern_native_token_request(
    grant: AuthorizationCodeGrant,
    registration: OidcClientRegistration,
    metadata: OidcProviderMetadata,
    *,
    policy: OidcDiscoveryPolicy | None = None,
) -> UnsentOidcTokenRequest:
    """Prepare an offline POST from a previously correlated authorization grant.

    The caller MUST obtain grant via server-side state/PKCE correlation, get
    metadata from trusted discovery, and independently confirm registration.
    This method cannot verify those external facts or send HTTP requests.
    """
    if (
        not isinstance(grant, AuthorizationCodeGrant)
        or not isinstance(registration, OidcClientRegistration)
        or not isinstance(metadata, OidcProviderMetadata)
    ):
        raise OidcTokenRequestError("Invalid OIDC token request input")
    if registration.mode is not OidcClientMode.NATIVE_LOOPBACK:
        raise OidcTokenRequestError("Public native token request requires native registration")
    try:
        config = build_cern_client_configuration(registration, metadata, policy=policy)
    except (OidcRegistrationError, ValueError):
        raise OidcTokenRequestError("Untrusted CERN token request configuration") from None
    if not isinstance(grant.redirect_uri, str) or grant.redirect_uri != config.redirect_uri:
        raise OidcTokenRequestError("OIDC redirect URI does not match registration")
    if not _valid_authorization_code(grant.code):
        raise OidcTokenRequestError("Invalid OIDC authorization code")
    if not isinstance(grant.nonce, str) or not _NONCE.fullmatch(grant.nonce):
        raise OidcTokenRequestError("Invalid OIDC authorization nonce")
    try:
        pkce_s256_challenge(grant.code_verifier)
    except (ValueError, TypeError, UnicodeError):
        raise OidcTokenRequestError("Invalid OIDC PKCE verifier") from None

    body = urlencode(
        (
            ("grant_type", "authorization_code"),
            ("code", grant.code),
            ("redirect_uri", config.redirect_uri),
            ("client_id", config.client_id),
            ("code_verifier", grant.code_verifier),
        )
    ).encode("ascii")
    return UnsentOidcTokenRequest(
        token_endpoint=metadata.token_endpoint,
        form_body=body,
        expected_nonce=grant.nonce,
    )
