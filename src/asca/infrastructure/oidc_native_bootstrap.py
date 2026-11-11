"""Default-only CERN native OIDC pre-authentication composition (unmounted).

Unlike the lower-level, deliberately injectable offline prototypes, this entry
point accepts no metadata, HTTP transport, verifier, clock, token or signing key
from its caller. It retrieves pinned public discovery with the existing HTTPS
fetcher and constructs the existing native exchange using its default adapters.

This is NOT a production login trust root: an operator declaration is not CERN
registration attestation; Python objects and monkeypatches remain forgeable;
the native callback listener and a durable replay store are not installed.
"""

from __future__ import annotations

import ssl
from typing import Any
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from asca.application.oidc_client_preflight import build_cern_client_configuration
from asca.application.oidc_discovery import (
    CERN_OIDC_ISSUER,
    OidcDiscoveryPolicy,
    OidcDiscoveryService,
)
from asca.domain.oidc_discovery import OidcDiscoveryError, OidcProviderMetadata
from asca.domain.oidc_native_bootstrap import NativeOidcIsolationStatus, OidcNativeBootstrapError
from asca.domain.oidc_native_exchange import OidcNativeExchangeError
from asca.domain.oidc_registration import (
    OidcClientMode,
    OidcClientRegistration,
    OidcRegistrationError,
)
from asca.infrastructure.oidc_http import HttpsOidcMetadataFetcher
from asca.infrastructure.oidc_jwks_http import HttpsCernOidcJwksFetcher
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

_APPROVED_ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})
_AUTH_ENDPOINT = CERN_OIDC_ISSUER + "/protocol/openid-connect/auth"
_TOKEN_ENDPOINT = CERN_OIDC_ISSUER + "/protocol/openid-connect/token"
_JWKS_ENDPOINT = CERN_OIDC_ISSUER + "/protocol/openid-connect/certs"


class _RejectDiscoveryRedirects(HTTPRedirectHandler):
    """Do not follow an attacker-selected target during metadata discovery."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


class CernOidcNativeUntrustedBootstrap:
    """Build a native pre-authentication flow from default security adapters.

    No dependency injection is offered by this public constructor or build().
    This guard reduces accidental test-adapter wiring; it is not tamper-proof.
    Explicit execution may contact public CERN discovery. The ASCA API does not
    instantiate this class or expose a native callback route.
    """

    def __init__(self, registration: OidcClientRegistration) -> None:
        if (
            type(registration) is not OidcClientRegistration
            or registration.mode is not OidcClientMode.NATIVE_LOOPBACK
        ):
            raise OidcNativeBootstrapError("Invalid CERN native client declaration")
        try:
            # Revalidate because even frozen Python dataclasses can be mutated.
            self._registration = OidcClientRegistration(
                client_id=registration.client_id,
                redirect_uri=registration.redirect_uri,
                mode=registration.mode,
                scopes=registration.scopes,
            )
        except (AttributeError, TypeError, ValueError):
            raise OidcNativeBootstrapError("Invalid CERN native client declaration") from None
        self._registration_snapshot = (
            self._registration.client_id,
            self._registration.redirect_uri,
            self._registration.mode,
            self._registration.scopes,
        )

    def _check_registration_snapshot(self) -> None:
        """Reject post-init mutation even if a new value is syntactically valid."""
        try:
            current = self._registration
            if (
                type(current) is not OidcClientRegistration
                or (
                    current.client_id,
                    current.redirect_uri,
                    current.mode,
                    current.scopes,
                )
                != self._registration_snapshot
            ):
                raise OidcNativeBootstrapError("Native client configuration changed")
            # Comparison alone cannot detect an enum changed to an equal string.
            OidcClientRegistration(
                client_id=current.client_id,
                redirect_uri=current.redirect_uri,
                mode=current.mode,
                scopes=current.scopes,
            )
        except (AttributeError, TypeError, ValueError):
            raise OidcNativeBootstrapError("Native client configuration changed") from None

    @property
    def isolation_status(self) -> NativeOidcIsolationStatus:
        """Return a descriptive constant, not an attestation or login result."""
        return NativeOidcIsolationStatus()

    def build(self) -> CernOidcNativeCodeExchange:
        """Retrieve pinned public metadata and construct default-only native flow.

        Does not validate the client's official CERN registration or authenticate
        any user. Transport and verifier must not be supplied by the caller.
        """
        try:
            self._check_registration_snapshot()
            policy = OidcDiscoveryPolicy()
            # Build the public-metadata adapter with explicit proxy isolation.
            # The existing discovery fetcher handles TLS, JSON and size checks;
            # the opener here prohibits environment proxy use and redirects.
            opener = build_opener(
                ProxyHandler({}),
                HTTPSHandler(context=ssl.create_default_context()),
                _RejectDiscoveryRedirects(),
            )
            fetcher = HttpsOidcMetadataFetcher(policy, opener=opener)
            metadata = OidcDiscoveryService(policy, fetcher).discover()
            if (
                type(metadata) is not OidcProviderMetadata
                or metadata.issuer != CERN_OIDC_ISSUER
                or metadata.authorization_endpoint != _AUTH_ENDPOINT
                or metadata.token_endpoint != _TOKEN_ENDPOINT
                or metadata.jwks_uri != _JWKS_ENDPOINT
                or metadata.supports_authorization_code is not True
                or metadata.supports_pkce_s256 is not True
                or type(metadata.approved_id_token_algorithms) is not tuple
                or not metadata.approved_id_token_algorithms
                or any(
                    type(algorithm) is not str or algorithm not in _APPROVED_ALGORITHMS
                    for algorithm in metadata.approved_id_token_algorithms
                )
                or len(metadata.approved_id_token_algorithms)
                != len(set(metadata.approved_id_token_algorithms))
            ):
                raise OidcNativeBootstrapError("CERN native discovery policy was rejected")

            self._check_registration_snapshot()
            config = build_cern_client_configuration(self._registration, metadata, policy=policy)
            if (
                config.client_id != self._registration.client_id
                or config.redirect_uri != self._registration.redirect_uri
            ):
                raise OidcNativeBootstrapError("CERN native registration policy was rejected")

            native = CernOidcNativeCodeExchange(self._registration, metadata)
            # These are *defensive structural checks*, not TLS provenance proofs.
            # They catch accidental injection/subclassing at the composition root.
            if (
                type(native) is not CernOidcNativeCodeExchange
                or type(native._transport) is not HttpsOidcTokenTransport
                or type(native._verifier) is not CernOidcVerificationPipeline
                or type(native._verifier._fetcher) is not HttpsCernOidcJwksFetcher
            ):
                raise OidcNativeBootstrapError("CERN native transport composition was rejected")
            return native
        except (
            OidcDiscoveryError,
            OidcRegistrationError,
            OidcNativeExchangeError,
            OidcNativeBootstrapError,
            TypeError,
            ValueError,
            AttributeError,
            OverflowError,
            OSError,
        ):
            raise OidcNativeBootstrapError("CERN native bootstrap was rejected") from None
