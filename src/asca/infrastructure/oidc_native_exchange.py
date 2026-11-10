"""Single-use native-loopback authorization-code/token-verification composition.

This isolated prototype intentionally does NOT support WEB_BFF, whose future
confidential-client exchange requires a separate, reviewed authentication
mechanism. It is not mounted as an ASCA login route and cannot grant identity.

Its default transport uses fixed-endpoint HTTPS with TLS verification; custom
transports/verifiers may be injected only in offline tests. Provider registration,
operational callback binding and result provenance still require external checks.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable

from asca.application.identity import AuthorizationStart, OidcAuthorizationService
from asca.application.oidc_client_preflight import build_cern_client_configuration
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_token_request import prepare_cern_native_token_request
from asca.application.oidc_token_response import parse_unverified_oidc_token_response
from asca.domain.identity import AuthenticationFlowError, AuthorizationCodeGrant
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_exchange import (
    ExchangedUntrustedCernOidcToken,
    OidcNativeExchangeError,
)
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_http import OidcTokenHttpError, UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import OidcTokenRequestError
from asca.domain.oidc_token_response import OidcTokenResponseError
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken, OidcVerificationError
from asca.infrastructure.identity_memory import InMemoryAuthorizationAttemptStore
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

_ALLOWED_ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})
_CODE = re.compile(r"[\x21-\x7E]{1,2048}\Z", re.ASCII)
_MAX_TIME = 2**53


class CernOidcNativeCodeExchange:
    """Consume a native callback once and POST its code/PKCE under one transaction.

    Neither a code grant nor an unverified token response is accepted from the
    caller. They are constructed and consumed in sequence inside this instance.
    The in-memory store only guarantees atomicity within this Python process.
    """

    def __init__(
        self,
        registration: OidcClientRegistration,
        metadata: OidcProviderMetadata,
        *,
        transport: HttpsOidcTokenTransport | None = None,
        verifier: CernOidcVerificationPipeline | None = None,
        clock: Callable[[], float] = time.time,
        ttl_seconds: int = 300,
        max_pending: int = 256,
    ) -> None:
        if (
            not isinstance(registration, OidcClientRegistration)
            or registration.mode is not OidcClientMode.NATIVE_LOOPBACK
            or not isinstance(metadata, OidcProviderMetadata)
            or metadata.issuer != CERN_OIDC_ISSUER
            or metadata.authorization_endpoint != CERN_OIDC_ISSUER + "/protocol/openid-connect/auth"
            or metadata.token_endpoint != CERN_OIDC_ISSUER + "/protocol/openid-connect/token"
            or metadata.jwks_uri != CERN_OIDC_ISSUER + "/protocol/openid-connect/certs"
            or metadata.supports_authorization_code is not True
            or metadata.supports_pkce_s256 is not True
            or not isinstance(metadata.approved_id_token_algorithms, tuple)
            or not metadata.approved_id_token_algorithms
            or any(
                not isinstance(alg, str) or alg not in _ALLOWED_ALGORITHMS
                for alg in metadata.approved_id_token_algorithms
            )
            or len(set(metadata.approved_id_token_algorithms))
            != len(metadata.approved_id_token_algorithms)
            or (transport is not None and not isinstance(transport, HttpsOidcTokenTransport))
            or (verifier is not None and not isinstance(verifier, CernOidcVerificationPipeline))
            or not callable(clock)
            or not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not 30 <= ttl_seconds <= 900
            or not isinstance(max_pending, int)
            or isinstance(max_pending, bool)
            or not 1 <= max_pending <= 10_000
        ):
            raise OidcNativeExchangeError("Invalid CERN native OIDC exchange policy")
        try:
            # Frozen Python dataclasses can be forged. Reconstruct before use.
            validated = OidcClientRegistration(
                client_id=registration.client_id,
                redirect_uri=registration.redirect_uri,
                mode=registration.mode,
                scopes=registration.scopes,
            )
            config = build_cern_client_configuration(validated, metadata)
        except (ValueError, TypeError, AttributeError):
            raise OidcNativeExchangeError("Invalid CERN native OIDC exchange policy") from None

        self._registration = validated
        self._metadata = metadata
        self._client_id = config.client_id
        self._redirect_uri = config.redirect_uri
        self._clock = clock
        self._store = InMemoryAuthorizationAttemptStore(max_pending=max_pending)
        self._service = OidcAuthorizationService(
            config, self._store, clock=self._checked_clock, ttl_seconds=ttl_seconds
        )
        self._transport = transport if transport is not None else HttpsOidcTokenTransport()
        self._verifier = verifier if verifier is not None else CernOidcVerificationPipeline()

    def _checked_clock(self) -> float:
        try:
            instant = self._clock()
            if (
                isinstance(instant, bool)
                or not isinstance(instant, (int, float))
                or not math.isfinite(instant)
                or not 1 <= instant < _MAX_TIME
            ):
                raise OidcNativeExchangeError("Invalid OIDC verification clock")
            return float(instant)
        except (TypeError, ValueError, OverflowError):
            raise OidcNativeExchangeError("Invalid OIDC verification clock") from None

    def begin(self) -> AuthorizationStart:
        """Create local state, nonce and PKCE, without transmitting credentials."""
        try:
            return self._service.begin()
        except (TypeError, ValueError, OverflowError):
            raise OidcNativeExchangeError("OIDC authorization attempt was rejected") from None

    def exchange_callback(
        self,
        *,
        browser_binding: str,
        state: str,
        code: str,
        response_issuer: str | None = None,
    ) -> ExchangedUntrustedCernOidcToken:
        """Consume once, POST the original code/PKCE, verify the returned ID token.

        A native host MUST obtain binding/state/code from its protected loopback
        callback context. It MUST confirm the official CERN client registration.
        This method never accepts a caller-supplied token or code verifier.
        """
        if (
            not isinstance(code, str)
            or _CODE.fullmatch(code) is None
            or not isinstance(browser_binding, str)
            or not browser_binding
            or not isinstance(state, str)
            or not state
            or (
                response_issuer is not None
                and (not isinstance(response_issuer, str) or response_issuer != CERN_OIDC_ISSUER)
            )
        ):
            raise OidcNativeExchangeError("Invalid OIDC native callback input")
        try:
            # The existing store atomically removes the correlated attempt.
            grant = self._service.finish(
                browser_binding=browser_binding,
                state=state,
                code=code,
                response_issuer=response_issuer,
            )
            if (
                not isinstance(grant, AuthorizationCodeGrant)
                or grant.code != code
                or grant.redirect_uri != self._redirect_uri
            ):
                raise OidcNativeExchangeError("Invalid consumed OIDC native callback")

            prepared = prepare_cern_native_token_request(grant, self._registration, self._metadata)
            if prepared.expected_nonce != grant.nonce:
                raise OidcNativeExchangeError("OIDC nonce binding was rejected")
            response = self._transport.exchange(prepared, self._registration)
            if not isinstance(response, UnverifiedOidcTokenHttpResponse):
                raise OidcNativeExchangeError("OIDC token exchange response was rejected")
            tokens = parse_unverified_oidc_token_response(response)
            checked = self._verifier.check(
                tokens,
                self._metadata,
                expected_client_id=self._client_id,
                expected_nonce=grant.nonce,
                now=int(self._checked_clock()),
            )
        except (
            AuthenticationFlowError,
            OidcNativeExchangeError,
            OidcTokenRequestError,
            OidcTokenHttpError,
            OidcTokenResponseError,
            OidcVerificationError,
            TypeError,
            ValueError,
            OverflowError,
        ):
            raise OidcNativeExchangeError("OIDC native code exchange was rejected") from None
        if (
            not isinstance(checked, CheckedUntrustedCernOidcToken)
            or checked.issuer != CERN_OIDC_ISSUER
            or not isinstance(checked.audiences, tuple)
            or self._client_id not in checked.audiences
            or not isinstance(checked.subject, str)
            or not checked.subject
            or checked.algorithm not in _ALLOWED_ALGORITHMS
            or not isinstance(checked.expires_at, int)
            or checked.expires_at <= int(self._checked_clock())
        ):
            raise OidcNativeExchangeError("OIDC native code exchange was rejected")
        return ExchangedUntrustedCernOidcToken(
            issuer=checked.issuer,
            subject=checked.subject,
            audiences=checked.audiences,
            expires_at=checked.expires_at,
            algorithm=checked.algorithm,
            kid=checked.kid,
        )
