"""Isolated browser-bound, single-use CERN OIDC verification composition.

This is an offline-only, process-local BFF prototype. It reuses the existing
atomic authorization-attempt store and protected browser-cookie parser. It does
NOT exchange the callback code for tokens or prove CERN client registration.
Consequently a checked result must never create an identity, session or access.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable

from asca.application.identity import OidcAuthorizationService
from asca.application.oidc_browser_binding import (
    OidcBrowserAuthorizationStart,
    begin_web_bff_authorization,
    finish_web_bff_callback,
)
from asca.application.oidc_client_preflight import build_cern_client_configuration
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_authorization_binding import (
    BoundUntrustedCernOidcToken,
    OidcAuthorizationBindingError,
)
from asca.domain.oidc_browser_cookie import validate_cookie_lifetime
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_registration import (
    OidcClientMode,
    OidcClientRegistration,
)
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.identity_memory import InMemoryAuthorizationAttemptStore
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

_MAX_TIME = 2**53
_CODE = re.compile(r"[\x21-\x7E]{1,2048}\Z", re.ASCII)
_ALLOWED_ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})


class CernOidcReplaySafeBffBinding:
    """Bind a nonce to a consumed web callback without promoting token authority.

    The store is constructed privately and is single-process only. For offline
    deterministic tests an injected verification pipeline may use fake HTTP.
    Both the pipeline and result are untrusted for authentication purposes.
    """

    def __init__(
        self,
        registration: OidcClientRegistration,
        metadata: OidcProviderMetadata,
        *,
        pipeline: CernOidcVerificationPipeline | None = None,
        clock: Callable[[], float] = time.time,
        ttl_seconds: int = 300,
        cookie_lifetime_seconds: int = 300,
        max_pending: int = 256,
    ) -> None:
        if (
            not isinstance(registration, OidcClientRegistration)
            or registration.mode is not OidcClientMode.WEB_BFF
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
            or (pipeline is not None and not isinstance(pipeline, CernOidcVerificationPipeline))
            or not callable(clock)
            or not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not 30 <= ttl_seconds <= 900
            or not isinstance(max_pending, int)
            or isinstance(max_pending, bool)
            or not 1 <= max_pending <= 10_000
        ):
            raise OidcAuthorizationBindingError("Invalid CERN BFF authorization policy")
        try:
            validated_cookie_lifetime = validate_cookie_lifetime(cookie_lifetime_seconds)
            if validated_cookie_lifetime > ttl_seconds:
                raise OidcAuthorizationBindingError("Cookie exceeds authorization attempt lifetime")
            # Revalidate the declaration in case a frozen dataclass was forged.
            validated_registration = OidcClientRegistration(
                client_id=registration.client_id,
                redirect_uri=registration.redirect_uri,
                mode=registration.mode,
                scopes=registration.scopes,
            )
            config = build_cern_client_configuration(validated_registration, metadata)
        except (TypeError, ValueError):
            raise OidcAuthorizationBindingError("Invalid CERN BFF authorization policy") from None

        self._registration = validated_registration
        self._metadata = metadata
        self._client_id = config.client_id
        self._redirect_uri = config.redirect_uri
        self._clock = clock
        self._cookie_lifetime_seconds = validated_cookie_lifetime
        self._store = InMemoryAuthorizationAttemptStore(max_pending=max_pending)
        self._service = OidcAuthorizationService(
            config, self._store, clock=self._checked_clock, ttl_seconds=ttl_seconds
        )
        self._pipeline = pipeline if pipeline is not None else CernOidcVerificationPipeline()

    def _checked_clock(self) -> float:
        """Reject invalid or nonfinite host clock values, without logging values."""
        try:
            value = self._clock()
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 1 <= value < _MAX_TIME
            ):
                raise OidcAuthorizationBindingError("Invalid OIDC verification clock")
            return float(value)
        except (OverflowError, ValueError, TypeError):
            raise OidcAuthorizationBindingError("Invalid OIDC verification clock") from None

    def begin(self) -> OidcBrowserAuthorizationStart:
        """Issue a fresh authorization state, nonce, PKCE challenge and BFF cookie."""
        try:
            return begin_web_bff_authorization(
                self._service,
                self._registration,
                cookie_lifetime_seconds=self._cookie_lifetime_seconds,
            )
        except (TypeError, ValueError):
            raise OidcAuthorizationBindingError("OIDC authorization attempt was rejected") from None

    def check_callback(
        self,
        *,
        cookie_header: object,
        state: str,
        code: str,
        tokens: ParsedUnverifiedOidcTokenResponse,
        response_issuer: str | None = None,
    ) -> BoundUntrustedCernOidcToken:
        """Consume the browser attempt exactly once, then verify a supplied token.

        The caller MUST be a trusted HTTPS BFF that reads its real Cookie header.
        Code-to-token exchange and code-to-token response correlation are NOT
        implemented here. All failed checks after consumption remain consumed.
        """
        if (
            not isinstance(code, str)
            or _CODE.fullmatch(code) is None
            or not isinstance(tokens, ParsedUnverifiedOidcTokenResponse)
            or (
                response_issuer is not None
                and (not isinstance(response_issuer, str) or response_issuer != CERN_OIDC_ISSUER)
            )
        ):
            raise OidcAuthorizationBindingError("Invalid OIDC callback input")
        try:
            grant = finish_web_bff_callback(
                self._service,
                cookie_header=cookie_header,
                state=state,
                code=code,
                response_issuer=response_issuer,
            )
            if grant.redirect_uri != self._redirect_uri or grant.code != code:
                raise OidcAuthorizationBindingError("Invalid consumed OIDC callback")
            checked = self._pipeline.check(
                tokens,
                self._metadata,
                expected_client_id=self._client_id,
                expected_nonce=grant.nonce,
                now=int(self._checked_clock()),
            )
        except (TypeError, ValueError, OverflowError):
            raise OidcAuthorizationBindingError("OIDC browser-bound verification failed") from None
        if (
            not isinstance(checked, CheckedUntrustedCernOidcToken)
            or checked.issuer != CERN_OIDC_ISSUER
            or not isinstance(checked.audiences, tuple)
            or self._client_id not in checked.audiences
            or not isinstance(checked.subject, str)
            or not checked.subject
            or checked.algorithm not in _ALLOWED_ALGORITHMS
        ):
            raise OidcAuthorizationBindingError("OIDC browser-bound verification failed")
        return BoundUntrustedCernOidcToken(
            issuer=checked.issuer,
            subject=checked.subject,
            audiences=checked.audiences,
            expires_at=checked.expires_at,
            algorithm=checked.algorithm,
            kid=checked.kid,
        )
