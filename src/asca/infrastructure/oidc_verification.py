"""Isolated, ordered CERN OIDC JWKS/JWS/claims checks without user login.

This composition invokes the pinned HTTPS fetcher itself, parses the bytes, and
verifies the caller's ID token using only that freshly fetched JWKS. No JWT
header, caller-supplied key or detached parsed-result object chooses a key URL.

This is *not* a production authentication adapter: authorization attempts and
client registration are not attested/consumed and results are forgeable Python
objects. The default fetcher has TLS guarantees, but offline fake openers do not.
No application route or startup hook instantiates this class.
"""

from __future__ import annotations

import re

from asca.application.oidc_claims import validate_untrusted_oidc_id_token_claims
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI, parse_cern_public_jwks
from asca.application.oidc_role_claims import inspect_untrusted_cern_application_role
from asca.domain.oidc_claims import ClaimsCheckedUntrustedOidcPayload, OidcClaimsError
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks import OidcJwksError
from asca.domain.oidc_jwks_http import FetchedUnverifiedOidcJwks, OidcJwksHttpError
from asca.domain.oidc_jws import OidcJwsError, SignatureCheckedUntrustedOidcPayload
from asca.domain.oidc_role_claims import OidcRoleClaimsError, UntrustedCernRoleObservation
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken, OidcVerificationError
from asca.infrastructure.oidc_jwks_http import HttpsCernOidcJwksFetcher
from asca.infrastructure.oidc_jws import verify_untrusted_oidc_jws_signature

_APPROVED_ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})
_CLIENT_ID = re.compile(r"[A-Za-z0-9._~:-]{1,256}\Z", re.ASCII)
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,256}\Z", re.ASCII)
_AUDIENCE = re.compile(r"[\x21-\x7E]{1,256}\Z", re.ASCII)


def _validate_before_fetch(
    tokens: ParsedUnverifiedOidcTokenResponse,
    metadata: OidcProviderMetadata,
    *,
    expected_client_id: str,
    expected_nonce: str,
    now: int,
    clock_skew_seconds: int,
    max_token_lifetime_seconds: int,
    trusted_additional_audiences: tuple[str, ...],
) -> None:
    """Reject manifestly invalid context before any HTTPS request is attempted."""
    if (
        not isinstance(tokens, ParsedUnverifiedOidcTokenResponse)
        or not isinstance(tokens.id_token, str)
        or not 1 <= len(tokens.id_token) <= 32_768
        or not tokens.id_token.isascii()
        or not isinstance(tokens.access_token, str)
        or not 1 <= len(tokens.access_token) <= 16_384
        or tokens.token_type != "Bearer"
        or not isinstance(metadata, OidcProviderMetadata)
        or metadata.issuer != CERN_OIDC_ISSUER
        or metadata.jwks_uri != CERN_OIDC_JWKS_URI
        or metadata.authorization_endpoint != CERN_OIDC_ISSUER + "/protocol/openid-connect/auth"
        or metadata.token_endpoint != CERN_OIDC_ISSUER + "/protocol/openid-connect/token"
        or metadata.supports_authorization_code is not True
        or metadata.supports_pkce_s256 is not True
        or not isinstance(metadata.approved_id_token_algorithms, tuple)
        or not metadata.approved_id_token_algorithms
        or any(
            not isinstance(alg, str) or alg not in _APPROVED_ALGORITHMS
            for alg in metadata.approved_id_token_algorithms
        )
        or len(set(metadata.approved_id_token_algorithms))
        != len(metadata.approved_id_token_algorithms)
        or not isinstance(expected_client_id, str)
        or _CLIENT_ID.fullmatch(expected_client_id) is None
        or not isinstance(expected_nonce, str)
        or _NONCE.fullmatch(expected_nonce) is None
        or not isinstance(now, int)
        or isinstance(now, bool)
        or not 1 <= now < 2**53
        or not isinstance(clock_skew_seconds, int)
        or isinstance(clock_skew_seconds, bool)
        or not 0 <= clock_skew_seconds <= 120
        or not isinstance(max_token_lifetime_seconds, int)
        or isinstance(max_token_lifetime_seconds, bool)
        or not 1 <= max_token_lifetime_seconds <= 86_400
        or not isinstance(trusted_additional_audiences, tuple)
        or len(trusted_additional_audiences) > 7
        or any(
            not isinstance(audience, str)
            or _AUDIENCE.fullmatch(audience) is None
            or audience == expected_client_id
            for audience in trusted_additional_audiences
        )
        or len(set(trusted_additional_audiences)) != len(trusted_additional_audiences)
    ):
        raise OidcVerificationError("Invalid CERN OIDC verification input or policy")


class CernOidcVerificationPipeline:
    """Sequentially fetch, parse, verify signature and check claims, once.

    No upstream parsed JWKS, chosen signing key, or signature-checked container
    is accepted from the caller. A caller-supplied fetcher is permitted ONLY in
    offline tests, where it deliberately does not prove real CERN provenance.
    """

    def __init__(self, *, fetcher: HttpsCernOidcJwksFetcher | None = None) -> None:
        if fetcher is not None and not isinstance(fetcher, HttpsCernOidcJwksFetcher):
            raise OidcVerificationError("Invalid CERN OIDC verification transport")
        self._fetcher = fetcher if fetcher is not None else HttpsCernOidcJwksFetcher()

    def _verified_payload(
        self,
        tokens: ParsedUnverifiedOidcTokenResponse,
        metadata: OidcProviderMetadata,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        clock_skew_seconds: int = 60,
        max_token_lifetime_seconds: int = 3_600,
        trusted_additional_audiences: tuple[str, ...] = (),
    ) -> tuple[SignatureCheckedUntrustedOidcPayload, ClaimsCheckedUntrustedOidcPayload]:
        """Return signature and claims checks from one constrained JWKS retrieval.

        No external signature-checked payload can enter this composition.
        These objects are still non-authoritative and forgeable in Python.
        """
        _validate_before_fetch(
            tokens,
            metadata,
            expected_client_id=expected_client_id,
            expected_nonce=expected_nonce,
            now=now,
            clock_skew_seconds=clock_skew_seconds,
            max_token_lifetime_seconds=max_token_lifetime_seconds,
            trusted_additional_audiences=trusted_additional_audiences,
        )
        try:
            fetched = self._fetcher.fetch(metadata)
            # A response object, including source_url, is forgeable. Require the
            # literal expected URL but do not promote it to a TLS attestation.
            if (
                not isinstance(fetched, FetchedUnverifiedOidcJwks)
                or fetched.source_url != CERN_OIDC_JWKS_URI
                or fetched.status_code != 200
                or not isinstance(fetched.body, bytes)
                or not 0 < len(fetched.body) <= 262_144
            ):
                raise OidcVerificationError("CERN OIDC JWKS source was rejected")
            jwks = parse_cern_public_jwks(fetched.body, metadata)
            checked_signature = verify_untrusted_oidc_jws_signature(tokens, jwks)
            checked_claims = validate_untrusted_oidc_id_token_claims(
                checked_signature,
                expected_client_id=expected_client_id,
                expected_nonce=expected_nonce,
                now=now,
                expected_access_token=tokens.access_token,
                clock_skew_seconds=clock_skew_seconds,
                max_token_lifetime_seconds=max_token_lifetime_seconds,
                trusted_additional_audiences=trusted_additional_audiences,
            )
        except (OidcJwksHttpError, OidcJwksError, OidcJwsError, OidcClaimsError):
            raise OidcVerificationError("CERN OIDC token verification was rejected") from None
        return checked_signature, checked_claims

    def check(
        self,
        tokens: ParsedUnverifiedOidcTokenResponse,
        metadata: OidcProviderMetadata,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        clock_skew_seconds: int = 60,
        max_token_lifetime_seconds: int = 3_600,
        trusted_additional_audiences: tuple[str, ...] = (),
    ) -> CheckedUntrustedCernOidcToken:
        """Check an ID token without authenticating or authorizing its caller."""
        _, checked_claims = self._verified_payload(
            tokens,
            metadata,
            expected_client_id=expected_client_id,
            expected_nonce=expected_nonce,
            now=now,
            clock_skew_seconds=clock_skew_seconds,
            max_token_lifetime_seconds=max_token_lifetime_seconds,
            trusted_additional_audiences=trusted_additional_audiences,
        )
        return CheckedUntrustedCernOidcToken(
            issuer=checked_claims.issuer,
            subject=checked_claims.subject,
            audiences=checked_claims.audiences,
            expires_at=checked_claims.expires_at,
            algorithm=checked_claims.algorithm,
            kid=checked_claims.kid,
            source_url=CERN_OIDC_JWKS_URI,
        )

    def observe_role(
        self,
        tokens: ParsedUnverifiedOidcTokenResponse,
        metadata: OidcProviderMetadata,
        *,
        expected_client_id: str,
        expected_nonce: str,
        expected_role: str,
        now: int,
    ) -> UntrustedCernRoleObservation:
        """Observe one role only from the same newly signature-verified ID token.

        The fixed strict default audience and time policy applies. This method
        does not consume a native transaction or attest CERN identity/roles.
        No session, authorization grant or chATLAS capability is created.
        """
        signed, _ = self._verified_payload(
            tokens,
            metadata,
            expected_client_id=expected_client_id,
            expected_nonce=expected_nonce,
            now=now,
            clock_skew_seconds=60,
            max_token_lifetime_seconds=3_600,
            trusted_additional_audiences=(),
        )
        try:
            return inspect_untrusted_cern_application_role(
                signed,
                expected_client_id=expected_client_id,
                expected_nonce=expected_nonce,
                expected_role=expected_role,
                now=now,
                expected_access_token=tokens.access_token,
            )
        except (OidcRoleClaimsError, TypeError, ValueError, AttributeError):
            raise OidcVerificationError("CERN OIDC role observation was rejected") from None
