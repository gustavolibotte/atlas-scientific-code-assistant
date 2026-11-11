"""Strict, offline OIDC ID-token claims checks without granting an identity.

The input is a *signature-checked* payload under an untrusted-provenance JWKS.
A future orchestrator must bind pinned TLS JWKS retrieval to signature checks,
claims checks and replay-safe authorization state before enabling any login.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from decimal import Decimal
from typing import Any

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_claims import ClaimsCheckedUntrustedOidcPayload, OidcClaimsError
from asca.domain.oidc_jws import SignatureCheckedUntrustedOidcPayload

_MAX_CLAIMS_BYTES = 16_384
_MAX_AUDIENCES = 8
_MAX_CLOCK_SKEW_SECONDS = 120
_MAX_TOKEN_LIFETIME_SECONDS = 86_400
_CLIENT_ID = re.compile(r"[A-Za-z0-9._~:-]{1,256}\Z", re.ASCII)
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,256}\Z", re.ASCII)
_SUBJECT = re.compile(r"[\x21-\x7E]{1,255}\Z", re.ASCII)
_AUDIENCE = re.compile(r"[\x21-\x7E]{1,256}\Z", re.ASCII)
_APPROVED_ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})
_PROHIBITED_UNBOUND_HASHES = frozenset({"c_hash", "s_hash"})
_ACCESS_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+={0,64}\Z", re.ASCII)


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise OidcClaimsError("Duplicate OIDC ID-token JSON members")
        result[name] = value
    return result


def _reject_constant(_value: str) -> None:
    raise OidcClaimsError("Invalid OIDC ID-token JSON numeric constant")


def _parse_claims(payload: bytes) -> dict[str, object]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= _MAX_CLAIMS_BYTES:
        raise OidcClaimsError("Invalid OIDC ID-token payload length")
    try:
        document: Any = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_constant,
            parse_float=Decimal,
        )
    except OidcClaimsError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        raise OidcClaimsError("Invalid OIDC ID-token strict JSON") from None
    if not isinstance(document, dict):
        raise OidcClaimsError("OIDC ID-token claims must be a JSON object")
    return document


def _numeric_date(value: object, *, claim: str) -> int:
    # This deliberately accepts only integer NumericDate timestamps. RFC 7519
    # also permits fractions, which are unsupported by this conservative policy.
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value < 2**53:
        raise OidcClaimsError(f"Invalid OIDC ID-token {claim} claim")
    return value


def _audiences(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, list) and 1 <= len(value) <= _MAX_AUDIENCES:
        values = tuple(value)
    else:
        raise OidcClaimsError("Invalid OIDC ID-token audience claim")
    if any(
        not isinstance(item, str) or _AUDIENCE.fullmatch(item) is None for item in values
    ) or len(set(values)) != len(values):
        raise OidcClaimsError("Invalid OIDC ID-token audience claim")
    return values


def _validate_optional_at_hash(
    document: dict[str, object], *, expected_access_token: str | None, algorithm: str
) -> None:
    """Bind a signed optional at_hash to this token endpoint response only.

    For RS256, PS256 and ES256, OIDC specifies SHA-256, leftmost 128 bits,
    base64url without padding. No token or hash value is returned or stored.
    A direct claims call without the matching token must fail closed.
    """
    if "at_hash" not in document:
        return
    if expected_access_token is None:
        raise OidcClaimsError("OIDC ID-token contains unsupported token-binding hash claims")
    supplied = document["at_hash"]
    if (
        not isinstance(supplied, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{22}", supplied, re.ASCII) is None
        or not isinstance(expected_access_token, str)
        or not 1 <= len(expected_access_token) <= 16_384
        or _ACCESS_TOKEN.fullmatch(expected_access_token) is None
        or algorithm not in _APPROVED_ALGORITHMS
    ):
        raise OidcClaimsError("Invalid OIDC ID-token access-token hash binding")
    digest = hashlib.sha256(expected_access_token.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(supplied, computed):
        raise OidcClaimsError("OIDC ID-token access-token hash did not match")


def validate_untrusted_oidc_id_token_claims(
    checked: SignatureCheckedUntrustedOidcPayload,
    *,
    expected_client_id: str,
    expected_nonce: str,
    now: int,
    expected_access_token: str | None = None,
    clock_skew_seconds: int = 60,
    max_token_lifetime_seconds: int = 3_600,
    trusted_additional_audiences: tuple[str, ...] = (),
) -> ClaimsCheckedUntrustedOidcPayload:
    """Check ID-token claims against explicit, locally supplied flow context.

    `expected_client_id` and `expected_nonce` MUST originate from trusted,
    unconsumed client registration and the pending authorization grant.
    `now` MUST come from a trusted clock. No network access or identity creation.
    Further trust-provenance and replay checks are mandatory downstream.
    """
    if (
        not isinstance(checked, SignatureCheckedUntrustedOidcPayload)
        or not isinstance(checked.algorithm, str)
        or checked.algorithm not in _APPROVED_ALGORITHMS
        or not isinstance(checked.kid, str)
        or re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", checked.kid, re.ASCII) is None
        or not isinstance(expected_client_id, str)
        or _CLIENT_ID.fullmatch(expected_client_id) is None
        or not isinstance(expected_nonce, str)
        or _NONCE.fullmatch(expected_nonce) is None
        or not isinstance(now, int)
        or isinstance(now, bool)
        or not 1 <= now < 2**53
        or not isinstance(clock_skew_seconds, int)
        or isinstance(clock_skew_seconds, bool)
        or not 0 <= clock_skew_seconds <= _MAX_CLOCK_SKEW_SECONDS
        or not isinstance(max_token_lifetime_seconds, int)
        or isinstance(max_token_lifetime_seconds, bool)
        or not 1 <= max_token_lifetime_seconds <= _MAX_TOKEN_LIFETIME_SECONDS
        or not isinstance(trusted_additional_audiences, tuple)
        or len(trusted_additional_audiences) > _MAX_AUDIENCES - 1
        or any(
            not isinstance(item, str)
            or _AUDIENCE.fullmatch(item) is None
            or item == expected_client_id
            for item in trusted_additional_audiences
        )
        or len(set(trusted_additional_audiences)) != len(trusted_additional_audiences)
    ):
        raise OidcClaimsError("Invalid OIDC claims-validation policy or input")

    document = _parse_claims(checked.payload)
    if _PROHIBITED_UNBOUND_HASHES.intersection(document):
        raise OidcClaimsError("OIDC ID-token contains unsupported token-binding hash claims")
    _validate_optional_at_hash(
        document, expected_access_token=expected_access_token, algorithm=checked.algorithm
    )

    issuer = document.get("iss")
    subject = document.get("sub")
    nonce = document.get("nonce")
    if (
        not isinstance(issuer, str)
        or not issuer.isascii()
        or not hmac.compare_digest(issuer, CERN_OIDC_ISSUER)
    ):
        raise OidcClaimsError("OIDC ID-token issuer is not the pinned CERN issuer")
    if not isinstance(subject, str) or _SUBJECT.fullmatch(subject) is None:
        raise OidcClaimsError("Invalid OIDC ID-token subject claim")
    if (
        not isinstance(nonce, str)
        or _NONCE.fullmatch(nonce) is None
        or not hmac.compare_digest(nonce, expected_nonce)
    ):
        raise OidcClaimsError("OIDC ID-token nonce does not match authorization context")

    audiences = _audiences(document.get("aud"))
    allowed_audiences = {expected_client_id, *trusted_additional_audiences}
    if expected_client_id not in audiences or not set(audiences).issubset(allowed_audiences):
        raise OidcClaimsError("OIDC ID-token audience is not authorized for this client")
    azp = document.get("azp")
    if (len(audiences) > 1 and "azp" not in document) or (
        "azp" in document
        and (
            not isinstance(azp, str)
            or not azp.isascii()
            or not hmac.compare_digest(azp, expected_client_id)
        )
    ):
        raise OidcClaimsError("OIDC ID-token authorized party is invalid")

    expires_at = _numeric_date(document.get("exp"), claim="exp")
    issued_at = _numeric_date(document.get("iat"), claim="iat")
    if (
        expires_at <= issued_at
        or expires_at - issued_at > max_token_lifetime_seconds
        or now >= expires_at + clock_skew_seconds
        or issued_at > now + clock_skew_seconds
        or now - issued_at > max_token_lifetime_seconds + clock_skew_seconds
    ):
        raise OidcClaimsError("OIDC ID-token is expired or outside the approved time policy")

    not_before: int | None = None
    if "nbf" in document:
        not_before = _numeric_date(document["nbf"], claim="nbf")
        if not_before > now + clock_skew_seconds or not_before >= expires_at:
            raise OidcClaimsError("OIDC ID-token is not yet valid")

    if "auth_time" in document:
        authentication_time = _numeric_date(document["auth_time"], claim="auth_time")
        if authentication_time > now + clock_skew_seconds:
            raise OidcClaimsError("OIDC ID-token authentication time is in the future")
        # No max_age was requested by this flow. Never infer one here.

    return ClaimsCheckedUntrustedOidcPayload(
        issuer=issuer,
        subject=subject,
        audiences=audiences,
        authorized_party=azp if isinstance(azp, str) else None,
        nonce=nonce,
        expires_at=expires_at,
        issued_at=issued_at,
        not_before=not_before,
        algorithm=checked.algorithm,
        kid=checked.kid,
    )
