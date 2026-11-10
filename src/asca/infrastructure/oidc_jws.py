"""Offline JWS signature verification under *untrusted-provenance* public JWKS.

This module verifies RS256, PS256, and ES256 mathematically but cannot establish
key provenance, validate OIDC claims, grant identity or create login sessions.
No HTTP, dynamic key locations, embedded JWKs or other JOSE algorithms are used.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from asca.domain.oidc_crypto_key import OidcCryptoKeyError
from asca.domain.oidc_jwks import ParsedUnverifiedOidcJwks
from asca.domain.oidc_jws import OidcJwsError, SignatureCheckedUntrustedOidcPayload
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.infrastructure.oidc_crypto_key import construct_cern_oidc_public_key

_MAX_TOKEN_CHARS = 32_768
_MAX_HEADER_CHARS = 4_096
_MAX_PAYLOAD_BYTES = 16_384
_MAX_JWS_SIGNATURE_BYTES = 1_024
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_ALLOWED_ALGS = frozenset({"RS256", "PS256", "ES256"})
_ALLOWED_HEADERS = frozenset({"alg", "kid", "typ"})
_P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def _decode_segment(value: str, *, limit: int) -> bytes:
    """Accept only canonical unpadded base64url with a fixed decoded byte cap."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4 * ((limit + 2) // 3) + 4
        or _BASE64URL.fullmatch(value) is None
    ):
        raise OidcJwsError("Invalid OIDC JWS compact encoding")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        raise OidcJwsError("Invalid OIDC JWS compact encoding") from None
    if (
        not raw
        or len(raw) > limit
        or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value
    ):
        raise OidcJwsError("Invalid OIDC JWS compact encoding")
    return raw


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise OidcJwsError("OIDC JWS protected header has duplicate JSON members")
        document[key] = value
    return document


def _reject_constant(_value: str) -> None:
    raise OidcJwsError("OIDC JWS protected header is not strict JSON")


def _protected_header(raw: bytes) -> tuple[str, str]:
    try:
        decoded: Any = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_constant,
        )
    except OidcJwsError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise OidcJwsError("OIDC JWS protected header is not strict JSON") from None
    if not isinstance(decoded, dict) or set(decoded) - _ALLOWED_HEADERS:
        raise OidcJwsError("OIDC JWS protected header is not approved")
    alg, kid = decoded.get("alg"), decoded.get("kid")
    if (
        not isinstance(alg, str)
        or alg not in _ALLOWED_ALGS
        or not isinstance(kid, str)
        or not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", kid, re.ASCII)
        or ("typ" in decoded and decoded["typ"] != "JWT")
    ):
        raise OidcJwsError("OIDC JWS protected header is not approved")
    return alg, kid


def _verify_signature(
    algorithm: str,
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    signature: bytes,
    signing_input: bytes,
) -> None:
    try:
        if algorithm in {"RS256", "PS256"}:
            if not isinstance(key, rsa.RSAPublicKey) or len(signature) != (key.key_size + 7) // 8:
                raise OidcJwsError("OIDC JWS signature format is invalid")
            rsa_padding: padding.AsymmetricPadding = (
                padding.PKCS1v15()
                if algorithm == "RS256"
                else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            )
            key.verify(signature, signing_input, rsa_padding, hashes.SHA256())
        elif algorithm == "ES256":
            if (
                not isinstance(key, ec.EllipticCurvePublicKey)
                or not isinstance(key.curve, ec.SECP256R1)
                or len(signature) != 64
            ):
                raise OidcJwsError("OIDC JWS signature format is invalid")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
                raise OidcJwsError("OIDC JWS signature format is invalid")
            der = utils.encode_dss_signature(r, s)
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        else:
            raise OidcJwsError("OIDC JWS signing algorithm is not approved")
    except OidcJwsError:
        raise
    except (InvalidSignature, ValueError, TypeError, OverflowError, UnsupportedAlgorithm):
        raise OidcJwsError("OIDC JWS signature verification failed") from None


def verify_untrusted_oidc_jws_signature(
    tokens: ParsedUnverifiedOidcTokenResponse,
    jwks: ParsedUnverifiedOidcJwks,
) -> SignatureCheckedUntrustedOidcPayload:
    """Check a compact ID-token JWS without interpreting or trusting its claims.

    The caller must separately establish trusted HTTPS provenance for the JWKS.
    This method does not implement OIDC issuer/audience/nonce/exp validation.
    """
    if (
        not isinstance(tokens, ParsedUnverifiedOidcTokenResponse)
        or not isinstance(jwks, ParsedUnverifiedOidcJwks)
        or not isinstance(tokens.id_token, str)
        or not 1 <= len(tokens.id_token) <= _MAX_TOKEN_CHARS
        or not tokens.id_token.isascii()
    ):
        raise OidcJwsError("Invalid unverified OIDC JWS input")
    segments = tokens.id_token.split(".")
    if len(segments) != 3 or len(segments[0]) > _MAX_HEADER_CHARS:
        raise OidcJwsError("Invalid OIDC JWS compact representation")
    protected_bytes = _decode_segment(segments[0], limit=3_072)
    payload = _decode_segment(segments[1], limit=_MAX_PAYLOAD_BYTES)
    signature = _decode_segment(segments[2], limit=_MAX_JWS_SIGNATURE_BYTES)
    algorithm, kid = _protected_header(protected_bytes)
    try:
        selected = construct_cern_oidc_public_key(jwks, kid=kid, algorithm=algorithm)
    except OidcCryptoKeyError:
        raise OidcJwsError("OIDC JWS signing key was rejected") from None
    if (
        selected.algorithm != algorithm
        or selected.kid != kid
        or selected.key_type not in {"RSA", "EC"}
    ):
        raise OidcJwsError("OIDC JWS signing key was rejected")
    signing_input = (segments[0] + "." + segments[1]).encode("ascii")
    _verify_signature(algorithm, selected.public_key, signature, signing_input)
    return SignatureCheckedUntrustedOidcPayload(algorithm=algorithm, kid=kid, payload=payload)
