"""Strict offline parsing and selection of CERN OIDC public signing JWKs.

A future TLS-verifying JWKS fetcher must pin the metadata URL and authenticate
its source. Parsing and key selection alone do not validate JWT signatures.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from decimal import Decimal
from typing import Any

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks import OidcJwksError, OidcPublicJwk, ParsedUnverifiedOidcJwks

CERN_OIDC_JWKS_URI = CERN_OIDC_ISSUER + "/protocol/openid-connect/certs"
_MAX_DOCUMENT_BYTES = 262_144
_MAX_KEYS = 64
_APPROVED_ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})
_RSA_ALGORITHMS = frozenset({"RS256", "PS256"})
_KID_PATTERN = re.compile(r"[A-Za-z0-9._~-]{1,128}\Z", re.ASCII)
_BASE64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_FORBIDDEN_KEY_FIELDS = frozenset(
    {"d", "p", "q", "dp", "dq", "qi", "oth", "k", "x5u", "jku", "jwk"}
)


def _reject_duplicate_json_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise OidcJwksError("OIDC JWKS has duplicate JSON members")
        result[name] = value
    return result


def _reject_nonfinite_json(_value: str) -> None:
    raise OidcJwksError("OIDC JWKS has invalid numeric constants")


def _decode_public_parameter(value: object, *, maximum_bytes: int) -> bytes:
    """Reject padded, ambiguous, oversized, or noncanonical base64url integers."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > ((maximum_bytes + 2) * 4 // 3)
        or not _BASE64URL_PATTERN.fullmatch(value)
    ):
        raise OidcJwksError("Invalid OIDC JWK public parameter")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        raise OidcJwksError("Invalid OIDC JWK public parameter") from None
    if (
        not raw
        or len(raw) > maximum_bytes
        or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value
    ):
        raise OidcJwksError("Invalid OIDC JWK public parameter")
    return raw


def _parse_supported_key(key: dict[str, object]) -> OidcPublicJwk | None:
    if _FORBIDDEN_KEY_FIELDS.intersection(key):
        raise OidcJwksError("OIDC JWKS contains private or externally referenced key material")

    kid = key.get("kid")
    algorithm = key.get("alg")
    key_type = key.get("kty")
    usage = key.get("use")
    operations = key.get("key_ops")
    if (
        not isinstance(kid, str)
        or not _KID_PATTERN.fullmatch(kid)
        or not isinstance(algorithm, str)
        or not isinstance(key_type, str)
        or not isinstance(usage, str)
    ):
        raise OidcJwksError("Invalid OIDC JWK key identifier or algorithm declaration")
    if operations is not None and operations != ["verify"]:
        raise OidcJwksError("OIDC JWK has incompatible key operations")

    # Other public key types, encryption keys, and nonapproved signing
    # algorithms are never selected. Keep document-wide kid uniqueness.
    if usage != "sig" or algorithm not in _APPROVED_ALGORITHMS:
        return None
    if key_type == "RSA" and algorithm in _RSA_ALGORITHMS:
        if any(field in key for field in ("crv", "x", "y")):
            raise OidcJwksError("OIDC RSA key contains incompatible public parameters")
        modulus = _decode_public_parameter(key.get("n"), maximum_bytes=1_024)
        exponent = _decode_public_parameter(key.get("e"), maximum_bytes=8)
        if modulus[0] == 0 or not 2_048 <= int.from_bytes(modulus, "big").bit_length() <= 8_192:
            raise OidcJwksError("OIDC RSA modulus is not within the approved size range")
        e = int.from_bytes(exponent, "big")
        if exponent[0] == 0 or not 3 <= e <= 0xFFFFFFFF or e % 2 != 1:
            raise OidcJwksError("OIDC RSA exponent is invalid")
        return OidcPublicJwk(
            kid=kid, algorithm=algorithm, key_type="RSA", modulus=modulus, exponent=exponent
        )
    if key_type == "EC" and algorithm == "ES256":
        if any(field in key for field in ("n", "e")):
            raise OidcJwksError("OIDC EC key contains incompatible public parameters")
        if key.get("crv") != "P-256":
            raise OidcJwksError("OIDC elliptic curve is not approved")
        x = _decode_public_parameter(key.get("x"), maximum_bytes=32)
        y = _decode_public_parameter(key.get("y"), maximum_bytes=32)
        if len(x) != 32 or len(y) != 32:
            raise OidcJwksError("OIDC P-256 coordinate length is invalid")
        # Point-on-curve and signature checks belong to the crypto adapter.
        return OidcPublicJwk(
            kid=kid,
            algorithm=algorithm,
            key_type="EC",
            curve="P-256",
            x_coordinate=x,
            y_coordinate=y,
        )
    raise OidcJwksError("OIDC JWK key type does not match signing algorithm")


def parse_cern_public_jwks(
    raw_json: bytes, metadata: OidcProviderMetadata
) -> ParsedUnverifiedOidcJwks:
    """Parse bytes previously fetched from the *pinned* CERN JWKS endpoint.

    Never fetch user-supplied URLs here. Metadata and returned dataclasses can
    be forged in Python; the caller must independently establish TLS provenance.
    """
    if (
        not isinstance(metadata, OidcProviderMetadata)
        or metadata.issuer != CERN_OIDC_ISSUER
        or metadata.jwks_uri != CERN_OIDC_JWKS_URI
        or not isinstance(metadata.approved_id_token_algorithms, tuple)
        or not metadata.approved_id_token_algorithms
        or any(alg not in _APPROVED_ALGORITHMS for alg in metadata.approved_id_token_algorithms)
        or not metadata.supports_authorization_code
        or not metadata.supports_pkce_s256
    ):
        raise OidcJwksError("OIDC JWKS metadata violates CERN trust policy")
    if not isinstance(raw_json, bytes) or not 0 < len(raw_json) <= _MAX_DOCUMENT_BYTES:
        raise OidcJwksError("OIDC JWKS document size is invalid")
    try:
        document: Any = json.loads(
            raw_json.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_members,
            parse_constant=_reject_nonfinite_json,
            parse_float=Decimal,
        )
    except OidcJwksError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        raise OidcJwksError("OIDC JWKS is not strict UTF-8 JSON") from None

    if not isinstance(document, dict) or "keys" not in document:
        raise OidcJwksError("OIDC JWKS is missing the keys collection")
    declared_keys = document["keys"]
    if not isinstance(declared_keys, list) or not 1 <= len(declared_keys) <= _MAX_KEYS:
        raise OidcJwksError("OIDC JWKS key collection is invalid")

    accepted: list[OidcPublicJwk] = []
    seen_kids: set[str] = set()
    for declared in declared_keys:
        if not isinstance(declared, dict):
            raise OidcJwksError("Invalid OIDC JWKS key entry")
        kid = declared.get("kid")
        if not isinstance(kid, str) or not _KID_PATTERN.fullmatch(kid) or kid in seen_kids:
            raise OidcJwksError("OIDC JWKS contains missing or ambiguous key identifiers")
        seen_kids.add(kid)
        public_key = _parse_supported_key(declared)
        if public_key is not None:
            accepted.append(public_key)
    if not accepted:
        raise OidcJwksError("OIDC JWKS has no approved public signing keys")
    return ParsedUnverifiedOidcJwks(
        issuer=CERN_OIDC_ISSUER,
        jwks_uri=CERN_OIDC_JWKS_URI,
        approved_algorithms=tuple(sorted(set(metadata.approved_id_token_algorithms))),
        keys=tuple(accepted),
    )


def select_cern_public_jwk(
    jwks: ParsedUnverifiedOidcJwks, *, kid: str, algorithm: str
) -> OidcPublicJwk:
    """Select exactly one matching declared public key; never verify a JWT."""
    if (
        not isinstance(jwks, ParsedUnverifiedOidcJwks)
        or jwks.issuer != CERN_OIDC_ISSUER
        or jwks.jwks_uri != CERN_OIDC_JWKS_URI
        or not isinstance(kid, str)
        or not _KID_PATTERN.fullmatch(kid)
        or not isinstance(algorithm, str)
        or algorithm not in _APPROVED_ALGORITHMS
        or algorithm not in jwks.approved_algorithms
        or not isinstance(jwks.keys, tuple)
    ):
        raise OidcJwksError("OIDC signing-key selection violates trust policy")
    candidates = [key for key in jwks.keys if isinstance(key, OidcPublicJwk) and key.kid == kid]
    if len(candidates) != 1 or candidates[0].algorithm != algorithm:
        raise OidcJwksError("OIDC signing-key identifier or algorithm is unavailable")
    return candidates[0]
