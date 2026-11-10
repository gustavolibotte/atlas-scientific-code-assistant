"""Construct bounded RSA/P-256 public crypto keys from *untrusted* CERN JWKs.

This module contains no network, private key, JWT parser, signature verification,
identity construction, or login integration. A manually forged JWKS object can
reach this boundary: revalidate all public parameters before calling the backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from asca.application.oidc_jwks import select_cern_public_jwk
from asca.domain.oidc_crypto_key import OidcCryptoKeyError
from asca.domain.oidc_jwks import OidcJwksError, OidcPublicJwk, ParsedUnverifiedOidcJwks

_APPROVED_RSA_ALGORITHMS = frozenset({"RS256", "PS256"})
_MAX_RSA_MODULUS_BYTES = 1_024
_MAX_RSA_EXPONENT_BYTES = 8


@dataclass(frozen=True, slots=True)
class ConstructedUnverifiedOidcPublicKey:
    """A mathematically accepted public key, **not** a trusted issuer key.

    The key's provenance remains unverified: do not use this object directly for
    an authentication or authorization decision. The key object is deliberately
    hidden from repr; its presence alone never implies a verified JWT.
    """

    kid: str
    algorithm: str
    key_type: str
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey = field(repr=False)


def _rsa_key(key: OidcPublicJwk) -> rsa.RSAPublicKey:
    modulus = key.modulus
    exponent = key.exponent
    if (
        key.key_type != "RSA"
        or key.algorithm not in _APPROVED_RSA_ALGORITHMS
        or key.curve is not None
        or key.x_coordinate is not None
        or key.y_coordinate is not None
        or not isinstance(modulus, bytes)
        or not isinstance(exponent, bytes)
        or not 256 <= len(modulus) <= _MAX_RSA_MODULUS_BYTES
        or not 1 <= len(exponent) <= _MAX_RSA_EXPONENT_BYTES
        or modulus[0] == 0
        or exponent[0] == 0
    ):
        raise OidcCryptoKeyError("Invalid OIDC RSA public-key parameters")
    n = int.from_bytes(modulus, "big")
    e = int.from_bytes(exponent, "big")
    if (
        not 2_048 <= n.bit_length() <= 8_192
        or n % 2 != 1
        or not 3 <= e <= 0xFFFFFFFF
        or e % 2 != 1
        or e >= n
    ):
        raise OidcCryptoKeyError("Invalid OIDC RSA public-key parameters")
    try:
        result = rsa.RSAPublicNumbers(e=e, n=n).public_key()
    except (ValueError, TypeError, OverflowError, UnsupportedAlgorithm):
        raise OidcCryptoKeyError("OIDC RSA public-key construction failed") from None
    if result.key_size != n.bit_length():
        raise OidcCryptoKeyError("OIDC RSA public-key construction failed")
    return result


def _ec_key(key: OidcPublicJwk) -> ec.EllipticCurvePublicKey:
    x = key.x_coordinate
    y = key.y_coordinate
    if (
        key.key_type != "EC"
        or key.algorithm != "ES256"
        or key.curve != "P-256"
        or key.modulus is not None
        or key.exponent is not None
        or not isinstance(x, bytes)
        or not isinstance(y, bytes)
        or len(x) != 32
        or len(y) != 32
    ):
        raise OidcCryptoKeyError("Invalid OIDC P-256 public-key parameters")
    try:
        public_key = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, "big"),
            y=int.from_bytes(y, "big"),
            curve=ec.SECP256R1(),
        ).public_key()
    except (ValueError, TypeError, OverflowError, UnsupportedAlgorithm):
        raise OidcCryptoKeyError("OIDC P-256 point is not on the approved curve") from None
    if not isinstance(public_key.curve, ec.SECP256R1) or public_key.key_size != 256:
        raise OidcCryptoKeyError("OIDC P-256 public-key construction failed")
    return public_key


def construct_cern_oidc_public_key(
    jwks: ParsedUnverifiedOidcJwks,
    *,
    kid: str,
    algorithm: str,
) -> ConstructedUnverifiedOidcPublicKey:
    """Select and construct an approved public key without trusting provenance.

    Selection is exact (`kid`, `alg`) and must come from the pinned CERN JWKS
    parser's output. Neither this type nor the upstream dataclasses prove that
    an HTTPS retrieval really occurred; a future orchestration layer must bind
    bytes to the pinned TLS fetch, verify JWS, and validate OIDC claims.
    """
    try:
        declared = select_cern_public_jwk(jwks, kid=kid, algorithm=algorithm)
    except (OidcJwksError, TypeError, ValueError):
        raise OidcCryptoKeyError("OIDC public signing-key selection failed") from None
    if not isinstance(declared, OidcPublicJwk):
        raise OidcCryptoKeyError("OIDC signing-key declaration is invalid")

    if algorithm in _APPROVED_RSA_ALGORITHMS:
        public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey = _rsa_key(declared)
    elif algorithm == "ES256":
        public_key = _ec_key(declared)
    else:
        raise OidcCryptoKeyError("Unsupported OIDC public-key signing algorithm")

    return ConstructedUnverifiedOidcPublicKey(
        kid=kid,
        algorithm=algorithm,
        key_type=declared.key_type,
        public_key=public_key,
    )
