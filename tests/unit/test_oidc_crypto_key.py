"""Offline construction tests: public-key validity is not proof of identity."""

import base64
import json
from dataclasses import FrozenInstanceError

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI, parse_cern_public_jwks
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.infrastructure.oidc_crypto_key import (
    ConstructedUnverifiedOidcPublicKey,
    construct_cern_oidc_public_key,
)

GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def rsa_key(kid: str = "rsa-1", algorithm: str = "RS256", length: int = 256) -> dict[str, object]:
    return {
        "kid": kid,
        "kty": "RSA",
        "use": "sig",
        "alg": algorithm,
        "n": b64(b"\x80" + b"\x01" * (length - 1)),
        "e": b64(b"\x01\x00\x01"),
    }


def ec_key(kid: str = "ec-1") -> dict[str, object]:
    return {
        "kid": kid,
        "kty": "EC",
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "x": b64(GX),
        "y": b64(GY),
    }


def metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_JWKS_URI,
        approved_id_token_algorithms=("RS256", "PS256", "ES256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def jwks(*keys: dict[str, object]):
    return parse_cern_public_jwks(json.dumps({"keys": keys}).encode("ascii"), metadata())


@pytest.mark.parametrize("algorithm", ["RS256", "PS256"])
@pytest.mark.parametrize("length", [256, 384, 1024])
def test_rsa_public_key_construction(algorithm: str, length: int) -> None:
    parsed = jwks(rsa_key(algorithm=algorithm, length=length))
    selected = construct_cern_oidc_public_key(parsed, kid="rsa-1", algorithm=algorithm)
    assert isinstance(selected, ConstructedUnverifiedOidcPublicKey)
    assert isinstance(selected.public_key, rsa.RSAPublicKey)
    assert selected.public_key.key_size == 8 * length
    numbers = selected.public_key.public_numbers()
    assert numbers.e == 65537
    assert numbers.n == int.from_bytes(b"\x80" + b"\x01" * (length - 1), "big")
    assert selected.key_type == "RSA"
    assert selected.algorithm == algorithm
    assert not isinstance(selected, VerifiedIdentity)
    assert not hasattr(selected, "verified_signature")
    assert not hasattr(selected, "authenticated_identity")


def test_p256_generator_is_accepted_on_curve() -> None:
    selected = construct_cern_oidc_public_key(jwks(ec_key()), kid="ec-1", algorithm="ES256")
    assert isinstance(selected.public_key, ec.EllipticCurvePublicKey)
    assert isinstance(selected.public_key.curve, ec.SECP256R1)
    assert selected.public_key.key_size == 256
    assert selected.public_key.public_numbers().x == int.from_bytes(GX, "big")
    assert selected.public_key.public_numbers().y == int.from_bytes(GY, "big")
    assert selected.algorithm == "ES256"
    assert selected.key_type == "EC"
    assert not isinstance(selected, VerifiedIdentity)


def test_mixed_public_jwks_require_exact_kid_and_algorithm() -> None:
    parsed = jwks(
        rsa_key(kid="rs256", algorithm="RS256"),
        rsa_key(kid="ps256", algorithm="PS256"),
        ec_key(),
    )
    assert construct_cern_oidc_public_key(parsed, kid="rs256", algorithm="RS256").key_type == "RSA"
    assert construct_cern_oidc_public_key(parsed, kid="ps256", algorithm="PS256").key_type == "RSA"
    assert construct_cern_oidc_public_key(parsed, kid="ec-1", algorithm="ES256").key_type == "EC"


def test_public_object_is_frozen_and_hidden_from_repr() -> None:
    selected = construct_cern_oidc_public_key(jwks(rsa_key()), kid="rsa-1", algorithm="RS256")
    assert "modulus" not in repr(selected)
    assert "public_key=" not in repr(selected)
    assert "RSA" in repr(selected)
    with pytest.raises(FrozenInstanceError):
        selected.algorithm = "HS256"  # type: ignore[misc]


def test_no_credential_or_authorization_semantics() -> None:
    selected = construct_cern_oidc_public_key(jwks(ec_key()), kid="ec-1", algorithm="ES256")
    for name in (
        "id_token",
        "access_token",
        "refresh_token",
        "issuer_verified",
        "session_id",
        "user",
        "roles",
        "permissions",
        "jws_verified",
        "trusted_origin",
    ):
        assert not hasattr(selected, name)
