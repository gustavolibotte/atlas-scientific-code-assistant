"""Offline JWKS declaration and key-selection tests; no cryptographic validation."""

import base64
import json
from dataclasses import FrozenInstanceError

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import (
    CERN_OIDC_JWKS_URI,
    parse_cern_public_jwks,
    select_cern_public_jwk,
)
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks import OidcJwksError, OidcPublicJwk, ParsedUnverifiedOidcJwks


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


RSA_MODULUS = b"\x80" + b"\x01" * 255
RSA_EXPONENT = b"\x01\x00\x01"


def rsa_key(*, kid: str = "rsa-key", algorithm: str = "RS256") -> dict[str, object]:
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": algorithm,
        "n": encoded(RSA_MODULUS),
        "e": encoded(RSA_EXPONENT),
    }


def ec_key(*, kid: str = "ec-key") -> dict[str, object]:
    return {
        "kty": "EC",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "x": encoded(b"\x01" * 32),
        "y": encoded(b"\x02" * 32),
    }


def provider(approved: tuple[str, ...] = ("RS256", "PS256", "ES256")) -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_JWKS_URI,
        approved_id_token_algorithms=approved,
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def payload(*keys: dict[str, object]) -> bytes:
    return json.dumps({"keys": keys}, separators=(",", ":")).encode("utf-8")


def test_rsa_keys_are_selected_by_exact_kid_and_algorithm() -> None:
    jwks = parse_cern_public_jwks(
        payload(rsa_key(), rsa_key(kid="rsa-ps", algorithm="PS256")), provider()
    )
    assert isinstance(jwks, ParsedUnverifiedOidcJwks)
    key = select_cern_public_jwk(jwks, kid="rsa-key", algorithm="RS256")
    assert isinstance(key, OidcPublicJwk)
    assert not isinstance(key, VerifiedIdentity)
    assert key.key_type == "RSA"
    assert key.algorithm == "RS256"
    assert key.modulus == RSA_MODULUS
    assert key.exponent == RSA_EXPONENT
    assert key.x_coordinate is None
    assert key.y_coordinate is None
    assert select_cern_public_jwk(jwks, kid="rsa-ps", algorithm="PS256").algorithm == "PS256"
    assert jwks.approved_algorithms == ("ES256", "PS256", "RS256")


def test_es256_jwk_parameters_are_bounded_but_not_verified() -> None:
    jwks = parse_cern_public_jwks(payload(ec_key()), provider())
    key = select_cern_public_jwk(jwks, kid="ec-key", algorithm="ES256")
    assert key.key_type == "EC"
    assert key.curve == "P-256"
    assert key.x_coordinate == b"\x01" * 32
    assert key.y_coordinate == b"\x02" * 32
    assert key.modulus is None
    assert not hasattr(key, "verified_identity")
    assert not hasattr(key, "verified_signature")
    assert not hasattr(jwks, "authenticated_user")


def test_public_jwk_objects_are_immutable_and_hide_material() -> None:
    jwks = parse_cern_public_jwks(payload(rsa_key()), provider())
    key = jwks.keys[0]
    assert encoded(RSA_MODULUS) not in repr(key)
    assert encoded(RSA_MODULUS) not in repr(jwks)
    with pytest.raises(FrozenInstanceError):
        key.algorithm = "HS256"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        jwks.keys = ()  # type: ignore[misc]


def test_rsa_and_ec_key_declarations_can_coexist() -> None:
    jwks = parse_cern_public_jwks(payload(rsa_key(), ec_key()), provider())
    assert len(jwks.keys) == 2
    assert {key.key_type for key in jwks.keys} == {"RSA", "EC"}


def test_key_ops_verify_is_allowed() -> None:
    key = rsa_key()
    key["key_ops"] = ["verify"]
    assert parse_cern_public_jwks(payload(key), provider()).keys[0].kid == "rsa-key"


def test_public_x509_metadata_is_not_used_as_key_material() -> None:
    key = rsa_key()
    key["x5c"] = ["certificate-only-no-verification"]
    key["x5t"] = "synthetic-sha1-thumbprint"
    key["x5t#S256"] = "synthetic-sha256-thumbprint"
    selected = parse_cern_public_jwks(payload(key), provider()).keys[0]
    assert selected.modulus == RSA_MODULUS
    assert not hasattr(selected, "x5c")


def test_non_signing_encryption_key_is_skipped_without_granting_authority() -> None:
    key = rsa_key(kid="encryption-key")
    key.update(use="enc", alg="RSA-OAEP")
    jwks = parse_cern_public_jwks(payload(key, ec_key()), provider())
    assert len(jwks.keys) == 1
    assert jwks.keys[0].kid == "ec-key"
    with pytest.raises(OidcJwksError):
        select_cern_public_jwk(jwks, kid="encryption-key", algorithm="ES256")


def test_unsupported_algorithm_is_skipped_when_valid_key_exists() -> None:
    key = rsa_key(kid="unsupported", algorithm="RS512")
    jwks = parse_cern_public_jwks(payload(key, rsa_key()), provider())
    assert len(jwks.keys) == 1
    assert jwks.keys[0].kid == "rsa-key"


@pytest.mark.parametrize("algorithm", ["none", "HS256", "RS512", "ES384", "rs256", "PS512"])
def test_unsupported_algorithm_cannot_select_a_key(algorithm: str) -> None:
    jwks = parse_cern_public_jwks(payload(rsa_key()), provider())
    with pytest.raises(OidcJwksError):
        select_cern_public_jwk(jwks, kid="rsa-key", algorithm=algorithm)


def test_provider_algorithm_allowlist_is_enforced_at_selection() -> None:
    jwks = parse_cern_public_jwks(payload(rsa_key(), ec_key()), provider(("ES256",)))
    assert select_cern_public_jwk(jwks, kid="ec-key", algorithm="ES256").kid == "ec-key"
    with pytest.raises(OidcJwksError):
        select_cern_public_jwk(jwks, kid="rsa-key", algorithm="RS256")


@pytest.mark.parametrize("kid", ["", "missing", "rsa-key ", "../rsa-key", "é", "a" * 129])
def test_invalid_or_unknown_key_identifier_is_not_selected(kid: str) -> None:
    jwks = parse_cern_public_jwks(payload(rsa_key()), provider())
    with pytest.raises(OidcJwksError):
        select_cern_public_jwk(jwks, kid=kid, algorithm="RS256")


def test_selector_never_falls_back_to_another_kid_or_algorithm() -> None:
    jwks = parse_cern_public_jwks(payload(rsa_key(), ec_key()), provider())
    with pytest.raises(OidcJwksError):
        select_cern_public_jwk(jwks, kid="rsa-key", algorithm="ES256")
    with pytest.raises(OidcJwksError):
        select_cern_public_jwk(jwks, kid="ec-key", algorithm="RS256")


def test_non_approved_jwk_only_collection_is_rejected() -> None:
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(rsa_key(algorithm="HS256")), provider())


def test_key_selection_does_not_return_tokens_or_identity() -> None:
    selected = select_cern_public_jwk(
        parse_cern_public_jwks(payload(rsa_key()), provider()), kid="rsa-key", algorithm="RS256"
    )
    for attr in ("access_token", "id_token", "subject", "identity", "session_id"):
        assert not hasattr(selected, attr)
