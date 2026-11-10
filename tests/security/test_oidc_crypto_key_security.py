"""Adversarial, offline tests of cryptographic JWK public-key construction."""

import base64
import json
import socket
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI, parse_cern_public_jwks
from asca.domain.oidc_crypto_key import OidcCryptoKeyError
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks import OidcPublicJwk
from asca.infrastructure.oidc_crypto_key import construct_cern_oidc_public_key

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


def modified_rsa(**changes: object):
    parsed = jwks(rsa_key())
    return replace(parsed, keys=(replace(parsed.keys[0], **changes),))


def modified_ec(**changes: object):
    parsed = jwks(ec_key())
    return replace(parsed, keys=(replace(parsed.keys[0], **changes),))


@pytest.mark.parametrize(
    "kid,algorithm",
    [
        ("", "RS256"),
        ("absent", "RS256"),
        ("rsa-1", "ES256"),
        ("rsa-1", "HS256"),
        ("rsa-1", "none"),
        ("rsa-1", "PS256"),
        ("rsa-1", "rs256"),
        ("rsa-1 ", "RS256"),
        (None, "RS256"),
        ("rsa-1", None),
        ("rsa-1", 3),
        (1, "RS256"),
    ],
)
def test_selection_fails_closed(kid: object, algorithm: object) -> None:
    with pytest.raises(OidcCryptoKeyError, match="selection failed"):
        construct_cern_oidc_public_key(
            jwks(rsa_key()),
            kid=kid,
            algorithm=algorithm,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("container", [None, {}, object(), "jwks", 42])
def test_non_jwks_inputs_fail_closed(container: object) -> None:
    with pytest.raises(OidcCryptoKeyError):
        construct_cern_oidc_public_key(container, kid="rsa-1", algorithm="RS256")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    [
        {"key_type": "EC"},
        {"curve": "P-256"},
        {"x_coordinate": GX},
        {"y_coordinate": GY},
        {"modulus": None},
        {"modulus": b""},
        {"modulus": "not bytes"},
        {"modulus": 42},
        {"modulus": b"\x00" + b"\x80" + b"\x01" * 255},
        {"modulus": b"\x7f" + b"\x01" * 255},
        {"modulus": b"\x80" + b"\x01" * 254},
        {"modulus": b"\x80" + b"\x01" * 1024},
        {"modulus": b"\x80" + b"\x00" * 255},
        {"exponent": None},
        {"exponent": b""},
        {"exponent": "65537"},
        {"exponent": b"\x00\x01\x00\x01"},
        {"exponent": b"\x01"},
        {"exponent": b"\x02"},
        {"exponent": b"\x04"},
        {"exponent": b"\xff" * 9},
        {"exponent": b"\x01\x00\x00\x00\x01"},
    ],
)
def test_forged_rsa_parameters_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(OidcCryptoKeyError):
        construct_cern_oidc_public_key(modified_rsa(**changes), kid="rsa-1", algorithm="RS256")


@pytest.mark.parametrize(
    "changes",
    [
        {"key_type": "RSA"},
        {"curve": "P-384"},
        {"curve": None},
        {"x_coordinate": None},
        {"y_coordinate": None},
        {"x_coordinate": b"\x00" * 32},
        {"y_coordinate": b"\x00" * 32},
        {"x_coordinate": b"\x01" * 32},
        {"y_coordinate": b"\x02" * 32},
        {"x_coordinate": "not bytes"},
        {"y_coordinate": "not bytes"},
        {"x_coordinate": b"\x00" * 31},
        {"y_coordinate": b"\x00" * 33},
        {"modulus": b"\x01"},
        {"exponent": b"\x03"},
        {"x_coordinate": b"\xff" * 32},
        {"y_coordinate": b"\xff" * 32},
    ],
)
def test_forged_or_off_curve_ec_points_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(OidcCryptoKeyError):
        construct_cern_oidc_public_key(modified_ec(**changes), kid="ec-1", algorithm="ES256")


def test_forged_jwks_metadata_not_accepted() -> None:
    parsed = jwks(rsa_key())
    for forged in (
        replace(parsed, issuer="https://evil.invalid"),
        replace(parsed, jwks_uri="https://evil.invalid/keys"),
        replace(parsed, approved_algorithms=("HS256",)),
        replace(parsed, keys=()),
    ):
        with pytest.raises(OidcCryptoKeyError):
            construct_cern_oidc_public_key(forged, kid="rsa-1", algorithm="RS256")


def test_key_selector_cannot_promote_non_jwk_objects() -> None:
    parsed = jwks(rsa_key())
    replaced = replace(parsed, keys=("not a JWK",))
    with pytest.raises(OidcCryptoKeyError):
        construct_cern_oidc_public_key(replaced, kid="rsa-1", algorithm="RS256")


def test_key_selector_cannot_select_same_kid_forged_different_algorithm() -> None:
    parsed = jwks(rsa_key())
    replaced = replace(parsed, keys=(replace(parsed.keys[0], algorithm="ES256"),))
    with pytest.raises(OidcCryptoKeyError):
        construct_cern_oidc_public_key(replaced, kid="rsa-1", algorithm="RS256")


def test_key_selector_no_duplicates_or_fallback() -> None:
    parsed = jwks(rsa_key())
    replaced = replace(parsed, keys=(parsed.keys[0], parsed.keys[0]))
    with pytest.raises(OidcCryptoKeyError):
        construct_cern_oidc_public_key(replaced, kid="rsa-1", algorithm="RS256")


def test_public_numbers_cannot_be_used_as_signing_private_key() -> None:
    selected = construct_cern_oidc_public_key(jwks(rsa_key()), kid="rsa-1", algorithm="RS256")
    assert isinstance(selected.public_key, rsa.RSAPublicKey)
    assert not isinstance(selected.public_key, rsa.RSAPrivateKey)
    assert not hasattr(selected.public_key, "sign")
    selected_ec = construct_cern_oidc_public_key(jwks(ec_key()), kid="ec-1", algorithm="ES256")
    assert isinstance(selected_ec.public_key, ec.EllipticCurvePublicKey)
    assert not isinstance(selected_ec.public_key, ec.EllipticCurvePrivateKey)
    assert not hasattr(selected_ec.public_key, "sign")


def test_error_does_not_echo_malformed_public_key() -> None:
    forged = modified_ec(x_coordinate=b"\xff" * 32)
    with pytest.raises(OidcCryptoKeyError) as raised:
        construct_cern_oidc_public_key(forged, kid="ec-1", algorithm="ES256")
    assert "ff" * 8 not in str(raised.value)
    assert "ff" * 8 not in repr(raised.value)


def test_crypto_key_construction_uses_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Unexpected network access during key construction")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    construct_cern_oidc_public_key(jwks(rsa_key()), kid="rsa-1", algorithm="RS256")
    construct_cern_oidc_public_key(jwks(ec_key()), kid="ec-1", algorithm="ES256")


def test_signature_verification_and_identity_are_not_claimed() -> None:
    selected = construct_cern_oidc_public_key(jwks(ec_key()), kid="ec-1", algorithm="ES256")
    assert isinstance(selected.public_key, ec.EllipticCurvePublicKey)
    for attribute in ("signature_valid", "verified_claims", "id_token", "issuer_verified"):
        assert not hasattr(selected, attribute)


def test_selected_jwk_public_bytes_remain_unmodified() -> None:
    parsed = jwks(rsa_key())
    before: OidcPublicJwk = parsed.keys[0]
    construct_cern_oidc_public_key(parsed, kid="rsa-1", algorithm="RS256")
    assert parsed.keys[0] is before


def test_rsa_backend_construction_failure_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    from asca.infrastructure import oidc_crypto_key as adapter

    def fail(*args: object, **kwargs: object) -> None:
        raise ValueError("private-backend-error")

    monkeypatch.setattr(adapter.rsa, "RSAPublicNumbers", fail)
    with pytest.raises(OidcCryptoKeyError) as caught:
        construct_cern_oidc_public_key(jwks(rsa_key()), kid="rsa-1", algorithm="RS256")
    assert "private-backend-error" not in str(caught.value)


def test_rsa_backend_returned_size_must_match(monkeypatch: pytest.MonkeyPatch) -> None:
    from asca.infrastructure import oidc_crypto_key as adapter

    class BogusPublicNumbers:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def public_key(self) -> object:
            class BadKey:
                key_size = 1024

            return BadKey()

    monkeypatch.setattr(adapter.rsa, "RSAPublicNumbers", BogusPublicNumbers)
    with pytest.raises(OidcCryptoKeyError, match="construction failed"):
        construct_cern_oidc_public_key(jwks(rsa_key()), kid="rsa-1", algorithm="RS256")


def test_ec_backend_response_type_and_curve_are_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    from asca.infrastructure import oidc_crypto_key as adapter

    class BogusNumbers:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def public_key(self) -> object:
            class BogusKey:
                curve = ec.SECP384R1()
                key_size = 384

            return BogusKey()

    monkeypatch.setattr(adapter.ec, "EllipticCurvePublicNumbers", BogusNumbers)
    with pytest.raises(OidcCryptoKeyError, match="construction failed"):
        construct_cern_oidc_public_key(jwks(ec_key()), kid="ec-1", algorithm="ES256")


def test_unexpected_selector_output_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from asca.infrastructure import oidc_crypto_key as adapter

    monkeypatch.setattr(adapter, "select_cern_public_jwk", lambda *_a, **_kw: "not-a-key")
    with pytest.raises(OidcCryptoKeyError, match="declaration is invalid"):
        construct_cern_oidc_public_key(jwks(rsa_key()), kid="rsa-1", algorithm="RS256")


def test_unsupported_algorithm_fail_closed_even_if_selector_is_bypassed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from asca.infrastructure import oidc_crypto_key as adapter

    original = jwks(rsa_key()).keys[0]
    monkeypatch.setattr(adapter, "select_cern_public_jwk", lambda *_a, **_kw: original)
    with pytest.raises(OidcCryptoKeyError, match="Unsupported"):
        construct_cern_oidc_public_key(jwks(rsa_key()), kid="rsa-1", algorithm="HS256")
