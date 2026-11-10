"""Deterministic offline signature verification tests using ephemeral signing keys."""

import base64
import json
from dataclasses import FrozenInstanceError

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI, parse_cern_public_jwks
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jws import OidcJwsError, SignatureCheckedUntrustedOidcPayload
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.infrastructure.oidc_jws import verify_untrusted_oidc_jws_signature

PAYLOAD = b'{"sub":"synthetic-subject","iss":"https://example.invalid","exp":1}'


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def rsa_private() -> rsa.RSAPrivateKey:
    """Ephemeral private key generated exclusively in process, never persisted."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_private() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


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


def jwks_for(private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, alg: str):
    public = private.public_key()
    key: dict[str, object] = {"kid": "synthetic", "use": "sig", "alg": alg}
    if isinstance(public, rsa.RSAPublicKey):
        numbers = public.public_numbers()
        key.update(
            kty="RSA",
            n=b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            e=b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        )
    else:
        numbers = public.public_numbers()
        key.update(
            kty="EC",
            crv="P-256",
            x=b64(numbers.x.to_bytes(32, "big")),
            y=b64(numbers.y.to_bytes(32, "big")),
        )
    return parse_cern_public_jwks(json.dumps({"keys": [key]}).encode("ascii"), metadata())


def sign(
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    alg: str,
    *,
    header: dict[str, object] | None = None,
    payload: bytes = PAYLOAD,
    salt_length: int = 32,
) -> str:
    head = header if header is not None else {"alg": alg, "kid": "synthetic", "typ": "JWT"}
    signing_input = (
        b64(json.dumps(head, separators=(",", ":")).encode("utf-8")) + "." + b64(payload)
    ).encode("ascii")
    if isinstance(private, rsa.RSAPrivateKey):
        scheme = (
            padding.PKCS1v15()
            if alg == "RS256"
            else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length)
        )
        signature = private.sign(signing_input, scheme, hashes.SHA256())
    else:
        der = private.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input.decode("ascii") + "." + b64(signature)


def tokens(token: str) -> ParsedUnverifiedOidcTokenResponse:
    return ParsedUnverifiedOidcTokenResponse(
        access_token="test-only",
        id_token=token,
        token_type="Bearer",
        expires_in=300,
        refresh_token=None,
        scope=None,
    )


@pytest.mark.parametrize("algorithm", ["RS256", "PS256"])
def test_valid_rsa_signature_is_not_an_identity(
    algorithm: str, rsa_private: rsa.RSAPrivateKey
) -> None:
    result = verify_untrusted_oidc_jws_signature(
        tokens(sign(rsa_private, algorithm)), jwks_for(rsa_private, algorithm)
    )
    assert isinstance(result, SignatureCheckedUntrustedOidcPayload)
    assert result.algorithm == algorithm
    assert result.kid == "synthetic"
    assert result.payload == PAYLOAD
    assert not isinstance(result, VerifiedIdentity)
    assert not hasattr(result, "identity")
    assert not hasattr(result, "claims")
    assert not hasattr(result, "session")
    assert PAYLOAD.decode("ascii") not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.payload = b"changed"  # type: ignore[misc]


def test_valid_ec_signature_is_not_an_identity(ec_private: ec.EllipticCurvePrivateKey) -> None:
    result = verify_untrusted_oidc_jws_signature(
        tokens(sign(ec_private, "ES256")), jwks_for(ec_private, "ES256")
    )
    assert result.algorithm == "ES256"
    assert result.payload == PAYLOAD
    assert not hasattr(result, "subject")


@pytest.mark.parametrize("algorithm", ["RS256", "PS256"])
def test_payload_tampering_fails(algorithm: str, rsa_private: rsa.RSAPrivateKey) -> None:
    original = sign(rsa_private, algorithm)
    h, _p, s = original.split(".")
    forged = ".".join((h, b64(b'{"sub":"attacker"}'), s))
    with pytest.raises(OidcJwsError, match="signature verification failed"):
        verify_untrusted_oidc_jws_signature(tokens(forged), jwks_for(rsa_private, algorithm))


@pytest.mark.parametrize("algorithm", ["RS256", "PS256"])
def test_wrong_key_fails(algorithm: str, rsa_private: rsa.RSAPrivateKey) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(OidcJwsError):
        verify_untrusted_oidc_jws_signature(
            tokens(sign(rsa_private, algorithm)), jwks_for(other, algorithm)
        )


def test_ps256_wrong_salt_length_fails(rsa_private: rsa.RSAPrivateKey) -> None:
    with pytest.raises(OidcJwsError):
        verify_untrusted_oidc_jws_signature(
            tokens(sign(rsa_private, "PS256", salt_length=20)), jwks_for(rsa_private, "PS256")
        )


def test_pkcs1_and_pss_cannot_be_interchanged(rsa_private: rsa.RSAPrivateKey) -> None:
    signed = sign(rsa_private, "RS256", header={"alg": "PS256", "kid": "synthetic"})
    with pytest.raises(OidcJwsError):
        verify_untrusted_oidc_jws_signature(tokens(signed), jwks_for(rsa_private, "PS256"))


def test_typ_can_be_absent(rsa_private: rsa.RSAPrivateKey) -> None:
    signed = sign(rsa_private, "RS256", header={"alg": "RS256", "kid": "synthetic"})
    assert (
        verify_untrusted_oidc_jws_signature(tokens(signed), jwks_for(rsa_private, "RS256")).payload
        == PAYLOAD
    )


def test_ec_payload_tampering_fails(ec_private: ec.EllipticCurvePrivateKey) -> None:
    original = sign(ec_private, "ES256")
    h, _p, s = original.split(".")
    with pytest.raises(OidcJwsError):
        verify_untrusted_oidc_jws_signature(
            tokens(h + "." + b64(b"bad") + "." + s), jwks_for(ec_private, "ES256")
        )


def test_ec_wrong_key_fails(ec_private: ec.EllipticCurvePrivateKey) -> None:
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(OidcJwsError):
        verify_untrusted_oidc_jws_signature(
            tokens(sign(ec_private, "ES256")), jwks_for(other, "ES256")
        )


def test_only_opaque_payload_is_returned(rsa_private: rsa.RSAPrivateKey) -> None:
    result = verify_untrusted_oidc_jws_signature(
        tokens(sign(rsa_private, "RS256", payload=b"not-json")), jwks_for(rsa_private, "RS256")
    )
    assert result.payload == b"not-json"
    assert not hasattr(result, "issuer")
    assert not hasattr(result, "audience")
    assert not hasattr(result, "authorization")


def test_tampering_approved_protected_header_invalidates_signature(
    rsa_private: rsa.RSAPrivateKey,
) -> None:
    original = sign(rsa_private, "RS256", header={"alg": "RS256", "kid": "synthetic", "typ": "JWT"})
    _h, p, s = original.split(".")
    tampered_header = b64(b'{"alg":"RS256","kid":"synthetic"}')
    with pytest.raises(OidcJwsError, match="signature verification failed"):
        verify_untrusted_oidc_jws_signature(
            tokens(tampered_header + "." + p + "." + s), jwks_for(rsa_private, "RS256")
        )
