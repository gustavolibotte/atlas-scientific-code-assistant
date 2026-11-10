"""Offline end-to-end CERN OIDC check pipeline with ephemeral signing keys."""

from __future__ import annotations

import base64
import json
from dataclasses import FrozenInstanceError
from email.message import Message
from typing import cast
from urllib.request import OpenerDirector, Request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken, OidcVerificationError
from asca.infrastructure.oidc_jwks_http import HttpsCernOidcJwksFetcher
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000
CLIENT = "test-asca-client"
NONCE = "syntheticNonce_01234567890123456789012345"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


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


def claims(**changes: object) -> dict[str, object]:
    data: dict[str, object] = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "synthetic-cern-subject",
        "aud": CLIENT,
        "nonce": NONCE,
        "iat": NOW - 30,
        "exp": NOW + 300,
    }
    data.update(changes)
    return data


def key_record(
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, algorithm: str
) -> dict[str, object]:
    numbers = private.public_key().public_numbers()
    result: dict[str, object] = {"kid": "test-key", "alg": algorithm, "use": "sig"}
    if isinstance(private, rsa.RSAPrivateKey):
        result.update(
            {
                "kty": "RSA",
                "n": b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                "e": b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
            }
        )
    else:
        result.update(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": b64(numbers.x.to_bytes(32, "big")),
                "y": b64(numbers.y.to_bytes(32, "big")),
            }
        )
    return result


def sign(
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    algorithm: str,
    *,
    payload: bytes | None = None,
    header: dict[str, object] | None = None,
) -> str:
    protected = (
        header if header is not None else {"alg": algorithm, "kid": "test-key", "typ": "JWT"}
    )
    body = payload if payload is not None else json.dumps(claims(), separators=(",", ":")).encode()
    signing = (b64(json.dumps(protected, separators=(",", ":")).encode()) + "." + b64(body)).encode(
        "ascii"
    )
    if isinstance(private, rsa.RSAPrivateKey):
        pad = (
            padding.PKCS1v15()
            if algorithm == "RS256"
            else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        )
        signature = private.sign(signing, pad, hashes.SHA256())
    else:
        der = private.sign(signing, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing.decode("ascii") + "." + b64(signature)


def tokens(signed: str) -> ParsedUnverifiedOidcTokenResponse:
    return ParsedUnverifiedOidcTokenResponse(
        access_token="synthetic-access-token",
        id_token=signed,
        token_type="Bearer",
        expires_in=300,
        refresh_token=None,
        scope=None,
    )


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/jwk-set+json",
    ) -> None:
        self.body = body
        self.status = status
        self.headers = Message()
        self.headers.add_header("Content-Type", content_type)
        self.closed = False
        self.read_limit: int | None = None

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True

    def read(self, limit: int) -> bytes:
        self.read_limit = limit
        return self.body[:limit]


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[Request] = []
        self.timeouts: list[float] = []

    def open(self, request: Request, *, timeout: float) -> FakeResponse:
        self.requests.append(request)
        self.timeouts.append(timeout)
        return self.response


def pipeline(body: bytes) -> tuple[CernOidcVerificationPipeline, FakeOpener]:
    fake = FakeOpener(FakeResponse(body))
    real_fetcher_with_fake_opener = HttpsCernOidcJwksFetcher(opener=cast(OpenerDirector, fake))
    return CernOidcVerificationPipeline(fetcher=real_fetcher_with_fake_opener), fake


def jwks(private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, algorithm: str) -> bytes:
    return json.dumps({"keys": [key_record(private, algorithm)]}).encode("ascii")


def check(
    service: CernOidcVerificationPipeline, signed: str, **changes: object
) -> CheckedUntrustedCernOidcToken:
    args: dict[str, object] = {"expected_client_id": CLIENT, "expected_nonce": NONCE, "now": NOW}
    args.update(changes)
    return service.check(tokens(signed), metadata(), **args)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def rsa_private() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_private() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.mark.parametrize("algorithm", ["RS256", "PS256", "ES256"])
def test_real_signatures_and_claims_end_to_end(
    algorithm: str, rsa_private: rsa.RSAPrivateKey, ec_private: ec.EllipticCurvePrivateKey
) -> None:
    private = ec_private if algorithm == "ES256" else rsa_private
    service, opener = pipeline(jwks(private, algorithm))
    result = check(service, sign(private, algorithm))
    assert isinstance(result, CheckedUntrustedCernOidcToken)
    assert not isinstance(result, VerifiedIdentity)
    assert result.issuer == CERN_OIDC_ISSUER
    assert result.subject == "synthetic-cern-subject"
    assert result.audiences == (CLIENT,)
    assert result.kid == "test-key"
    assert result.algorithm == algorithm
    assert result.expires_at == NOW + 300
    assert result.source_url == CERN_OIDC_JWKS_URI
    assert len(opener.requests) == 1
    assert opener.requests[0].full_url == CERN_OIDC_JWKS_URI
    assert opener.requests[0].get_method() == "GET"
    assert opener.timeouts == [5.0]
    assert opener.response.read_limit == 262_145
    assert opener.response.closed
    for attr in ("identity", "roles", "principal", "authenticated", "permissions", "session"):
        assert not hasattr(result, attr)
    for raw in (CLIENT, NONCE, "synthetic-cern-subject", CERN_OIDC_JWKS_URI):
        assert raw not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.subject = "forged"  # type: ignore[misc]


def test_multiple_explicitly_allowed_audiences(rsa_private: rsa.RSAPrivateKey) -> None:
    service, _ = pipeline(jwks(rsa_private, "RS256"))
    data = json.dumps(claims(aud=[CLIENT, "service"], azp=CLIENT)).encode()
    result = check(
        service,
        sign(rsa_private, "RS256", payload=data),
        trusted_additional_audiences=("service",),
    )
    assert result.audiences == (CLIENT, "service")


def test_client_and_nonce_are_not_authenticated_by_pipeline(rsa_private: rsa.RSAPrivateKey) -> None:
    """Check success does not prove the client or nonce came from pending state."""
    service, _ = pipeline(jwks(rsa_private, "RS256"))
    result = check(service, sign(rsa_private, "RS256"))
    assert isinstance(result, CheckedUntrustedCernOidcToken)
    assert not hasattr(result, "authorization_attempt_consumed")
    assert not hasattr(result, "client_registration_attested")
    assert not hasattr(result, "session_id")


def test_default_fetcher_stays_unmounted() -> None:
    instance = CernOidcVerificationPipeline()
    assert isinstance(instance._fetcher, HttpsCernOidcJwksFetcher)
    assert not hasattr(instance, "login")
    assert not hasattr(instance, "create_session")


def test_invalid_fetcher_rejected() -> None:
    for candidate in (False, object(), "fake", 1):
        with pytest.raises(OidcVerificationError, match="transport"):
            CernOidcVerificationPipeline(fetcher=candidate)  # type: ignore[arg-type]
