"""Offline real-signature tests of one-fetch CERN role observation composition."""

from __future__ import annotations

import base64
import hashlib
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
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_role_claims import UntrustedCernRoleObservation
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_jwks_http import HttpsCernOidcJwksFetcher
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000
CLIENT = "asca-glibotte-dev"
NONCE = "syntheticNonce_01234567890123456789012345"
ROLE = "asca-developer"
TOKEN = "synthetic-access-token"


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


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
    digest = hashlib.sha256(TOKEN.encode("ascii")).digest()
    document: dict[str, object] = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "synthetic-user",
        "aud": CLIENT,
        "nonce": NONCE,
        "iat": NOW - 30,
        "exp": NOW + 300,
        "at_hash": b64(digest[:16]),
        "resource_access": {CLIENT: {"roles": [ROLE]}},
        "cern_roles": [ROLE],
    }
    document.update(changes)
    return document


def public_jwk(
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, algorithm: str
) -> dict[str, object]:
    numbers = private.public_key().public_numbers()
    record: dict[str, object] = {"kid": "synthetic-key", "alg": algorithm, "use": "sig"}
    if isinstance(private, rsa.RSAPrivateKey):
        record.update(
            kty="RSA",
            n=b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            e=b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        )
    else:
        record.update(
            kty="EC",
            crv="P-256",
            x=b64(numbers.x.to_bytes(32, "big")),
            y=b64(numbers.y.to_bytes(32, "big")),
        )
    return record


def signed_token(
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    algorithm: str,
    payload: dict[str, object],
) -> str:
    head = b64(json.dumps({"alg": algorithm, "kid": "synthetic-key"}).encode())
    body = b64(json.dumps(payload).encode())
    message = (head + "." + body).encode("ascii")
    if isinstance(private, rsa.RSAPrivateKey):
        mode = (
            padding.PKCS1v15()
            if algorithm == "RS256"
            else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        )
        signature = private.sign(message, mode, hashes.SHA256())
    else:
        der = private.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return head + "." + body + "." + b64(signature)


def tokens(jwt: str, *, access_token: str = TOKEN) -> ParsedUnverifiedOidcTokenResponse:
    return ParsedUnverifiedOidcTokenResponse(
        access_token=access_token,
        id_token=jwt,
        token_type="Bearer",
        expires_in=300,
        refresh_token=None,
        scope=None,
    )


class FakeResponse:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.status = 200
        self.headers = Message()
        self.headers.add_header("Content-Type", "application/jwk-set+json")

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.raw[:limit]


class FakeOpener:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.requests: list[Request] = []

    def open(self, request: Request, *, timeout: float) -> FakeResponse:
        assert timeout == 5.0
        self.requests.append(request)
        return FakeResponse(self.body)


def service(
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, algorithm: str
) -> tuple[CernOidcVerificationPipeline, FakeOpener]:
    content = json.dumps({"keys": [public_jwk(private, algorithm)]}).encode()
    opener = FakeOpener(content)
    fetcher = HttpsCernOidcJwksFetcher(opener=cast(OpenerDirector, opener))
    return CernOidcVerificationPipeline(fetcher=fetcher), opener


def observe(
    pipeline: CernOidcVerificationPipeline, jwt: str, **changes: object
) -> UntrustedCernRoleObservation:
    opts: dict[str, object] = {
        "expected_client_id": CLIENT,
        "expected_nonce": NONCE,
        "expected_role": ROLE,
        "now": NOW,
    }
    opts.update(changes)
    return pipeline.observe_role(tokens(jwt), metadata(), **opts)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def rsa_private() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_private() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.mark.parametrize("algorithm", ["RS256", "PS256", "ES256"])
@pytest.mark.parametrize(
    ("payload", "status"),
    [
        (claims(), "claimed"),
        (claims(resource_access={}, cern_roles=[]), "absent"),
        (claims(resource_access={}, cern_roles=[], cern_roles_missing_mfa=[ROLE]), "mfa_required"),
        (claims(resource_access={}, cern_roles=[], cern_roles_missing_loa=[ROLE]), "loa_required"),
        (
            claims(
                resource_access={},
                cern_roles=[],
                cern_roles_missing_mfa=[ROLE],
                cern_roles_missing_loa=[ROLE],
            ),
            "mfa_and_loa_required",
        ),
    ],
)
def test_verified_token_role_status_is_non_authoritative(
    rsa_private: rsa.RSAPrivateKey,
    ec_private: ec.EllipticCurvePrivateKey,
    algorithm: str,
    payload: dict[str, object],
    status: str,
) -> None:
    private = ec_private if algorithm == "ES256" else rsa_private
    pipeline, opener = service(private, algorithm)
    result = observe(pipeline, signed_token(private, algorithm, payload))
    assert type(result) is UntrustedCernRoleObservation
    assert result.status == status
    assert result.authorization == "not_implemented"
    assert result.login == "not_implemented"
    assert len(opener.requests) == 1
    assert opener.requests[0].full_url == CERN_OIDC_JWKS_URI
    assert result.status not in ("authorized", "authenticated")
    assert not hasattr(result, "subject")
    assert not hasattr(result, "session")
    assert CLIENT not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.status = "authorized"  # type: ignore[misc]


def test_existing_check_api_is_unchanged(rsa_private: rsa.RSAPrivateKey) -> None:
    pipeline, opener = service(rsa_private, "RS256")
    checked = pipeline.check(
        tokens(signed_token(rsa_private, "RS256", claims())),
        metadata(),
        expected_client_id=CLIENT,
        expected_nonce=NONCE,
        now=NOW,
    )
    assert type(checked) is CheckedUntrustedCernOidcToken
    assert checked.subject == "synthetic-user"
    assert not hasattr(checked, "role")
    assert len(opener.requests) == 1
