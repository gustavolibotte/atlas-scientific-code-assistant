"""Cryptographic JWKS/JWS/claims at_hash integration with ephemeral offline keys."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks_http import FetchedUnverifiedOidcJwks
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken, OidcVerificationError
from asca.infrastructure.oidc_jwks_http import HttpsCernOidcJwksFetcher
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000
CLIENT = "synthetic-at-hash-pipeline"
NONCE = "syntheticNonce_01234567890123456789012345"
TOKEN = "synthetic-access-token"
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


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


def public_jwks(private: PrivateKey, algorithm: str) -> bytes:
    numbers = private.public_key().public_numbers()
    record: dict[str, object] = {"kid": "at-hash-key", "alg": algorithm, "use": "sig"}
    if isinstance(private, rsa.RSAPrivateKey):
        record.update(
            {
                "kty": "RSA",
                "n": b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                "e": b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
            }
        )
    else:
        record.update(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": b64(numbers.x.to_bytes(32, "big")),
                "y": b64(numbers.y.to_bytes(32, "big")),
            }
        )
    return json.dumps({"keys": [record]}).encode("ascii")


def signed(private: PrivateKey, algorithm: str, *, at_hash: str) -> str:
    claims = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "synthetic-subject",
        "aud": CLIENT,
        "nonce": NONCE,
        "iat": NOW - 30,
        "exp": NOW + 240,
        "at_hash": at_hash,
    }
    header = {"alg": algorithm, "kid": "at-hash-key", "typ": "JWT"}
    signing_input = (
        b64(json.dumps(header, separators=(",", ":")).encode("ascii"))
        + "."
        + b64(json.dumps(claims, separators=(",", ":")).encode("ascii"))
    ).encode("ascii")
    if isinstance(private, rsa.RSAPrivateKey):
        rsa_padding = (
            padding.PKCS1v15()
            if algorithm == "RS256"
            else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        )
        signature = private.sign(signing_input, rsa_padding, hashes.SHA256())
    else:
        der = private.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input.decode("ascii") + "." + b64(signature)


class SyntheticFetcher(HttpsCernOidcJwksFetcher):
    """In-memory JWKS: no network or CERN-provenance attestation."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.calls = 0

    def fetch(self, _metadata: OidcProviderMetadata) -> FetchedUnverifiedOidcJwks:
        self.calls += 1
        return FetchedUnverifiedOidcJwks(body=self.body, source_url=CERN_OIDC_JWKS_URI)


def token_response(id_token: str, access_token: str) -> ParsedUnverifiedOidcTokenResponse:
    return ParsedUnverifiedOidcTokenResponse(
        access_token=access_token,
        id_token=id_token,
        token_type="Bearer",
        expires_in=300,
        refresh_token=None,
        scope=None,
    )


@pytest.mark.parametrize("algorithm", ["RS256", "PS256", "ES256"])
def test_full_cryptographic_pipeline_binds_signed_at_hash_to_response_token(
    algorithm: str,
) -> None:
    private: PrivateKey = (
        ec.generate_private_key(ec.SECP256R1())
        if algorithm == "ES256"
        else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    digest = hashlib.sha256(TOKEN.encode("ascii")).digest()
    actual_hash = b64(digest[:16])
    id_token = signed(private, algorithm, at_hash=actual_hash)
    fetcher = SyntheticFetcher(public_jwks(private, algorithm))
    checker = CernOidcVerificationPipeline(fetcher=fetcher)
    result = checker.check(
        token_response(id_token, TOKEN),
        metadata(),
        expected_client_id=CLIENT,
        expected_nonce=NONCE,
        now=NOW,
    )
    assert isinstance(result, CheckedUntrustedCernOidcToken)
    assert result.subject == "synthetic-subject"
    assert result.algorithm == algorithm
    assert fetcher.calls == 1
    assert TOKEN not in repr(result)
    assert not hasattr(result, "session")
    assert not hasattr(result, "roles")
    with pytest.raises(OidcVerificationError, match="rejected"):
        checker.check(
            token_response(id_token, "substituted-access-token"),
            metadata(),
            expected_client_id=CLIENT,
            expected_nonce=NONCE,
            now=NOW,
        )
    assert fetcher.calls == 2
