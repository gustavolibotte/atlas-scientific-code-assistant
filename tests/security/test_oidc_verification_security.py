"""Adversarial pipeline tests with independent synthetic TLS response fixtures."""

from __future__ import annotations

import base64
import json
import socket
from dataclasses import replace
from email.message import Message
from typing import cast
from urllib.request import OpenerDirector, Request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks_http import FetchedUnverifiedOidcJwks, OidcJwksHttpError
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
def private() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def signed(private: rsa.RSAPrivateKey) -> str:
    return sign(private, "RS256")


def reject(
    service: CernOidcVerificationPipeline,
    signed: str,
    *,
    detail: str = "rejected",
    **changes: object,
) -> None:
    with pytest.raises(OidcVerificationError, match=detail) as raised:
        check(service, signed, **changes)
    assert signed not in str(raised.value)
    assert "synthetic-access-token" not in str(raised.value)
    assert NONCE not in str(raised.value)


@pytest.mark.parametrize(
    "altered",
    [
        {"nonce": "wrongNonce_0123456789012345678901"},
        {"iss": "https://other.example.invalid"},
        {"aud": "other-client"},
        {"sub": ""},
        {"iat": NOW + 500},
        {"exp": NOW - 500},
        {"exp": "wrong"},
        {"nbf": NOW + 500},
        {"azp": "other"},
        {"at_hash": "unvalidated"},
        {"c_hash": "unvalidated"},
        {"s_hash": "unvalidated"},
        {"roles": ["superuser"], "nonce": "invalid_nonce_here"},
    ],
)
def test_signed_but_invalid_claims_never_pass(
    private: rsa.RSAPrivateKey, altered: dict[str, object]
) -> None:
    service, _ = pipeline(jwks(private, "RS256"))
    reject(service, sign(private, "RS256", payload=json.dumps(claims(**altered)).encode()))


@pytest.mark.parametrize(
    "bad_body",
    [
        b"not-json",
        b"{}",
        b'{"keys": []}',
        b'{"keys": [{"kid":"wrong","kty":"oct","use":"sig","alg":"HS256"}]}',
        b'{"keys": [null]}',
        b'{"keys": [], "keys": []}',
        b'{"keys": [1]}',
        b"{}" * 131073,
    ],
)
def test_malformed_or_untrusted_jwks_fail_closed(
    private: rsa.RSAPrivateKey, signed: str, bad_body: bytes
) -> None:
    service, _ = pipeline(bad_body)
    reject(service, signed)


def test_unrelated_public_key_cannot_verify_signature(
    private: rsa.RSAPrivateKey, signed: str
) -> None:
    unrelated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service, _ = pipeline(jwks(unrelated, "RS256"))
    reject(service, signed)


def test_modified_payload_rejected(private: rsa.RSAPrivateKey, signed: str) -> None:
    service, _ = pipeline(jwks(private, "RS256"))
    h, _, signature = signed.split(".")
    reject(service, h + "." + b64(b'{"sub":"attacker"}') + "." + signature)


def test_modified_protected_header_rejected(private: rsa.RSAPrivateKey, signed: str) -> None:
    service, _ = pipeline(jwks(private, "RS256"))
    _, p, s = signed.split(".")
    reject(service, b64(b'{"alg":"RS256","kid":"test-key"}') + "." + p + "." + s)


def test_wrong_algorithm_jwk_declaration_rejected(private: rsa.RSAPrivateKey, signed: str) -> None:
    mismatched_key = key_record(private, "PS256")
    service, _ = pipeline(json.dumps({"keys": [mismatched_key]}).encode())
    reject(service, signed)


def test_header_supplied_jku_is_not_consulted(private: rsa.RSAPrivateKey) -> None:
    service, opener = pipeline(jwks(private, "RS256"))
    hostile = sign(
        private,
        "RS256",
        header={"kid": "test-key", "alg": "RS256", "jku": "https://attacker.invalid/jwks"},
    )
    reject(service, hostile)
    assert len(opener.requests) == 1
    assert opener.requests[0].full_url == CERN_OIDC_JWKS_URI


@pytest.mark.parametrize(
    "changes",
    [
        {"issuer": "https://evil.invalid"},
        {"authorization_endpoint": "https://evil.invalid/auth"},
        {"token_endpoint": "https://evil.invalid/token"},
        {"jwks_uri": "https://evil.invalid/jwks"},
        {"jwks_uri": CERN_OIDC_JWKS_URI + "?param=1"},
        {"supports_authorization_code": False},
        {"supports_pkce_s256": False},
        {"approved_id_token_algorithms": ("HS256",)},
        {"approved_id_token_algorithms": ("RS256", "RS256")},
        {"approved_id_token_algorithms": []},
        {"approved_id_token_algorithms": ()},
        {"approved_id_token_algorithms": (None,)},
    ],
)
def test_invalid_metadata_rejected_before_request(
    private: rsa.RSAPrivateKey, signed: str, changes: dict[str, object]
) -> None:
    service, opener = pipeline(jwks(private, "RS256"))
    with pytest.raises(OidcVerificationError, match="input"):
        service.check(
            tokens(signed),
            replace(metadata(), **changes),
            expected_client_id=CLIENT,
            expected_nonce=NONCE,
            now=NOW,
        )
    assert not opener.requests


@pytest.mark.parametrize(
    "changes",
    [
        {"expected_client_id": "bad client"},
        {"expected_client_id": ""},
        {"expected_client_id": 123},
        {"expected_nonce": "bad"},
        {"expected_nonce": "short"},
        {"expected_nonce": None},
        {"now": None},
        {"now": True},
        {"now": 0},
        {"now": 2**53},
        {"clock_skew_seconds": 121},
        {"clock_skew_seconds": -1},
        {"clock_skew_seconds": True},
        {"max_token_lifetime_seconds": 0},
        {"max_token_lifetime_seconds": 86401},
        {"trusted_additional_audiences": (CLIENT,)},
        {"trusted_additional_audiences": ("other", "other")},
        {"trusted_additional_audiences": ["other"]},
    ],
)
def test_bad_context_rejected_before_request(
    private: rsa.RSAPrivateKey, signed: str, changes: dict[str, object]
) -> None:
    service, opener = pipeline(jwks(private, "RS256"))
    defaults: dict[str, object] = {
        "expected_client_id": CLIENT,
        "expected_nonce": NONCE,
        "now": NOW,
    }
    defaults.update(changes)
    with pytest.raises(OidcVerificationError):
        service.check(tokens(signed), metadata(), **defaults)  # type: ignore[arg-type]
    assert not opener.requests


@pytest.mark.parametrize("invalid", [None, 1, {}, object(), "jwt"])
def test_wrong_token_type_rejected_before_request(
    invalid: object, private: rsa.RSAPrivateKey
) -> None:
    service, opener = pipeline(jwks(private, "RS256"))
    with pytest.raises(OidcVerificationError):
        service.check(  # type: ignore[arg-type]
            invalid, metadata(), expected_client_id=CLIENT, expected_nonce=NONCE, now=NOW
        )
    assert not opener.requests


def test_bad_jws_fails_and_does_not_produce_result(private: rsa.RSAPrivateKey) -> None:
    service, _ = pipeline(jwks(private, "RS256"))
    reject(service, "a.b.c")


def test_trusted_transport_errors_are_sanitized(private: rsa.RSAPrivateKey, signed: str) -> None:
    class BrokenFetcher(HttpsCernOidcJwksFetcher):
        def fetch(self, metadata: object) -> FetchedUnverifiedOidcJwks:
            del metadata
            raise OidcJwksHttpError("synthetic-secret-connection-detail")

    service = CernOidcVerificationPipeline(fetcher=BrokenFetcher())
    with pytest.raises(OidcVerificationError) as exc:
        check(service, signed)
    assert "synthetic-secret" not in str(exc.value)


@pytest.mark.parametrize(
    "source", ["https://evil.invalid/jwks", CERN_OIDC_ISSUER, "http://auth.cern.ch/jwks"]
)
def test_wrong_fetched_origin_fails(private: rsa.RSAPrivateKey, signed: str, source: str) -> None:
    class ForgedFetcher(HttpsCernOidcJwksFetcher):
        def fetch(self, metadata: object) -> FetchedUnverifiedOidcJwks:
            del metadata
            return FetchedUnverifiedOidcJwks(body=jwks(private, "RS256"), source_url=source)

    service = CernOidcVerificationPipeline(fetcher=ForgedFetcher())
    reject(service, signed, detail="source" if source.startswith("https://") else "rejected")


@pytest.mark.parametrize("value", [None, "junk", b"junk", object(), 1])
def test_nonresponse_from_fake_fetcher_fails(
    private: rsa.RSAPrivateKey, signed: str, value: object
) -> None:
    class ForgedFetcher(HttpsCernOidcJwksFetcher):
        def fetch(self, metadata: object) -> object:
            del metadata
            return value

    service = CernOidcVerificationPipeline(fetcher=ForgedFetcher())
    reject(service, signed, detail="source")


def test_explicit_input_not_derived_from_untrusted_claims(private: rsa.RSAPrivateKey) -> None:
    service, _ = pipeline(jwks(private, "RS256"))
    signed = sign(private, "RS256", payload=json.dumps(claims(aud="evil-client")).encode())
    reject(service, signed)


def test_never_performs_additional_network_requests(
    private: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, opener = pipeline(jwks(private, "RS256"))

    def blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected network access")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    result = check(service, sign(private, "RS256"))
    assert result.subject == "synthetic-cern-subject"
    assert len(opener.requests) == 1


def test_forged_source_label_is_not_provenance(private: rsa.RSAPrivateKey) -> None:
    forged = FetchedUnverifiedOidcJwks(body=jwks(private, "RS256"), source_url=CERN_OIDC_JWKS_URI)
    assert forged.source_url == CERN_OIDC_JWKS_URI
    assert not hasattr(forged, "tls_authenticated")


def test_even_signature_and_claims_validity_is_not_a_session(private: rsa.RSAPrivateKey) -> None:
    service, _ = pipeline(jwks(private, "RS256"))
    result = check(service, sign(private, "RS256"))
    for name in ("verified_identity", "session", "access_token", "permissions", "logged_in"):
        assert not hasattr(result, name)


@pytest.mark.parametrize(
    "change",
    [
        {"token_type": "Basic"},
        {"token_type": None},
        {"access_token": ""},
        {"access_token": None},
        {"access_token": "x" * 16385},
        {"id_token": "x" * 32769},
        {"id_token": None},
    ],
)
def test_manually_forged_token_response_rejected_without_network(
    private: rsa.RSAPrivateKey, signed: str, change: dict[str, object]
) -> None:
    service, opener = pipeline(jwks(private, "RS256"))
    with pytest.raises(OidcVerificationError):
        service.check(
            replace(tokens(signed), **change),
            metadata(),
            expected_client_id=CLIENT,
            expected_nonce=NONCE,
            now=NOW,
        )
    assert not opener.requests


def test_valid_but_wrong_nonce_is_rejected_after_signature_check(
    private: rsa.RSAPrivateKey, signed: str
) -> None:
    service, opener = pipeline(jwks(private, "RS256"))
    reject(service, signed, expected_nonce="wrong_nonce_012345678901234567890")
    assert len(opener.requests) == 1


def test_valid_but_wrong_expected_client_is_rejected_after_signature_check(
    private: rsa.RSAPrivateKey, signed: str
) -> None:
    service, opener = pipeline(jwks(private, "RS256"))
    reject(service, signed, expected_client_id="other-client")
    assert len(opener.requests) == 1


@pytest.mark.parametrize("status", [201, 301, 302, 404, 429, 500])
def test_non_200_fetcher_response_fails_closed(
    private: rsa.RSAPrivateKey, signed: str, status: int
) -> None:
    fake = FakeOpener(FakeResponse(jwks(private, "RS256"), status=status))
    service = CernOidcVerificationPipeline(
        fetcher=HttpsCernOidcJwksFetcher(opener=cast(OpenerDirector, fake))
    )
    reject(service, signed)
    assert fake.response.closed


@pytest.mark.parametrize(
    "content_type", ["text/html", "application/octet-stream", "application/json; charset=latin1"]
)
def test_unapproved_http_content_types_fail(
    private: rsa.RSAPrivateKey, signed: str, content_type: str
) -> None:
    fake = FakeOpener(FakeResponse(jwks(private, "RS256"), content_type=content_type))
    service = CernOidcVerificationPipeline(
        fetcher=HttpsCernOidcJwksFetcher(opener=cast(OpenerDirector, fake))
    )
    reject(service, signed)
    assert fake.response.closed
