"""Offline unit tests for pinned public CERN JWKS HTTPS retrieval."""

import base64
import json
import ssl
from dataclasses import FrozenInstanceError
from email.message import Message
from typing import cast
from urllib.request import HTTPSHandler, OpenerDirector, ProxyHandler, Request

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI, parse_cern_public_jwks
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks_http import FetchedUnverifiedOidcJwks, OidcJwksHttpError
from asca.infrastructure.oidc_jwks_http import (
    HttpsCernOidcJwksFetcher,
    _RejectJwksRedirects,
)


def metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_JWKS_URI,
        approved_id_token_algorithms=("RS256", "ES256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def headers(*entries: tuple[str, str]) -> Message:
    result = Message()
    for name, value in entries:
        result.add_header(name, value)
    return result


class FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        body: bytes = b'{"keys":[{"kid":"synthetic"}]}',
        response_headers: object | None = None,
    ) -> None:
        self.status = status
        self.body = body
        self.headers = (
            response_headers
            if response_headers is not None
            else headers(("Content-Type", "application/json"))
        )
        self.closed = False
        self.read_limit: int | None = None

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True

    def read(self, amount: int) -> bytes:
        self.read_limit = amount
        return self.body[:amount]


class FakeOpener:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.requests: list[Request] = []
        self.timeouts: list[float] = []

    def open(self, request: Request, *, timeout: float) -> FakeResponse:
        self.requests.append(request)
        self.timeouts.append(timeout)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def fetcher(opener: FakeOpener, *, timeout: float = 5.0) -> HttpsCernOidcJwksFetcher:
    return HttpsCernOidcJwksFetcher(opener=cast(OpenerDirector, opener), timeout_seconds=timeout)


def test_fetched_data_is_bounded_and_explicitly_unverified() -> None:
    response = FakeResponse()
    fake = FakeOpener(response)
    retrieved = fetcher(fake).fetch(metadata())
    assert isinstance(retrieved, FetchedUnverifiedOidcJwks)
    assert retrieved.source_url == CERN_OIDC_JWKS_URI
    assert retrieved.status_code == 200
    assert retrieved.body == response.body
    assert response.closed
    assert response.read_limit == 262_145
    assert not hasattr(retrieved, "verified_signature")
    assert not hasattr(retrieved, "identity")
    assert "synthetic" not in repr(retrieved)
    with pytest.raises(FrozenInstanceError):
        retrieved.body = b"replaced"  # type: ignore[misc]


def test_get_request_has_no_credentials_and_exact_pinned_url() -> None:
    fake = FakeOpener(FakeResponse())
    fetcher(fake, timeout=2.5).fetch(metadata())
    request = fake.requests[0]
    assert request.get_method() == "GET"
    assert request.full_url == CERN_OIDC_JWKS_URI
    assert request.data is None
    request_headers = {name.lower(): value for name, value in request.header_items()}
    assert "jwk-set+json" in request_headers["accept"]
    assert request_headers["cache-control"] == "no-store"
    assert not {"cookie", "authorization", "proxy-authorization"}.intersection(request_headers)
    assert fake.timeouts == [2.5]


@pytest.mark.parametrize("timeout", [0.1, 1, 5.0, 15])
def test_timeout_boundaries_allowed(timeout: float) -> None:
    fake = FakeOpener(FakeResponse())
    fetcher(fake, timeout=timeout).fetch(metadata())
    assert fake.timeouts == [float(timeout)]


@pytest.mark.parametrize(
    "timeout",
    [0, 0.09, 15.01, -1, float("inf"), float("-inf"), float("nan"), True, "5", None],
)
def test_invalid_timeout_rejected(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout"):
        HttpsCernOidcJwksFetcher(timeout_seconds=timeout)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
        "application/json ; CHARSET=UTF-8",
        "application/jwk-set+json",
        "Application/JWK-Set+JSON; charset=UTF-8",
    ],
)
def test_approved_media_types_are_accepted(content_type: str) -> None:
    response = FakeResponse(response_headers=headers(("Content-Type", content_type)))
    assert fetcher(FakeOpener(response)).fetch(metadata()).body == response.body


def test_implicit_transfer_length_is_valid() -> None:
    response = FakeResponse(response_headers=headers(("Content-Type", "application/json")))
    assert fetcher(FakeOpener(response)).fetch(metadata()).body == response.body


def test_matching_content_length_is_valid() -> None:
    response = FakeResponse()
    response.headers = headers(
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(response.body))),
    )
    assert fetcher(FakeOpener(response)).fetch(metadata()).body == response.body


def test_exact_chunked_framing_can_be_accepted_when_content_length_absent() -> None:
    response = FakeResponse(
        response_headers=headers(
            ("Content-Type", "application/jwk-set+json"),
            ("Transfer-Encoding", "chunked"),
        )
    )
    assert fetcher(FakeOpener(response)).fetch(metadata()).body == response.body


def test_identity_content_encoding_is_accepted() -> None:
    response = FakeResponse(
        response_headers=headers(
            ("Content-Type", "application/json"),
            ("Content-Encoding", "identity"),
        )
    )
    assert fetcher(FakeOpener(response)).fetch(metadata()).body == response.body


def test_default_opener_disables_proxies_and_redirects() -> None:
    client = HttpsCernOidcJwksFetcher()
    assert not any(isinstance(handler, ProxyHandler) for handler in client._opener.handlers)
    assert any(isinstance(handler, _RejectJwksRedirects) for handler in client._opener.handlers)
    handlers = [handler for handler in client._opener.handlers if isinstance(handler, HTTPSHandler)]
    assert len(handlers) == 1
    assert handlers[0]._context.verify_mode is ssl.CERT_REQUIRED
    assert handlers[0]._context.check_hostname is True


def test_redirect_policy_does_not_follow_user_supplied_location() -> None:
    policy = _RejectJwksRedirects()
    assert (
        policy.redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://evil.invalid/",  # type: ignore[arg-type]
        )
        is None
    )


def test_maximum_size_body_is_bounded_without_http_length() -> None:
    body = b"x" * 262_144
    response = FakeResponse(body=body)
    assert fetcher(FakeOpener(response)).fetch(metadata()).body == body
    assert response.read_limit == 262_145


@pytest.mark.parametrize("body", [b"", b"x" * 262_145])
def test_fetched_data_contract_rejects_bad_body(body: bytes) -> None:
    with pytest.raises(OidcJwksHttpError):
        FetchedUnverifiedOidcJwks(body=body, source_url=CERN_OIDC_JWKS_URI)


@pytest.mark.parametrize("url", ["http://cern.example/certs", "", 23])
def test_fetched_data_contract_rejects_bad_source(url: object) -> None:
    with pytest.raises(OidcJwksHttpError):
        FetchedUnverifiedOidcJwks(body=b"{}", source_url=url)  # type: ignore[arg-type]


@pytest.mark.parametrize("code", [301, 400, 500, True])
def test_fetched_data_contract_rejects_non_200_code(code: object) -> None:
    with pytest.raises(OidcJwksHttpError):
        FetchedUnverifiedOidcJwks(
            body=b"{}",
            source_url=CERN_OIDC_JWKS_URI,
            status_code=code,  # type: ignore[arg-type]
        )


def test_fetch_then_parse_with_synthetic_rsa_declaration_offline() -> None:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    raw = json.dumps(
        {
            "keys": [
                {
                    "kid": "synthetic-rsa",
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "n": b64(b"\x80" + b"\x01" * 255),
                    "e": b64(b"\x01\x00\x01"),
                }
            ]
        }
    ).encode("ascii")
    fetched = fetcher(FakeOpener(FakeResponse(body=raw))).fetch(metadata())
    parsed = parse_cern_public_jwks(fetched.body, metadata())
    assert parsed.keys[0].kid == "synthetic-rsa"
    assert not hasattr(parsed, "verified_signature")
