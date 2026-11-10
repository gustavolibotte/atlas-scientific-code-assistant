"""Deterministic native token-transport tests; no real HTTP requests."""

from dataclasses import FrozenInstanceError
from email.message import Message
from typing import cast
from urllib.parse import urlencode
from urllib.request import OpenerDirector, Request

import pytest

from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_http import OidcTokenHttpError, UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.infrastructure.oidc_token_http import (
    CERN_OIDC_TOKEN_ENDPOINT,
    HttpsOidcTokenTransport,
)

REDIRECT = "http://127.0.0.1:8765/callback"
NONCE = "N" * 43
VERIFIER = "V" * 64


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id="example-not-registered",
        redirect_uri=REDIRECT,
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )


def prepared() -> UnsentOidcTokenRequest:
    body = urlencode(
        {
            "grant_type": "authorization_code",
            "code": "synthetic-private-code",
            "redirect_uri": REDIRECT,
            "client_id": "example-not-registered",
            "code_verifier": VERIFIER,
        }
    ).encode("ascii")
    return UnsentOidcTokenRequest(
        token_endpoint=CERN_OIDC_TOKEN_ENDPOINT, form_body=body, expected_nonce=NONCE
    )


class FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        body: bytes = b'{"access_token":"synthetic-test-only"}',
        headers: Message | None = None,
    ) -> None:
        self.status = status
        self.body = body
        self.headers = headers if headers is not None else json_headers()
        self.closed = False
        self.read_limit: int | None = None

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True

    def read(self, amount: int) -> bytes:
        self.read_limit = amount
        return self.body[:amount]


def json_headers() -> Message:
    headers = Message()
    headers.add_header("Content-Type", "application/json")
    return headers


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


def transport(opener: FakeOpener, *, timeout: float = 5.0) -> HttpsOidcTokenTransport:
    return HttpsOidcTokenTransport(
        timeout_seconds=timeout,
        opener=cast(OpenerDirector, opener),
    )


def test_valid_response_remains_opaque_and_unverified() -> None:
    response = FakeResponse()
    opener = FakeOpener(response)
    result = transport(opener).exchange(prepared(), registration())
    assert isinstance(result, UnverifiedOidcTokenHttpResponse)
    assert result.status_code == 200
    assert result.body == response.body
    assert response.closed
    assert response.read_limit == 65_537
    assert not hasattr(result, "verified_identity")
    assert not hasattr(result, "id_token_validated")
    assert "access_token" not in repr(result)
    assert "synthetic-test-only" not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.body = b"changed"  # type: ignore[misc]


def test_transport_sends_post_only_to_pinned_endpoint() -> None:
    opener = FakeOpener(FakeResponse())
    transport(opener, timeout=2.0).exchange(prepared(), registration())
    sent = opener.requests[0]
    assert sent.full_url == CERN_OIDC_TOKEN_ENDPOINT
    assert sent.get_method() == "POST"
    assert sent.data == prepared().form_body
    headers = {name.lower(): value for name, value in sent.header_items()}
    assert headers["content-type"] == "application/x-www-form-urlencoded"
    assert headers["accept"] == "application/json"
    assert headers["cache-control"] == "no-store"
    assert "authorization" not in headers
    assert "cookie" not in headers
    assert "client_secret" not in sent.data.decode("ascii")
    assert opener.timeouts == [2.0]


@pytest.mark.parametrize("timeout", [0, 0.09, 15.01, -1, float("nan"), float("inf"), True, "5"])
def test_invalid_timeout_rejected(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout"):
        HttpsOidcTokenTransport(timeout_seconds=timeout)  # type: ignore[arg-type]


@pytest.mark.parametrize("body", [b"", b"x" * 65537])
def test_unverified_response_rejects_bad_body(body: bytes) -> None:
    with pytest.raises(OidcTokenHttpError):
        UnverifiedOidcTokenHttpResponse(body=body)


def test_failed_transport_does_not_return_a_session() -> None:
    result = transport(FakeOpener(FakeResponse())).exchange(prepared(), registration())
    assert not hasattr(result, "session_id")
    assert not hasattr(result, "authenticated_identity")
