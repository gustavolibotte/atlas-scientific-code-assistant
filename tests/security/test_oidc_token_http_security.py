"""Adversarial no-network tests for native CERN token endpoint transport."""

from dataclasses import replace
from email.message import Message
from http.client import HTTPException
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import OpenerDirector, ProxyHandler, Request

import pytest

from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_http import OidcTokenHttpError
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.infrastructure.oidc_token_http import (
    CERN_OIDC_TOKEN_ENDPOINT,
    HttpsOidcTokenTransport,
    _RejectRedirects,
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
        self.headers = headers if headers is not None else headers_for_json()
        self.closed = False
        self.read_limit: int | None = None

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True

    def read(self, amount: int) -> bytes:
        self.read_limit = amount
        return self.body[:amount]


def headers_for_json() -> Message:
    result = Message()
    result.add_header("Content-Type", "application/json")
    return result


class FakeOpener:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.requests: list[Request] = []

    def open(self, request: Request, *, timeout: float) -> FakeResponse:
        self.requests.append(request)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def transport(opener: FakeOpener) -> HttpsOidcTokenTransport:
    return HttpsOidcTokenTransport(opener=cast(OpenerDirector, opener))


def headers(*items: tuple[str, str]) -> Message:
    result = Message()
    for name, value in items:
        result.add_header(name, value)
    return result


def forged_request(**changes: str) -> object:
    fields = {
        "grant_type": "authorization_code",
        "code": "private-test-code",
        "redirect_uri": REDIRECT,
        "client_id": "example-not-registered",
        "code_verifier": VERIFIER,
    }
    fields.update(changes)
    return replace(prepared(), form_body=urlencode(fields).encode("ascii"))


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://auth.cern.ch/auth/realms/cern/protocol/openid-connect/token",
        "https://evil.example.invalid/token",
        CERN_OIDC_TOKEN_ENDPOINT + "?",
        CERN_OIDC_TOKEN_ENDPOINT + "#",
        "https://auth.cern.ch/auth/realms/cern/other",
        "https://user:pass@auth.cern.ch/auth/realms/cern/protocol/openid-connect/token",
    ],
)
def test_endpoint_substitution_blocked_before_any_request(endpoint: str) -> None:
    opener = FakeOpener(FakeResponse())
    with pytest.raises(OidcTokenHttpError, match="not approved"):
        transport(opener).exchange(replace(prepared(), token_endpoint=endpoint), registration())
    assert not opener.requests


def test_web_bff_registration_cannot_use_native_transport() -> None:
    web = OidcClientRegistration(
        client_id="example-not-registered",
        redirect_uri="https://asca.example.org/callback",
        mode=OidcClientMode.WEB_BFF,
    )
    opener = FakeOpener(FakeResponse())
    with pytest.raises(OidcTokenHttpError):
        transport(opener).exchange(prepared(), web)
    assert not opener.requests


@pytest.mark.parametrize(
    "changes",
    [
        {"grant_type": "client_credentials"},
        {"code": ""},
        {"code": "abc\nsecret"},
        {"code": "a" * 2049},
        {"code_verifier": "short"},
        {"redirect_uri": "http://127.0.0.1:8765/other"},
        {"client_id": "different-client"},
    ],
)
def test_forged_form_rejected_before_network(changes: dict[str, str]) -> None:
    opener = FakeOpener(FakeResponse())
    with pytest.raises(OidcTokenHttpError):
        transport(opener).exchange(forged_request(**changes), registration())
    assert not opener.requests


@pytest.mark.parametrize(
    "body",
    [
        b"grant_type=authorization_code&code=only",
        b"grant_type=authorization_code&code=abc&client_secret=leak",
        b"grant_type=authorization_code&code=%GG",
        b"not=valid&" * 1500,
        b"",
    ],
)
def test_bad_form_rejected_without_echo(body: bytes) -> None:
    opener = FakeOpener(FakeResponse())
    with pytest.raises(OidcTokenHttpError) as error:
        transport(opener).exchange(replace(prepared(), form_body=body), registration())
    assert "client_secret" not in str(error.value)
    assert not opener.requests


def test_duplicate_form_parameter_rejected() -> None:
    opener = FakeOpener(FakeResponse())
    extra = prepared().form_body + b"&code=other"
    with pytest.raises(OidcTokenHttpError):
        transport(opener).exchange(replace(prepared(), form_body=extra), registration())
    assert not opener.requests


@pytest.mark.parametrize(
    "response_headers",
    [
        headers(),
        headers(("Content-Type", "text/html")),
        headers(("Content-Type", "application/json"), ("Content-Type", "application/json")),
        headers(("Content-Type", "application/json"), ("Content-Encoding", "gzip")),
        headers(("Content-Type", "application/json"), ("Content-Length", "65537")),
        headers(("Content-Type", "application/json"), ("Content-Length", "-1")),
        headers(("Content-Type", "application/json"), ("Content-Length", "foo")),
        headers(("Content-Type", "application/json"), ("Content-Length", "0")),
        headers(
            ("Content-Type", "application/json"), ("Content-Length", "2"), ("Content-Length", "2")
        ),
    ],
)
def test_rejects_malformed_response_headers(response_headers: Message) -> None:
    opener = FakeOpener(FakeResponse(headers=response_headers))
    with pytest.raises(OidcTokenHttpError):
        transport(opener).exchange(prepared(), registration())


@pytest.mark.parametrize("status", [201, 204, 301, 302, 303, 307, 308, 400, 500])
def test_non_200_rejected_without_exposing_server_details(status: int) -> None:
    with pytest.raises(OidcTokenHttpError):
        transport(FakeOpener(FakeResponse(status=status))).exchange(prepared(), registration())


def test_oversized_body_rejected_even_without_content_length() -> None:
    response = FakeResponse(body=b"A" * 65537)
    with pytest.raises(OidcTokenHttpError):
        transport(FakeOpener(response)).exchange(prepared(), registration())
    assert response.read_limit == 65537
    assert response.closed


@pytest.mark.parametrize("body", [b"", b"not-json-but-opaque"])
def test_empty_body_rejected_but_opaque_nonempty_bytes_not_trusted(body: bytes) -> None:
    opener = FakeOpener(FakeResponse(body=body))
    if not body:
        with pytest.raises(OidcTokenHttpError):
            transport(opener).exchange(prepared(), registration())
    else:
        result = transport(opener).exchange(prepared(), registration())
        assert result.body == body
        assert not hasattr(result, "verified_identity")


@pytest.mark.parametrize(
    "failure",
    [TimeoutError("secret"), URLError("private data"), OSError("secret"), HTTPException("secret")],
)
def test_transport_errors_sanitized(failure: Exception) -> None:
    opener = FakeOpener(failure)
    with pytest.raises(OidcTokenHttpError) as caught:
        transport(opener).exchange(prepared(), registration())
    assert "secret" not in str(caught.value)
    assert "private data" not in str(caught.value)
    assert "private-test-code" not in str(caught.value)


def test_error_response_is_not_passed_to_user() -> None:
    opener = FakeOpener(HTTPError(CERN_OIDC_TOKEN_ENDPOINT, 400, "private-code", {}, None))
    with pytest.raises(OidcTokenHttpError) as caught:
        transport(opener).exchange(prepared(), registration())
    assert "private-code" not in str(caught.value)


def test_redirect_policy_never_follows() -> None:
    handler = _RejectRedirects()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/") is None  # type: ignore[arg-type]


def test_default_opener_has_no_proxy_and_has_redirect_blocker() -> None:
    client = HttpsOidcTokenTransport()
    opener = client._opener
    assert not any(isinstance(handler, ProxyHandler) for handler in opener.handlers)
    assert any(isinstance(handler, _RejectRedirects) for handler in opener.handlers)


def test_invalid_types_are_blocked_before_network() -> None:
    opener = FakeOpener(FakeResponse())
    client = transport(opener)
    for value in (None, "abc", object()):
        with pytest.raises(OidcTokenHttpError):
            client.exchange(value, registration())  # type: ignore[arg-type]
    assert not opener.requests


def test_nonce_validation_blocks_forged_object() -> None:
    opener = FakeOpener(FakeResponse())
    with pytest.raises(OidcTokenHttpError):
        transport(opener).exchange(replace(prepared(), expected_nonce="bad"), registration())
    assert not opener.requests


@pytest.mark.parametrize("declared_length", ["1", "2", "65536"])
def test_rejects_content_length_mismatch(declared_length: str) -> None:
    body = b'{"access_token":"synthetic-test-only"}'
    response = FakeResponse(
        body=body,
        headers=headers(
            ("Content-Type", "application/json"),
            ("Content-Length", declared_length),
        ),
    )
    with pytest.raises(OidcTokenHttpError, match="response was rejected"):
        transport(FakeOpener(response)).exchange(prepared(), registration())
    assert response.closed


def test_matching_content_length_is_accepted() -> None:
    body = b'{"access_token":"synthetic-test-only"}'
    response = FakeResponse(
        body=body,
        headers=headers(
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ),
    )
    result = transport(FakeOpener(response)).exchange(prepared(), registration())
    assert result.body == body
    assert response.closed
