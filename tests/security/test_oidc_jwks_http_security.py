"""Adversarial no-network tests for bounded CERN JWKS retrieval."""

from dataclasses import replace
from email.message import Message
from http.client import HTTPException
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.request import OpenerDirector, Request

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks_http import OidcJwksHttpError
from asca.infrastructure.oidc_jwks_http import HttpsCernOidcJwksFetcher


class FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        body: object = b'{"keys":[{"kid":"example"}]}',
        header_values: object | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.status = status
        self.body = body
        self.headers = (
            header_values
            if header_values is not None
            else headers(("Content-Type", "application/json"))
        )
        self.failure = failure
        self.closed = False
        self.read_limit: int | None = None

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True

    def read(self, amount: int) -> object:
        self.read_limit = amount
        if self.failure is not None:
            raise self.failure
        return self.body[:amount] if isinstance(self.body, bytes) else self.body


class FakeOpener:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.requests: list[Request] = []

    def open(self, request: Request, *, timeout: float) -> FakeResponse:
        self.requests.append(request)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def headers(*items: tuple[str, str]) -> Message:
    result = Message()
    for name, value in items:
        result.add_header(name, value)
    return result


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


def fetcher(opener: FakeOpener) -> HttpsCernOidcJwksFetcher:
    return HttpsCernOidcJwksFetcher(opener=cast(OpenerDirector, opener))


@pytest.mark.parametrize(
    "changes",
    [
        {"issuer": "https://evil.example.org"},
        {"issuer": "http://auth.cern.ch/auth/realms/cern"},
        {"jwks_uri": "https://evil.example.org/certs"},
        {"jwks_uri": "http://auth.cern.ch/auth/realms/cern/protocol/openid-connect/certs"},
        {"jwks_uri": CERN_OIDC_JWKS_URI + "?redirect=evil"},
        {"jwks_uri": CERN_OIDC_JWKS_URI + "#fragment"},
        {"jwks_uri": CERN_OIDC_ISSUER + "/other"},
        {"approved_id_token_algorithms": ()},
        {"approved_id_token_algorithms": ("HS256",)},
        {"approved_id_token_algorithms": ("RS256", "none")},
        {"approved_id_token_algorithms": ("RS256", "RS256")},
        {"approved_id_token_algorithms": ["RS256"]},
        {"approved_id_token_algorithms": ("RS256", None)},
        {"supports_authorization_code": False},
        {"supports_pkce_s256": False},
        {"supports_pkce_s256": 1},
        {"supports_authorization_code": 1},
    ],
)
def test_bad_metadata_rejected_before_network(changes: dict[str, object]) -> None:
    opener = FakeOpener(FakeResponse())
    with pytest.raises(OidcJwksHttpError, match="metadata policy"):
        fetcher(opener).fetch(replace(metadata(), **changes))
    assert not opener.requests


def test_untrusted_non_metadata_inputs_never_start_network() -> None:
    opener = FakeOpener(FakeResponse())
    for value in (None, {}, object(), "https://example.invalid"):
        with pytest.raises(OidcJwksHttpError):
            fetcher(opener).fetch(value)  # type: ignore[arg-type]
    assert not opener.requests


@pytest.mark.parametrize("status", [201, 204, 301, 302, 303, 307, 308, 400, 404, 429, 500])
def test_non_200_response_never_returns_jwks(status: int) -> None:
    response = FakeResponse(status=status)
    with pytest.raises(OidcJwksHttpError, match="rejected"):
        fetcher(FakeOpener(response)).fetch(metadata())
    assert response.closed


@pytest.mark.parametrize(
    "response_headers",
    [
        headers(),
        headers(("Content-Type", "text/html")),
        headers(("Content-Type", "application/octet-stream")),
        headers(("Content-Type", "application/json; charset=iso-8859-1")),
        headers(("Content-Type", "application/json; charset=utf-8; extra=true")),
        headers(("Content-Type", "application/json, application/json")),
        headers(("Content-Type", "application/json"), ("Content-Type", "application/json")),
        headers(("Content-Type", "application/json"), ("Content-Encoding", "gzip")),
        headers(("Content-Type", "application/json"), ("Content-Encoding", "br")),
        headers(("Content-Type", "application/json"), ("Content-Encoding", "identity, gzip")),
        headers(("Content-Type", "application/json"), ("Content-Length", "0")),
        headers(("Content-Type", "application/json"), ("Content-Length", "-1")),
        headers(("Content-Type", "application/json"), ("Content-Length", "foo")),
        headers(("Content-Type", "application/json"), ("Content-Length", "262145")),
        headers(("Content-Type", "application/json"), ("Content-Length", "999999999999")),
        headers(
            ("Content-Type", "application/json"),
            ("Content-Length", "2"),
            ("Content-Length", "2"),
        ),
        headers(("Content-Type", "application/json"), ("Transfer-Encoding", "gzip")),
        headers(("Content-Type", "application/json"), ("Transfer-Encoding", "chunked,gzip")),
        headers(
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
            ("Content-Length", "5"),
        ),
        headers(
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
            ("Transfer-Encoding", "chunked"),
        ),
    ],
)
def test_malformed_headers_are_rejected(response_headers: Message) -> None:
    response = FakeResponse(header_values=response_headers)
    with pytest.raises(OidcJwksHttpError):
        fetcher(FakeOpener(response)).fetch(metadata())
    assert response.closed


@pytest.mark.parametrize("invalid_type", [False, {}, "raw bytes", bytearray(b"{}"), None])
def test_non_byte_http_response_is_rejected(invalid_type: object) -> None:
    response = FakeResponse(body=invalid_type)
    with pytest.raises(OidcJwksHttpError):
        fetcher(FakeOpener(response)).fetch(metadata())
    assert response.closed


@pytest.mark.parametrize("declared_length", ["1", "2", "262144"])
def test_declared_content_length_mismatch_is_rejected(declared_length: str) -> None:
    response = FakeResponse(
        header_values=headers(
            ("Content-Type", "application/json"), ("Content-Length", declared_length)
        )
    )
    with pytest.raises(OidcJwksHttpError, match="rejected"):
        fetcher(FakeOpener(response)).fetch(metadata())
    assert response.closed


def test_empty_and_oversized_responses_are_rejected() -> None:
    for body in (b"", b"x" * 262_145):
        response = FakeResponse(body=body)
        with pytest.raises(OidcJwksHttpError):
            fetcher(FakeOpener(response)).fetch(metadata())
        assert response.read_limit == 262_145
        assert response.closed


@pytest.mark.parametrize(
    "exception",
    [
        TimeoutError("secret-jwks-token"),
        URLError("secret-connection-detail"),
        HTTPException("secret-response"),
        ConnectionError("secret-jwks"),
        OSError("secret-host"),
        ValueError("secret-data"),
        TypeError("secret-data"),
        HTTPError(CERN_OIDC_JWKS_URI, 302, "secret-location", {}, None),
    ],
)
def test_network_errors_are_sanitized(exception: Exception) -> None:
    opener = FakeOpener(exception)
    with pytest.raises(OidcJwksHttpError) as raised:
        fetcher(opener).fetch(metadata())
    assert "secret" not in str(raised.value)
    assert "secret" not in repr(raised.value)


@pytest.mark.parametrize(
    "exception", [TimeoutError("secret-read"), OSError("secret-read"), ValueError("secret-read")]
)
def test_read_errors_sanitized_and_resources_closed(exception: Exception) -> None:
    response = FakeResponse(failure=exception)
    with pytest.raises(OidcJwksHttpError) as raised:
        fetcher(FakeOpener(response)).fetch(metadata())
    assert "secret" not in str(raised.value)
    assert response.closed


class BrokenHeaders:
    def get_all(self, name: str, default: list[str]) -> object:
        del name, default
        raise TypeError("secret-header")


class MalformedHeaders:
    def __init__(self, result: object) -> None:
        self.result = result

    def get_all(self, name: str, default: list[str]) -> object:
        del name, default
        return self.result


@pytest.mark.parametrize(
    "invalid",
    [
        BrokenHeaders(),
        MalformedHeaders("text"),
        MalformedHeaders(("a",)),
        MalformedHeaders([1]),
        MalformedHeaders(["bad\nvalue"]),
        MalformedHeaders(["x" * 257]),
        MalformedHeaders([""]),
    ],
)
def test_malformed_header_collection_is_rejected(invalid: object) -> None:
    response = FakeResponse(header_values=invalid)
    with pytest.raises(OidcJwksHttpError) as raised:
        fetcher(FakeOpener(response)).fetch(metadata())
    assert "secret" not in str(raised.value)
    assert response.closed


def test_response_does_not_depend_on_json_body_syntax() -> None:
    """Transport intentionally does not parse JSON; the JWKS parser must do that."""
    response = FakeResponse(body=b"not-json")
    result = fetcher(FakeOpener(response)).fetch(metadata())
    assert result.body == b"not-json"
    assert not hasattr(result, "parsed_keys")


def test_network_is_only_called_after_metadata_validation() -> None:
    opener = FakeOpener(FakeResponse())
    client = fetcher(opener)
    with pytest.raises(OidcJwksHttpError):
        client.fetch(replace(metadata(), jwks_uri="https://attacker.invalid/certs"))
    assert not opener.requests
    client.fetch(metadata())
    assert len(opener.requests) == 1
    assert opener.requests[0].full_url == CERN_OIDC_JWKS_URI


def test_malformed_content_type_control_character_is_rejected() -> None:
    response = FakeResponse(header_values=headers(("Content-Type", "application/json\x7f")))
    with pytest.raises(OidcJwksHttpError):
        fetcher(FakeOpener(response)).fetch(metadata())


def test_unexpected_payload_is_never_an_authenticated_principal() -> None:
    response = FakeResponse(body=b'{"admin":true,"access_token":"synthetic"}')
    retrieved = fetcher(FakeOpener(response)).fetch(metadata())
    for attribute in ("identity", "authenticated", "roles", "access_token", "signature"):
        assert not hasattr(retrieved, attribute)
