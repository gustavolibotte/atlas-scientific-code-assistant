"""Transport threat tests: redirect, SSRF, truncation and ambiguous JSON."""

from io import BytesIO
from urllib.error import URLError
from urllib.request import Request

import pytest

from asca.application.oidc_discovery import CERN_OIDC_DISCOVERY_URL, OidcDiscoveryPolicy
from asca.domain.oidc_discovery import OidcDiscoveryError
from asca.infrastructure.oidc_http import HttpsOidcMetadataFetcher, _NoRedirect


class FakeResponse:
    def __init__(self, payload: bytes, *, status: int = 200, mime: str = "application/json"):
        self.buffer = BytesIO(payload)
        self.status = status
        self.headers = {"Content-Type": mime}
        self.closed = False

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True

    def read(self, count: int = -1) -> bytes:
        return self.buffer.read(count)


class FakeOpener:
    def __init__(self, response: FakeResponse | Exception):
        self.result = response
        self.requests: list[Request] = []
        self.timeout: float | None = None

    def open(self, request: Request, *, timeout: float) -> FakeResponse:
        self.requests.append(request)
        self.timeout = timeout
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def fetcher(response: FakeResponse | Exception) -> tuple[HttpsOidcMetadataFetcher, FakeOpener]:
    opener = FakeOpener(response)
    # The injected opener is a deterministic test double, never a real network opener.
    subject = HttpsOidcMetadataFetcher(
        OidcDiscoveryPolicy(),
        opener=opener,  # type: ignore[arg-type]
    )
    return subject, opener


def test_public_json_is_decoded_with_bounded_request() -> None:
    response = FakeResponse(b'{"issuer":"safe"}', mime="application/json; charset=utf-8")
    subject, opener = fetcher(response)
    assert subject.fetch(CERN_OIDC_DISCOVERY_URL) == {"issuer": "safe"}
    assert len(opener.requests) == 1
    request = opener.requests[0]
    assert request.full_url == CERN_OIDC_DISCOVERY_URL
    assert request.get_method() == "GET"
    assert request.get_header("Accept") == "application/json"
    assert not request.has_header("Authorization")
    assert not request.has_header("Cookie")
    assert opener.timeout == 5.0


def test_rejects_unapproved_url_without_network() -> None:
    subject, opener = fetcher(FakeResponse(b"{}"))
    with pytest.raises(OidcDiscoveryError, match="allowlisted"):
        subject.fetch("https://evil.invalid/metadata")
    assert not opener.requests


@pytest.mark.parametrize("timeout", [0, -1, 16, 100])
def test_disallows_unbounded_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        HttpsOidcMetadataFetcher(OidcDiscoveryPolicy(), timeout_seconds=timeout)


@pytest.mark.parametrize(
    ("status", "mime"),
    [(302, "application/json"), (401, "application/json"), (200, "text/html"), (200, "")],
)
def test_rejects_redirect_status_and_unexpected_media_type(status: int, mime: str) -> None:
    subject, _ = fetcher(FakeResponse(b"{}", status=status, mime=mime))
    with pytest.raises(OidcDiscoveryError, match="HTTP response"):
        subject.fetch(CERN_OIDC_DISCOVERY_URL)


def test_rejects_oversized_json() -> None:
    subject, _ = fetcher(FakeResponse(b" " * 262145))
    with pytest.raises(OidcDiscoveryError, match="size limit"):
        subject.fetch(CERN_OIDC_DISCOVERY_URL)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b'{"issuer":"a","issuer":"b"}', "duplicate"),
        (b'{"issuer":NaN}', "non-finite|strict JSON"),
        (b'{"issuer":Infinity}', "non-finite|strict JSON"),
        (b'{"broken":', "strict JSON"),
        (b"\xff", "strict JSON"),
    ],
)
def test_rejects_ambiguous_or_invalid_json(payload: bytes, message: str) -> None:
    subject, _ = fetcher(FakeResponse(payload))
    with pytest.raises(OidcDiscoveryError, match=message):
        subject.fetch(CERN_OIDC_DISCOVERY_URL)


def test_network_errors_are_sanitized() -> None:
    subject, _ = fetcher(URLError("user supplied secret URL"))
    with pytest.raises(OidcDiscoveryError, match="HTTPS request failed") as captured:
        subject.fetch(CERN_OIDC_DISCOVERY_URL)
    assert "secret" not in str(captured.value)


def test_response_stream_is_closed() -> None:
    response = FakeResponse(b"{}")
    subject, _ = fetcher(response)
    subject.fetch(CERN_OIDC_DISCOVERY_URL)
    assert response.closed


def test_redirect_handler_rejects_following_any_location() -> None:
    handler = _NoRedirect()
    request = Request(CERN_OIDC_DISCOVERY_URL)
    assert (
        handler.redirect_request(request, None, 302, "Moved", {}, "https://attacker.invalid/stolen")
        is None
    )


def test_default_opener_installs_no_redirect_handler() -> None:
    subject = HttpsOidcMetadataFetcher(OidcDiscoveryPolicy())
    assert any(isinstance(item, _NoRedirect) for item in subject._opener.handlers)


def test_rejects_invalid_content_type_header_value() -> None:
    response = FakeResponse(b"{}")
    response.headers["Content-Type"] = None  # type: ignore[assignment]
    subject, _ = fetcher(response)
    with pytest.raises(OidcDiscoveryError, match="HTTP response"):
        subject.fetch(CERN_OIDC_DISCOVERY_URL)
