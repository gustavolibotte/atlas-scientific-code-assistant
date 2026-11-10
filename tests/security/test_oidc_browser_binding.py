"""Security regression tests for offline OIDC browser/callback correlation."""

from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.identity import OidcAuthorizationService, OidcClientConfiguration
from asca.application.oidc_browser_binding import (
    begin_web_bff_authorization,
    finish_web_bff_callback,
)
from asca.domain.identity import AuthenticationFlowError, VerifiedIdentity
from asca.domain.oidc_browser_cookie import (
    COOKIE_NAME,
    OidcBrowserCookie,
    OidcBrowserCookieError,
    read_browser_binding_cookie,
)
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.infrastructure.identity_memory import InMemoryAuthorizationAttemptStore


def _fixture() -> tuple[OidcAuthorizationService, OidcClientRegistration]:
    registration = OidcClientRegistration(
        client_id="example-not-registered",
        redirect_uri="https://asca.example.org/api/v1/identity/callback",
        mode=OidcClientMode.WEB_BFF,
    )
    service = OidcAuthorizationService(
        OidcClientConfiguration(
            issuer="https://example.invalid/issuer",
            authorization_endpoint="https://example.invalid/authorize",
            client_id=registration.client_id,
            redirect_uri=registration.redirect_uri,
            scopes=registration.scopes,
        ),
        InMemoryAuthorizationAttemptStore(),
        clock=lambda: 100.0,
    )
    return service, registration


def test_web_bff_callback_requires_original_cookie_and_state() -> None:
    service, registration = _fixture()
    start = begin_web_bff_authorization(service, registration)
    state = parse_qs(urlsplit(start.authorization_url).query)["state"][0]
    assert start.cookie.binding not in start.authorization_url
    assert start.cookie.binding not in repr(start)
    header = start.cookie.set_cookie_header()
    cookie_pair = header.split(";", 1)[0]
    grant = finish_web_bff_callback(
        service, cookie_header=cookie_pair, state=state, code="unverified-code"
    )
    assert grant.code == "unverified-code"
    assert not isinstance(grant, VerifiedIdentity)
    assert grant.code not in repr(grant)
    with pytest.raises(AuthenticationFlowError):
        finish_web_bff_callback(
            service, cookie_header=cookie_pair, state=state, code="unverified-code"
        )


def test_no_cookie_or_other_cookie_cannot_finish() -> None:
    service, registration = _fixture()
    start = begin_web_bff_authorization(service, registration)
    state = parse_qs(urlsplit(start.authorization_url).query)["state"][0]
    for header in (None, "", "other=value"):
        with pytest.raises(OidcBrowserCookieError):
            finish_web_bff_callback(service, cookie_header=header, state=state, code="code")
    # The original, non-consumed attempt remains valid.
    result = finish_web_bff_callback(
        service, cookie_header=f"{COOKIE_NAME}={start.cookie.binding}", state=state, code="code"
    )
    assert result.code == "code"


def test_wrong_browser_cookie_does_not_consume_original_attempt() -> None:
    service, registration = _fixture()
    start = begin_web_bff_authorization(service, registration)
    other = begin_web_bff_authorization(service, registration)
    state = parse_qs(urlsplit(start.authorization_url).query)["state"][0]
    with pytest.raises(AuthenticationFlowError):
        finish_web_bff_callback(
            service, cookie_header=f"{COOKIE_NAME}={other.cookie.binding}", state=state, code="code"
        )
    grant = finish_web_bff_callback(
        service, cookie_header=f"{COOKIE_NAME}={start.cookie.binding}", state=state, code="code"
    )
    assert grant.code == "code"


def test_invalid_state_does_not_consume_original_attempt() -> None:
    service, registration = _fixture()
    start = begin_web_bff_authorization(service, registration)
    with pytest.raises(AuthenticationFlowError):
        finish_web_bff_callback(
            service,
            cookie_header=f"{COOKIE_NAME}={start.cookie.binding}",
            state="altered",
            code="code",
        )


def test_native_registration_is_rejected_before_creating_attempt() -> None:
    service, _ = _fixture()
    native = OidcClientRegistration(
        client_id="example-not-registered",
        redirect_uri="http://127.0.0.1:8765/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )
    with pytest.raises(OidcBrowserCookieError, match="web BFF"):
        begin_web_bff_authorization(service, native)


def test_invalid_lifetime_is_rejected_before_creating_attempt() -> None:
    service, registration = _fixture()
    with pytest.raises(OidcBrowserCookieError, match="lifetime"):
        begin_web_bff_authorization(service, registration, cookie_lifetime_seconds=0)


@pytest.mark.parametrize(
    "header",
    [
        "",
        "x=y",
        f"{COOKIE_NAME}=bad",
        f"{COOKIE_NAME}=abc\nnext=trick",
        f"{COOKIE_NAME}=abc\rnext=trick",
        f'{COOKIE_NAME}="quoted"',
        f"{COOKIE_NAME}={'a' * 43}; {COOKIE_NAME}={'b' * 43}",
        f"{COOKIE_NAME}={'a' * 43}; broken",
        f"{COOKIE_NAME}={'a' * 43}; ; trailing=value",
        f"{COOKIE_NAME}={'a' * 43}; other=é",
        "x=y" * 3000,
    ],
)
def test_malformed_or_ambiguous_cookie_header_is_rejected(header: str) -> None:
    with pytest.raises(OidcBrowserCookieError):
        read_browser_binding_cookie(header)


def test_cookie_cannot_be_mistaken_for_authenticated_session() -> None:
    cookie = OidcBrowserCookie("A" * 43)
    assert not hasattr(cookie, "authenticated_identity")
    assert not hasattr(cookie, "access_token")
    assert not hasattr(cookie, "refresh_token")


def test_well_formed_but_unissued_cookie_is_not_authorized() -> None:
    service, registration = _fixture()
    start = begin_web_bff_authorization(service, registration)
    state = parse_qs(urlsplit(start.authorization_url).query)["state"][0]
    with pytest.raises(AuthenticationFlowError):
        finish_web_bff_callback(
            service,
            cookie_header=f"{COOKIE_NAME}={'A' * 43}",
            state=state,
            code="code",
        )
    result = finish_web_bff_callback(
        service,
        cookie_header=f"{COOKIE_NAME}={start.cookie.binding}",
        state=state,
        code="code",
    )
    assert result.code == "code"


def test_denied_authorization_consumes_attempt() -> None:
    service, registration = _fixture()
    start = begin_web_bff_authorization(service, registration)
    state = parse_qs(urlsplit(start.authorization_url).query)["state"][0]
    cookie = f"{COOKIE_NAME}={start.cookie.binding}"
    with pytest.raises(AuthenticationFlowError):
        finish_web_bff_callback(service, cookie_header=cookie, state=state, error="access_denied")
    with pytest.raises(AuthenticationFlowError):
        finish_web_bff_callback(service, cookie_header=cookie, state=state, code="code")
