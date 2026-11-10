"""Offline tests of single-use, BFF-bound OIDC verification composition."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_authorization_binding import (
    BoundUntrustedCernOidcToken,
    OidcAuthorizationBindingError,
)
from asca.domain.oidc_browser_cookie import COOKIE_NAME, OidcBrowserCookie
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken, OidcVerificationError
from asca.infrastructure.oidc_authorization_binding import CernOidcReplaySafeBffBinding
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000.0
CLIENT = "synthetic-asca-client"
CALLBACK = "https://asca.example.invalid/oidc/callback"


def metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("RS256", "PS256", "ES256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id=CLIENT,
        redirect_uri=CALLBACK,
        mode=OidcClientMode.WEB_BFF,
        scopes=("openid", "profile"),
    )


def tokens() -> ParsedUnverifiedOidcTokenResponse:
    return ParsedUnverifiedOidcTokenResponse(
        access_token="synthetic-access",
        id_token="synthetic.invalid.signature",
        token_type="Bearer",
        expires_in=300,
        refresh_token=None,
        scope=None,
    )


class TestPipeline(CernOidcVerificationPipeline):
    """Offline-only injected pipeline; not evidence of CERN key provenance."""

    __test__ = False

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []
        self.fail = False

    def check(
        self,
        token_data: ParsedUnverifiedOidcTokenResponse,
        provider: OidcProviderMetadata,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        clock_skew_seconds: int = 60,
        max_token_lifetime_seconds: int = 3_600,
        trusted_additional_audiences: tuple[str, ...] = (),
    ) -> CheckedUntrustedCernOidcToken:
        del token_data, clock_skew_seconds, max_token_lifetime_seconds, trusted_additional_audiences
        assert provider.issuer == CERN_OIDC_ISSUER
        self.calls.append((expected_client_id, expected_nonce, now))
        if self.fail:
            raise OidcVerificationError("synthetic internal value")
        return CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="synthetic-subject",
            audiences=(expected_client_id,),
            expires_at=now + 300,
            algorithm="RS256",
            kid="test-key",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )


def make(
    *,
    pipeline: TestPipeline | None = None,
    clock: list[float] | None = None,
    **kwargs: object,
) -> tuple[CernOidcReplaySafeBffBinding, TestPipeline, list[float]]:
    fake = pipeline if pipeline is not None else TestPipeline()
    instant = clock if clock is not None else [NOW]
    service = CernOidcReplaySafeBffBinding(
        registration(),
        metadata(),
        pipeline=fake,
        clock=lambda: instant[0],
        **kwargs,  # type: ignore[arg-type]
    )
    return service, fake, instant


def begin(service: CernOidcReplaySafeBffBinding) -> tuple[str, str, str]:
    start = service.begin()
    params = parse_qs(urlsplit(start.authorization_url).query)
    cookie = start.cookie.set_cookie_header().split(";", 1)[0]
    assert cookie.startswith(COOKIE_NAME + "=")
    assert start.cookie.binding not in start.authorization_url
    assert "code_verifier" not in params
    return cookie, params["state"][0], params["nonce"][0]


def check(service: CernOidcReplaySafeBffBinding, cookie: str, state: str, **changes: object):
    args: dict[str, object] = {
        "cookie_header": cookie,
        "state": state,
        "code": "synthetic-code",
        "tokens": tokens(),
    }
    args.update(changes)
    return service.check_callback(**args)  # type: ignore[arg-type]


def test_issued_nonce_and_client_id_are_bound_to_consumed_attempt() -> None:
    service, fake, _ = make()
    cookie, state, expected_nonce = begin(service)
    actual = check(service, cookie, state)
    assert fake.calls == [(CLIENT, expected_nonce, int(NOW))]
    assert isinstance(actual, BoundUntrustedCernOidcToken)
    assert actual.subject == "synthetic-subject"
    assert actual.audiences == (CLIENT,)
    assert not isinstance(actual, VerifiedIdentity)
    for name in ("authenticated", "session", "roles", "permissions", "access_token", "nonce"):
        assert not hasattr(actual, name)
    for value in (CLIENT, expected_nonce, "synthetic-subject"):
        assert value not in repr(actual)
    with pytest.raises(FrozenInstanceError):
        actual.subject = "forged"  # type: ignore[misc]


def test_begin_returns_valid_cookie_policy() -> None:
    service, _, _ = make(cookie_lifetime_seconds=240)
    result = service.begin()
    header = result.cookie.set_cookie_header()
    assert isinstance(result.cookie, OidcBrowserCookie)
    assert "Max-Age=240" in header
    assert "Secure; HttpOnly; SameSite=Lax" in header
    assert "Path=/" in header
    assert "Clear-Cookie" not in header
    assert "state=" not in repr(result)


def test_two_attempts_have_distinct_nonce_and_state() -> None:
    service, fake, _ = make()
    a_cookie, a_state, a_nonce = begin(service)
    b_cookie, b_state, b_nonce = begin(service)
    assert len({a_cookie, b_cookie}) == 2
    assert len({a_state, b_state}) == 2
    assert len({a_nonce, b_nonce}) == 2
    check(service, b_cookie, b_state)
    check(service, a_cookie, a_state)
    assert [call[1] for call in fake.calls] == [b_nonce, a_nonce]


def test_single_attempt_is_consumed_before_verification() -> None:
    service, fake, _ = make()
    cookie, state, _ = begin(service)
    fake.fail = True
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state)
    fake.fail = False
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state)
    assert len(fake.calls) == 1


def test_wrong_cookie_and_state_do_not_consume_correct_attempt() -> None:
    service, fake, _ = make()
    cookie, state, _ = begin(service)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, f"{COOKIE_NAME}={'A' * 43}", state)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, "invalid")
    assert not fake.calls
    check(service, cookie, state)
    assert len(fake.calls) == 1


def test_callback_expiry_prevents_verification() -> None:
    service, fake, clock = make(ttl_seconds=60, cookie_lifetime_seconds=60)
    cookie, state, _ = begin(service)
    clock[0] += 61
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state)
    assert fake.calls == []


def test_filled_store_rejects_new_begin_until_consumed() -> None:
    service, _, _ = make(max_pending=1)
    cookie, state, _ = begin(service)
    with pytest.raises(OidcAuthorizationBindingError):
        begin(service)
    check(service, cookie, state)
    begin(service)


def test_callback_issuer_optional_or_exact() -> None:
    service, fake, _ = make()
    cookie, state, _ = begin(service)
    check(service, cookie, state, response_issuer=CERN_OIDC_ISSUER)
    assert len(fake.calls) == 1


def test_default_pipeline_and_attempt_store_are_internal() -> None:
    service = CernOidcReplaySafeBffBinding(registration(), metadata(), clock=lambda: NOW)
    assert isinstance(service._pipeline, CernOidcVerificationPipeline)
    assert not hasattr(service, "create_session")
    assert not hasattr(service, "authenticate")


def test_success_is_not_authorization_code_exchange() -> None:
    service, fake, _ = make()
    cookie, state, _ = begin(service)
    result = check(service, cookie, state, code="not-exchanged")
    assert isinstance(result, BoundUntrustedCernOidcToken)
    assert len(fake.calls) == 1
    assert not hasattr(result, "exchange_receipt")
    assert not hasattr(result, "verified_client_registration")
