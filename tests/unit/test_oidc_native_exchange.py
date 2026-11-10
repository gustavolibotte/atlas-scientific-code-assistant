"""Native authorization-code exchange and correlated token checks, offline only."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_exchange import (
    ExchangedUntrustedCernOidcToken,
)
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000.0
CLIENT = "synthetic-native-asca"
REDIRECT = "http://127.0.0.1:8765/callback"


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
        client_id=CLIENT, redirect_uri=REDIRECT, mode=OidcClientMode.NATIVE_LOOPBACK
    )


def body(token: str = "a.b.c") -> bytes:
    return json.dumps(
        {
            "access_token": "synthetic-access",
            "token_type": "Bearer",
            "id_token": token,
            "expires_in": 300,
        }
    ).encode()


class FakeTransport(HttpsOidcTokenTransport):
    def __init__(self) -> None:
        self.requests: list[UnsentOidcTokenRequest] = []
        self.registrations: list[OidcClientRegistration] = []
        self.response: object = UnverifiedOidcTokenHttpResponse(body=body())
        self.failure = False

    def exchange(
        self, prepared: UnsentOidcTokenRequest, client: OidcClientRegistration
    ) -> UnverifiedOidcTokenHttpResponse:
        self.requests.append(prepared)
        self.registrations.append(client)
        if self.failure:
            raise ValueError("sensitive-synthetic-token-transport-error")
        return self.response  # type: ignore[return-value]


class FakeVerifier(CernOidcVerificationPipeline):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int, str]] = []
        self.failure = False
        self.override: dict[str, object] = {}

    def check(
        self,
        tokens,
        metadata,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        clock_skew_seconds: int = 60,
        max_token_lifetime_seconds: int = 3600,
        trusted_additional_audiences: tuple[str, ...] = (),
    ):  # type: ignore[no-untyped-def]
        from dataclasses import replace

        del metadata, clock_skew_seconds, max_token_lifetime_seconds, trusted_additional_audiences
        self.calls.append((expected_client_id, expected_nonce, now, tokens.id_token))
        if self.failure:
            raise ValueError("synthetic-secret-jws-validation-error")
        result = CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="test-native-subject",
            audiences=(expected_client_id,),
            expires_at=now + 250,
            algorithm="RS256",
            kid="synthetic-key",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )
        return replace(result, **self.override)


def make(
    *,
    transport: FakeTransport | None = None,
    verifier: FakeVerifier | None = None,
    clock=None,
    **kwargs,
):
    token_transport = transport if transport is not None else FakeTransport()
    token_verifier = verifier if verifier is not None else FakeVerifier()
    now = [NOW] if clock is None else clock
    service = CernOidcNativeCodeExchange(
        registration(),
        metadata(),
        transport=token_transport,
        verifier=token_verifier,
        clock=lambda: now[0],
        **kwargs,
    )
    return service, token_transport, token_verifier, now


def begin(service: CernOidcNativeCodeExchange) -> tuple[str, str, str, str]:
    started = service.begin()
    query = parse_qs(urlsplit(started.authorization_url).query)
    return started.browser_binding, query["state"][0], query["nonce"][0], query["code_challenge"][0]


def finish(
    service: CernOidcNativeCodeExchange,
    binding: str,
    state: str,
    *,
    code: str = "synthetic-code",
    **kwargs,
):
    return service.exchange_callback(browser_binding=binding, state=state, code=code, **kwargs)


def test_consumed_code_pkce_redirect_and_nonce_are_the_exchange_inputs() -> None:
    service, transport, verifier, _ = make()
    binding, state, nonce, challenge = begin(service)
    result = finish(service, binding, state)
    assert isinstance(result, ExchangedUntrustedCernOidcToken)
    assert not isinstance(result, VerifiedIdentity)
    assert result.subject == "test-native-subject"
    assert len(transport.requests) == 1
    request = transport.requests[0]
    params = parse_qs(request.form_body.decode("ascii"))
    assert params["code"] == ["synthetic-code"]
    assert params["grant_type"] == ["authorization_code"]
    assert params["redirect_uri"] == [REDIRECT]
    assert params["client_id"] == [CLIENT]
    assert len(params["code_verifier"][0]) >= 43
    from asca.application.identity import pkce_s256_challenge

    assert pkce_s256_challenge(params["code_verifier"][0]) == challenge
    assert request.expected_nonce == nonce
    assert verifier.calls == [(CLIENT, nonce, int(NOW), "a.b.c")]
    assert transport.registrations == [registration()]
    assert "synthetic-code" not in repr(request)
    for secret in (nonce, binding, "synthetic-code", CLIENT):
        assert secret not in repr(result)
    assert not hasattr(result, "access_token")
    assert not hasattr(result, "session")
    assert not hasattr(result, "authorization")
    with pytest.raises(FrozenInstanceError):
        result.subject = "forged"  # type: ignore[misc]


def test_native_start_generates_distinct_secret_contexts() -> None:
    service, _, _, _ = make()
    a = begin(service)
    b = begin(service)
    assert a[0] != b[0] and a[1] != b[1] and a[2] != b[2] and a[3] != b[3]
    assert "code_verifier" not in service.begin().authorization_url


def test_default_adapters_exist_but_no_login_route() -> None:
    service = CernOidcNativeCodeExchange(registration(), metadata())
    assert isinstance(service._transport, HttpsOidcTokenTransport)
    assert isinstance(service._verifier, CernOidcVerificationPipeline)
    assert not hasattr(service, "login")
    assert not hasattr(service, "create_session")


def test_manual_token_response_is_not_a_callback_argument() -> None:
    service, _, _, _ = make()
    binding, state, _, _ = begin(service)
    with pytest.raises(TypeError):
        service.exchange_callback(browser_binding=binding, state=state, code="ok", tokens=body())  # type: ignore[call-arg]
    assert finish(service, binding, state).subject == "test-native-subject"


def test_callback_can_omit_issuer_per_existing_contract() -> None:
    service, _, _, _ = make()
    binding, state, _, _ = begin(service)
    assert finish(service, binding, state).subject == "test-native-subject"


def test_exact_callback_issuer_can_be_supplied() -> None:
    service, _, _, _ = make()
    binding, state, _, _ = begin(service)
    assert finish(service, binding, state, response_issuer=CERN_OIDC_ISSUER).subject
