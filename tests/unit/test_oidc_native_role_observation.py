"""Offline tests of role observation bound to one consumed native code grant."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_callback import NativeLoopbackHttpRequest
from asca.domain.oidc_native_exchange import (
    ExchangedUntrustedCernOidcToken,
    OidcNativeExchangeError,
)
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied, OidcNativeLifecycleError
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_role_claims import UntrustedCernRoleObservation
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken, OidcVerificationError
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_native_lifecycle import CernNativeCallbackLifecycle
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

CLIENT = "asca-glibotte-dev"
ROLE = "asca-developer"
REDIRECT = "http://127.0.0.1:45921/oidc/callback"
NOW = 1_800_000_000.0


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id=CLIENT, redirect_uri=REDIRECT, mode=OidcClientMode.NATIVE_LOOPBACK
    )


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


class FakeTransport(HttpsOidcTokenTransport):
    def __init__(self) -> None:
        self.requests: list[UnsentOidcTokenRequest] = []

    def exchange(
        self, prepared: UnsentOidcTokenRequest, _client: OidcClientRegistration
    ) -> UnverifiedOidcTokenHttpResponse:
        self.requests.append(prepared)
        body = json.dumps(
            {"access_token": "synthetic-token", "token_type": "Bearer", "id_token": "a.b.c"}
        ).encode()
        return UnverifiedOidcTokenHttpResponse(body=body)


class FakeVerifier(CernOidcVerificationPipeline):
    def __init__(self) -> None:
        self.observed: list[tuple[str, str, str, int]] = []
        self.checked: list[str] = []
        self.status = "claimed"
        self.invalid = False
        self.fail = False

    def observe_role(
        self,
        tokens: object,
        provider: object,
        *,
        expected_client_id: str,
        expected_nonce: str,
        expected_role: str,
        now: int,
    ) -> UntrustedCernRoleObservation:
        assert provider == metadata()
        assert tokens.access_token == "synthetic-token"
        self.observed.append((expected_client_id, expected_nonce, expected_role, now))
        if self.fail:
            raise OidcVerificationError("synthetic-private-secret")
        if self.invalid:
            return object()  # type: ignore[return-value]
        return UntrustedCernRoleObservation(status=self.status)  # type: ignore[arg-type]

    def check(
        self,
        tokens: object,
        provider: object,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        **_kwargs: object,
    ) -> CheckedUntrustedCernOidcToken:
        assert provider == metadata() and tokens is not None
        self.checked.append(expected_nonce)
        return CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="synthetic-subject",
            audiences=(expected_client_id,),
            expires_at=now + 300,
            algorithm="RS256",
            kid="synthetic-kid",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )


def make() -> tuple[
    CernNativeCallbackLifecycle, CernOidcNativeCodeExchange, FakeTransport, FakeVerifier
]:
    transport = FakeTransport()
    verifier = FakeVerifier()
    exchange = CernOidcNativeCodeExchange(
        registration(), metadata(), transport=transport, verifier=verifier, clock=lambda: NOW
    )
    return CernNativeCallbackLifecycle(exchange), exchange, transport, verifier


def start(lifecycle: CernNativeCallbackLifecycle) -> tuple[str, str, str]:
    grant = lifecycle.begin()
    params = parse_qs(urlsplit(grant.authorization_url).query)
    return grant.browser_binding, params["state"][0], params["nonce"][0]


def callback(state: str, *, denial: bool = False) -> NativeLoopbackHttpRequest:
    query = f"state={state}&" + ("error=access_denied" if denial else "code=synthetic-code")
    return NativeLoopbackHttpRequest(
        method="GET",
        request_target=f"/oidc/callback?{query}",
        http_version="HTTP/1.1",
        headers=(("Host", "127.0.0.1:45921"),),
        peer_ip="127.0.0.1",
        local_ip="127.0.0.1",
        local_port=45921,
    )


@pytest.mark.parametrize(
    "status", ["claimed", "absent", "mfa_required", "loa_required", "mfa_and_loa_required"]
)
def test_role_observation_uses_original_single_use_grant(status: str) -> None:
    lifecycle, _, transport, verifier = make()
    verifier.status = status
    binding, state, nonce = start(lifecycle)
    result = lifecycle.complete_role_observation(request=callback(state), protected_binding=binding)
    assert type(result) is UntrustedCernRoleObservation
    assert result.status == status
    assert result.login == "not_implemented" and result.authorization == "not_implemented"
    assert verifier.observed == [(CLIENT, nonce, ROLE, int(NOW))]
    assert verifier.checked == []
    assert len(transport.requests) == 1
    assert "synthetic-code" not in repr(transport.requests[0])
    for secret in (binding, state, nonce, "synthetic-token"):
        assert secret not in repr(result)
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=callback(state), protected_binding=binding)
    assert len(transport.requests) == 1


def test_existing_token_check_path_remains_unchanged() -> None:
    lifecycle, _, transport, verifier = make()
    binding, state, _ = start(lifecycle)
    result = lifecycle.complete(request=callback(state), protected_binding=binding)
    assert type(result) is ExchangedUntrustedCernOidcToken
    assert len(verifier.checked) == 1 and not verifier.observed
    assert len(transport.requests) == 1


def test_correlated_denial_consumes_without_token_exchange() -> None:
    lifecycle, _, transport, verifier = make()
    binding, state, _ = start(lifecycle)
    result = lifecycle.complete_role_observation(
        request=callback(state, denial=True), protected_binding=binding
    )
    assert type(result) is NativeCallbackDenied
    assert not transport.requests and not verifier.observed
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete_role_observation(request=callback(state), protected_binding=binding)
    assert not transport.requests


def test_direct_exchange_observation_is_single_use() -> None:
    lifecycle, exchange, transport, _ = make()
    binding, state, _ = start(lifecycle)
    result = exchange.exchange_callback_observe_role(
        browser_binding=binding, state=state, code="synthetic-code"
    )
    assert result.status == "claimed" and len(transport.requests) == 1
    with pytest.raises(OidcNativeExchangeError):
        exchange.exchange_callback_observe_role(
            browser_binding=binding, state=state, code="synthetic-code"
        )
    assert len(transport.requests) == 1
