"""Native callback lifecycle: successful callbacks and correlated denial, offline."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_callback import NativeLoopbackHttpRequest
from asca.domain.oidc_native_exchange import ExchangedUntrustedCernOidcToken
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied, OidcNativeLifecycleError
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_native_lifecycle import CernNativeCallbackLifecycle
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000.0
CLIENT = "offline-lifecycle-client"
DENIAL = "access_denied"


def registration(host: str = "127.0.0.1") -> OidcClientRegistration:
    authority = "[::1]" if host == "::1" else host
    return OidcClientRegistration(
        client_id=CLIENT,
        redirect_uri=f"http://{authority}:45921/oidc/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
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
        self.fail = False

    def exchange(
        self, prepared: UnsentOidcTokenRequest, client: OidcClientRegistration
    ) -> UnverifiedOidcTokenHttpResponse:
        assert client.client_id == CLIENT
        self.requests.append(prepared)
        if self.fail:
            raise ValueError("sensitive-transport-failure")
        body = json.dumps(
            {"access_token": "synthetic-token", "token_type": "Bearer", "id_token": "a.b.c"}
        ).encode("utf-8")
        return UnverifiedOidcTokenHttpResponse(body=body)


class FakeVerifier(CernOidcVerificationPipeline):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail = False

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
        assert provider == metadata()
        assert tokens is not None
        self.calls.append((expected_client_id, expected_nonce))
        if self.fail:
            raise ValueError("sensitive-verifier-failure")
        return CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="synthetic-subject",
            audiences=(expected_client_id,),
            expires_at=now + 200,
            algorithm="RS256",
            kid="synthetic-kid",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )


def make(host: str = "127.0.0.1", *, ttl: int = 300):
    clock = [NOW]
    transport = FakeTransport()
    verifier = FakeVerifier()
    exchange = CernOidcNativeCodeExchange(
        registration(host),
        metadata(),
        transport=transport,
        verifier=verifier,
        clock=lambda: clock[0],
        ttl_seconds=ttl,
    )
    lifecycle = CernNativeCallbackLifecycle(exchange)
    return lifecycle, exchange, transport, verifier, clock


def start(lifecycle: CernNativeCallbackLifecycle) -> tuple[str, str]:
    started = lifecycle.begin()
    state = parse_qs(urlsplit(started.authorization_url).query)["state"][0]
    return started.browser_binding, state


def request(state: str, *, host: str = "127.0.0.1", **changes: object):
    authority = f"[{host}]:45921" if ":" in host else f"{host}:45921"
    values: dict[str, object] = {
        "method": "GET",
        "request_target": f"/oidc/callback?state={state}&error={DENIAL}",
        "http_version": "HTTP/1.1",
        "headers": (("Host", authority),),
        "peer_ip": host,
        "local_ip": host,
        "local_port": 45921,
        "body": b"",
    }
    values.update(changes)
    return NativeLoopbackHttpRequest(**values)  # type: ignore[arg-type]


def test_denial_consumes_exactly_once_and_never_posts_token() -> None:
    lifecycle, _, transport, verifier, _ = make()
    binding, state = start(lifecycle)
    outcome = lifecycle.complete(request=request(state), protected_binding=binding)
    assert outcome == NativeCallbackDenied()
    assert outcome.status == "denied" and outcome.login == "not_implemented"
    assert not isinstance(outcome, VerifiedIdentity)
    assert transport.requests == [] and verifier.calls == []
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=request(state), protected_binding=binding)
    assert not hasattr(outcome, "token") and not hasattr(outcome, "subject")
    assert binding not in repr(outcome) and state not in repr(outcome)
    with pytest.raises(FrozenInstanceError):
        outcome.status = "authenticated"  # type: ignore[misc]


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_success_uses_same_store_and_can_only_post_once(host: str) -> None:
    lifecycle, _, transport, verifier, _ = make(host)
    binding, state = start(lifecycle)
    success = request(
        state,
        host=host,
        request_target=f"/oidc/callback?state={state}&code=synthetic-code",
    )
    result = lifecycle.complete(request=success, protected_binding=binding)
    assert isinstance(result, ExchangedUntrustedCernOidcToken)
    assert result.subject == "synthetic-subject"
    assert len(transport.requests) == len(verifier.calls) == 1
    assert not isinstance(result, VerifiedIdentity)
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=success, protected_binding=binding)
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=request(state, host=host), protected_binding=binding)
    assert len(transport.requests) == 1


def test_denial_then_success_rejected_without_token_post() -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    lifecycle.complete(request=request(state), protected_binding=binding)
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(
            request=request(state, request_target=f"/oidc/callback?state={state}&code=abc"),
            protected_binding=binding,
        )
    assert transport.requests == []


def test_wrong_state_denial_does_not_consume_the_correct_state() -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=request("Z" * 43), protected_binding=binding)
    assert lifecycle.complete(request=request(state), protected_binding=binding).status == "denied"
    assert transport.requests == []


def test_wrong_binding_denial_does_not_consume() -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=request(state), protected_binding="Y" * 43)
    assert lifecycle.complete(request=request(state), protected_binding=binding).status == "denied"
    assert transport.requests == []


def test_expiration_rejects_denial_and_fresh_start_succeeds() -> None:
    lifecycle, _, transport, _, clock = make(ttl=30)
    binding, state = start(lifecycle)
    clock[0] += 31
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=request(state), protected_binding=binding)
    fresh_binding, fresh_state = start(lifecycle)
    assert (
        lifecycle.complete(request=request(fresh_state), protected_binding=fresh_binding).status
        == "denied"
    )
    assert transport.requests == []


@pytest.mark.parametrize("error", ["access_denied", "login_required", "interaction_required"])
def test_supported_denial_tokens_are_preserved_as_denial_only(error: str) -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    outcome = lifecycle.complete(
        request=request(state, request_target=f"/oidc/callback?state={state}&error={error}"),
        protected_binding=binding,
    )
    assert outcome.status == "denied"
    assert transport.requests == []


def test_issuer_validated_before_denying() -> None:
    from urllib.parse import quote

    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    invalid = request(
        state, request_target=f"/oidc/callback?state={state}&error=access_denied&iss=x"
    )
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=invalid, protected_binding=binding)
    valid = request(
        state,
        request_target=(
            f"/oidc/callback?state={state}&error=access_denied"
            f"&iss={quote(CERN_OIDC_ISSUER, safe='')}"
        ),
    )
    assert lifecycle.complete(request=valid, protected_binding=binding).status == "denied"
    assert transport.requests == []


def test_new_authorization_after_denial_uses_different_binding_and_state() -> None:
    lifecycle, _, _, _, _ = make()
    first = start(lifecycle)
    assert lifecycle.complete(request=request(first[1]), protected_binding=first[0]).status
    second = start(lifecycle)
    assert first[0] != second[0] and first[1] != second[1]
    assert lifecycle.complete(request=request(second[1]), protected_binding=second[0]).status


def test_forged_registration_subclass_is_not_accepted_by_lifecycle() -> None:
    from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange

    class FakeExchange(CernOidcNativeCodeExchange):
        pass

    with pytest.raises(OidcNativeLifecycleError):
        CernNativeCallbackLifecycle(FakeExchange(registration(), metadata()))


def test_lifecycle_cannot_accept_callback_tokens_or_verifiers() -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    with pytest.raises(TypeError):
        lifecycle.complete(  # type: ignore[call-arg]
            request=request(state),
            protected_binding=binding,
            id_token="synthetic-evil",
        )
    assert lifecycle.complete(request=request(state), protected_binding=binding).status
    assert transport.requests == []


def test_injected_authorization_start_failure_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    lifecycle, exchange, _, _, _ = make()

    def rejected_start() -> None:
        raise ValueError("secret-start-implementation-error")

    monkeypatch.setattr(exchange, "begin", rejected_start)
    with pytest.raises(OidcNativeLifecycleError) as caught:
        lifecycle.begin()
    assert "secret" not in str(caught.value)


def test_forged_native_registration_rejected_during_construction() -> None:
    exchange = CernOidcNativeCodeExchange(registration(), metadata())
    object.__setattr__(exchange, "_registration", object())
    with pytest.raises(OidcNativeLifecycleError):
        CernNativeCallbackLifecycle(exchange)


def test_missing_code_after_forged_policy_result_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from asca.domain.oidc_native_callback import ParsedUntrustedNativeCallback

    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    monkeypatch.setattr(
        lifecycle._policy,
        "parse",
        lambda _request: ParsedUntrustedNativeCallback(
            state=state, code=None, error=None, response_issuer=None
        ),
    )
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=request(state), protected_binding=binding)
    assert transport.requests == []
