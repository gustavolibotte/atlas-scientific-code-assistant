"""Deterministic native OIDC bootstrap checks using synthetic public discovery."""

from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError, fields
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPSHandler, ProxyHandler

import pytest

from asca.application.oidc_discovery import CERN_OIDC_DISCOVERY_URL, CERN_OIDC_ISSUER
from asca.domain.oidc_native_bootstrap import NativeOidcIsolationStatus, OidcNativeBootstrapError
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.infrastructure.oidc_http import HttpsOidcMetadataFetcher
from asca.infrastructure.oidc_jwks_http import HttpsCernOidcJwksFetcher
from asca.infrastructure.oidc_native_bootstrap import (
    CernOidcNativeUntrustedBootstrap,
    _RejectDiscoveryRedirects,
)
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

CLIENT = "synthetic-native-asca-client"


def registration(*, ipv6: bool = False) -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id=CLIENT,
        redirect_uri=("http://[::1]:8765/callback" if ipv6 else "http://127.0.0.1:8765/callback"),
        mode=OidcClientMode.NATIVE_LOOPBACK,
        scopes=("openid", "profile"),
    )


def discovery(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "issuer": CERN_OIDC_ISSUER,
        "authorization_endpoint": CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        "token_endpoint": CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        "jwks_uri": CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256", "PS256", "ES256"],
    }
    result.update(changes)
    return result


def fake_discovery(monkeypatch: pytest.MonkeyPatch, data: object | None = None) -> list[str]:
    calls: list[str] = []
    response = discovery() if data is None else data

    def fetch(self: HttpsOidcMetadataFetcher, url: str) -> object:
        assert isinstance(self, HttpsOidcMetadataFetcher)
        calls.append(url)
        return response

    monkeypatch.setattr(HttpsOidcMetadataFetcher, "fetch", fetch)
    return calls


def test_isolation_status_cannot_claim_authentication() -> None:
    status = NativeOidcIsolationStatus()
    assert status.mode == "native_loopback"
    assert status.login == "not_implemented"
    assert status.client_registration_attested is False
    assert status.loopback_listener_secured is False
    assert status.production_identity_authority is False
    assert all(not field.init for field in fields(status))
    assert not hasattr(status, "identity")
    assert not hasattr(status, "permissions")
    with pytest.raises((FrozenInstanceError, AttributeError)):
        status.login = "available"  # type: ignore[misc]


def test_bootstrap_status_is_descriptive_and_unprivileged() -> None:
    bootstrap = CernOidcNativeUntrustedBootstrap(registration())
    assert bootstrap.isolation_status == NativeOidcIsolationStatus()
    assert not hasattr(bootstrap, "login")
    assert not hasattr(bootstrap, "create_session")
    assert CLIENT not in repr(bootstrap)


@pytest.mark.parametrize("ipv6", [False, True])
def test_builds_only_default_native_adapters(monkeypatch: pytest.MonkeyPatch, ipv6: bool) -> None:
    calls = fake_discovery(monkeypatch)
    bootstrap = CernOidcNativeUntrustedBootstrap(registration(ipv6=ipv6))
    service = bootstrap.build()
    assert type(service) is CernOidcNativeCodeExchange
    assert type(service._transport) is HttpsOidcTokenTransport
    assert type(service._verifier) is CernOidcVerificationPipeline
    assert type(service._verifier._fetcher) is HttpsCernOidcJwksFetcher
    assert service._client_id == CLIENT
    assert service._registration.mode is OidcClientMode.NATIVE_LOOPBACK
    assert calls == [CERN_OIDC_DISCOVERY_URL]
    assert not hasattr(service, "create_session")


def test_native_pre_authentication_start_is_pkce_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_discovery(monkeypatch)
    native = CernOidcNativeUntrustedBootstrap(registration()).build()
    issued = native.begin()
    url = urlsplit(issued.authorization_url)
    params = parse_qs(url.query)
    assert url.scheme == "https"
    assert params["response_type"] == ["code"]
    assert params["client_id"] == [CLIENT]
    assert params["redirect_uri"] == [registration().redirect_uri]
    assert params["code_challenge_method"] == ["S256"]
    assert params["scope"] == ["openid profile"]
    assert len(params["state"][0]) >= 43
    assert len(params["nonce"][0]) >= 43
    assert len(params["code_challenge"][0]) == 43
    assert issued.browser_binding not in issued.authorization_url
    assert "code_verifier" not in params
    assert not hasattr(issued, "verified_identity")


def test_one_build_means_one_pinned_public_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = fake_discovery(monkeypatch)
    bootstrap = CernOidcNativeUntrustedBootstrap(registration())
    first = bootstrap.build()
    second = bootstrap.build()
    assert first is not second
    assert first._store is not second._store
    assert first._verifier is not second._verifier
    assert calls == [CERN_OIDC_DISCOVERY_URL, CERN_OIDC_DISCOVERY_URL]


def test_explicit_proxy_isolation_tls_and_redirect_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[HttpsOidcMetadataFetcher] = []

    def fetch(self: HttpsOidcMetadataFetcher, url: str) -> object:
        assert url == CERN_OIDC_DISCOVERY_URL
        observed.append(self)
        return discovery()

    monkeypatch.setattr(HttpsOidcMetadataFetcher, "fetch", fetch)
    CernOidcNativeUntrustedBootstrap(registration()).build()
    assert len(observed) == 1
    opener = observed[0]._opener
    handlers = opener.handlers
    proxies = [handler for handler in handlers if isinstance(handler, ProxyHandler)]
    # Empty ProxyHandler installs no protocol handlers; environment proxies are not used.
    assert proxies == []
    https = [handler for handler in handlers if isinstance(handler, HTTPSHandler)]
    assert len(https) == 1
    assert https[0]._context.check_hostname is True
    assert any(isinstance(handler, _RejectDiscoveryRedirects) for handler in handlers)
    handler = next(h for h in handlers if isinstance(h, _RejectDiscoveryRedirects))
    assert (
        handler.redirect_request(None, None, 302, "redirect", None, "https://evil.invalid") is None
    )


def test_no_caller_supplied_transport_or_metadata_arguments() -> None:
    init = inspect.signature(CernOidcNativeUntrustedBootstrap)
    build = inspect.signature(CernOidcNativeUntrustedBootstrap.build)
    assert tuple(init.parameters) == ("registration",)
    assert tuple(build.parameters) == ("self",)
    with pytest.raises(TypeError):
        CernOidcNativeUntrustedBootstrap(  # type: ignore[call-arg]
            registration(), transport=object()
        )
    with pytest.raises(TypeError):
        CernOidcNativeUntrustedBootstrap(registration()).build(  # type: ignore[call-arg]
            metadata=object()
        )


def test_build_does_not_accept_tokens_nonces_or_forged_results() -> None:
    instance = CernOidcNativeUntrustedBootstrap(registration())
    with pytest.raises(TypeError):
        instance.build(tokens="attacker-token")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        instance.build(expected_nonce="attacker-nonce")  # type: ignore[call-arg]


def test_registration_is_independently_reconstructed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_discovery(monkeypatch)
    declared = registration()
    bootstrap = CernOidcNativeUntrustedBootstrap(declared)
    object.__setattr__(declared, "client_id", "attacker-client")
    native = bootstrap.build()
    assert native._client_id == CLIENT


@pytest.mark.parametrize("algorithms", [["RS256"], ["ES256"], ["PS256"], ["PS256", "RS256"]])
def test_approved_asymmetric_algorithm_subsets(
    monkeypatch: pytest.MonkeyPatch, algorithms: list[str]
) -> None:
    fake_discovery(monkeypatch, discovery(id_token_signing_alg_values_supported=algorithms))
    service = CernOidcNativeUntrustedBootstrap(registration()).build()
    assert set(service._metadata.approved_id_token_algorithms) == set(algorithms)


def test_registration_error_type_is_sanitized() -> None:
    assert issubclass(OidcNativeBootstrapError, ValueError)
    assert "token" not in str(OidcNativeBootstrapError("rejected"))


def test_environment_proxy_cannot_redirect_public_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://attacker.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid:8080")
    seen: list[HttpsOidcMetadataFetcher] = []

    def fetch(self: HttpsOidcMetadataFetcher, url: str) -> object:
        assert url == CERN_OIDC_DISCOVERY_URL
        seen.append(self)
        return discovery()

    monkeypatch.setattr(HttpsOidcMetadataFetcher, "fetch", fetch)
    CernOidcNativeUntrustedBootstrap(registration()).build()
    assert len(seen) == 1
    assert not any(isinstance(handler, ProxyHandler) for handler in seen[0]._opener.handlers)
