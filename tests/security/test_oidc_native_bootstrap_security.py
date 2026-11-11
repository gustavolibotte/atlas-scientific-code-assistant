"""Adversarial native bootstrap checks: fail closed, no login authority.

Every metadata response is synthetic. No CERN request or credential is used.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER, OidcDiscoveryService
from asca.domain.oidc_discovery import OidcDiscoveryError, OidcProviderMetadata
from asca.domain.oidc_native_bootstrap import NativeOidcIsolationStatus, OidcNativeBootstrapError
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.infrastructure import oidc_native_bootstrap as bootstrap_module
from asca.infrastructure.oidc_http import HttpsOidcMetadataFetcher
from asca.infrastructure.oidc_native_bootstrap import CernOidcNativeUntrustedBootstrap
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange

CLIENT = "synthetic-client-security-fixture"


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id=CLIENT,
        redirect_uri="http://127.0.0.1:8000/oidc/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )


def discovery() -> dict[str, object]:
    return {
        "issuer": CERN_OIDC_ISSUER,
        "authorization_endpoint": CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        "token_endpoint": CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        "jwks_uri": CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256", "PS256"],
    }


def metadata() -> OidcProviderMetadata:
    d = discovery()
    return OidcProviderMetadata(
        issuer=str(d["issuer"]),
        authorization_endpoint=str(d["authorization_endpoint"]),
        token_endpoint=str(d["token_endpoint"]),
        jwks_uri=str(d["jwks_uri"]),
        approved_id_token_algorithms=("ES256", "PS256", "RS256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def install_fetch(monkeypatch: pytest.MonkeyPatch, obj: object) -> list[str]:
    urls: list[str] = []

    def fetch(_self: HttpsOidcMetadataFetcher, url: str) -> object:
        urls.append(url)
        return obj

    monkeypatch.setattr(HttpsOidcMetadataFetcher, "fetch", fetch)
    return urls


def rejected(monkeypatch: pytest.MonkeyPatch, document: object) -> None:
    urls = install_fetch(monkeypatch, document)
    with pytest.raises(OidcNativeBootstrapError) as exc:
        CernOidcNativeUntrustedBootstrap(registration()).build()
    assert str(exc.value) == "CERN native bootstrap was rejected"
    assert exc.value.__cause__ is None
    assert len(urls) == 1


@pytest.mark.parametrize("bad", [None, False, 0, 1, {}, [], "native", object()])
def test_reject_nonregistration_without_discovery(bad: object) -> None:
    with pytest.raises(OidcNativeBootstrapError, match="declaration"):
        CernOidcNativeUntrustedBootstrap(bad)  # type: ignore[arg-type]


def test_web_bff_cannot_be_bootstrapped_as_native() -> None:
    web = OidcClientRegistration(
        client_id=CLIENT,
        redirect_uri="https://asca.example.invalid/oidc/callback",
        mode=OidcClientMode.WEB_BFF,
    )
    with pytest.raises(OidcNativeBootstrapError, match="declaration"):
        CernOidcNativeUntrustedBootstrap(web)


def test_registration_subclass_is_not_accepted() -> None:
    class ForgedRegistration(OidcClientRegistration):
        pass

    forged = ForgedRegistration(
        client_id=CLIENT,
        redirect_uri="http://127.0.0.1:8000/oidc/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )
    with pytest.raises(OidcNativeBootstrapError):
        CernOidcNativeUntrustedBootstrap(forged)


@pytest.mark.parametrize(
    "mutation",
    [
        {"client_id": "attacker id with spaces"},
        {"client_id": None},
        {"redirect_uri": "https://evil.invalid/callback"},
        {"redirect_uri": "http://169.254.169.254/callback"},
        {"redirect_uri": "http://127.0.0.1:0/callback"},
        {"redirect_uri": None},
        {"scopes": ("openid", "admin")},
        {"scopes": ["openid"]},
        {"mode": "native_loopback"},
    ],
)
def test_mutated_frozen_registration_rejected(mutation: dict[str, object]) -> None:
    declared = registration()
    for name, value in mutation.items():
        object.__setattr__(declared, name, value)
    with pytest.raises(OidcNativeBootstrapError, match="declaration"):
        CernOidcNativeUntrustedBootstrap(declared)


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "https://evil.invalid"},
        {"issuer": CERN_OIDC_ISSUER + "/elsewhere"},
        {"authorization_endpoint": "https://evil.invalid/authorize"},
        {"authorization_endpoint": CERN_OIDC_ISSUER + "/wrong"},
        {"authorization_endpoint": CERN_OIDC_ISSUER + "/protocol/openid-connect/auth?x=1"},
        {"token_endpoint": "https://evil.invalid/token"},
        {"token_endpoint": CERN_OIDC_ISSUER + "/wrong-token"},
        {"jwks_uri": "https://evil.invalid/jwks"},
        {"jwks_uri": CERN_OIDC_ISSUER + "/wrong-certs"},
        {"jwks_uri": CERN_OIDC_ISSUER + "/protocol/openid-connect/certs#fragment"},
        {"response_types_supported": ["token", "id_token"]},
        {"code_challenge_methods_supported": ["plain"]},
        {"id_token_signing_alg_values_supported": ["HS256"]},
        {"id_token_signing_alg_values_supported": ["none"]},
        {"id_token_signing_alg_values_supported": []},
        {"issuer": None},
        {"response_types_supported": None},
    ],
)
def test_untrusted_discovery_rejected(
    monkeypatch: pytest.MonkeyPatch, change: dict[str, object]
) -> None:
    document = discovery()
    document.update(change)
    rejected(monkeypatch, document)


@pytest.mark.parametrize("bad", [False, 123, "", "not-json", [], {}, object()])
def test_unstructured_discovery_rejected(monkeypatch: pytest.MonkeyPatch, bad: object) -> None:
    rejected(monkeypatch, bad)


@pytest.mark.parametrize(
    "mutations",
    [
        {"issuer": "https://evil.invalid"},
        {"authorization_endpoint": "https://evil.invalid/authorize"},
        {"authorization_endpoint": CERN_OIDC_ISSUER + "/other"},
        {"token_endpoint": CERN_OIDC_ISSUER + "/other"},
        {"jwks_uri": CERN_OIDC_ISSUER + "/bad"},
        {"supports_authorization_code": False},
        {"supports_pkce_s256": False},
        {"approved_id_token_algorithms": ()},
        {"approved_id_token_algorithms": ("RS256", "RS256")},
        {"approved_id_token_algorithms": ("HS256",)},
        {"approved_id_token_algorithms": ["RS256"]},
        {"approved_id_token_algorithms": (None,)},
    ],
)
def test_even_forged_discovery_result_is_rechecked(
    monkeypatch: pytest.MonkeyPatch, mutations: dict[str, object]
) -> None:
    def forged(_self: OidcDiscoveryService) -> OidcProviderMetadata:
        return replace(metadata(), **mutations)

    monkeypatch.setattr(OidcDiscoveryService, "discover", forged)
    with pytest.raises(OidcNativeBootstrapError, match="rejected"):
        CernOidcNativeUntrustedBootstrap(registration()).build()


@pytest.mark.parametrize("forged", [None, {}, object(), "jwks", 1])
def test_invalid_discovery_result_container_rejected(
    monkeypatch: pytest.MonkeyPatch, forged: object
) -> None:
    monkeypatch.setattr(OidcDiscoveryService, "discover", lambda _self: forged)
    with pytest.raises(OidcNativeBootstrapError):
        CernOidcNativeUntrustedBootstrap(registration()).build()


def test_untrusted_discovery_exception_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = "synthetic-private-provider-details"

    def broken(_self: HttpsOidcMetadataFetcher, _url: str) -> object:
        raise OidcDiscoveryError(marker)

    monkeypatch.setattr(HttpsOidcMetadataFetcher, "fetch", broken)
    with pytest.raises(OidcNativeBootstrapError) as exc:
        CernOidcNativeUntrustedBootstrap(registration()).build()
    assert marker not in str(exc.value)
    assert exc.value.__cause__ is None


@pytest.mark.parametrize("error", [ValueError, TypeError, OSError, OverflowError])
def test_expected_transport_errors_are_sanitized(
    monkeypatch: pytest.MonkeyPatch, error: type[Exception]
) -> None:
    marker = "private-network-diagnostic"

    def broken(_self: HttpsOidcMetadataFetcher, _url: str) -> object:
        raise error(marker)

    monkeypatch.setattr(HttpsOidcMetadataFetcher, "fetch", broken)
    with pytest.raises(OidcNativeBootstrapError) as exc:
        CernOidcNativeUntrustedBootstrap(registration()).build()
    assert marker not in str(exc.value)


@pytest.mark.parametrize("field", ["_transport", "_verifier", "_fetcher"])
def test_forged_default_adapter_is_rejected(monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    install_fetch(monkeypatch, discovery())
    original_init = CernOidcNativeCodeExchange.__init__

    def tampered(self: CernOidcNativeCodeExchange, *args: object, **kwargs: object) -> None:
        original_init(self, *args, **kwargs)  # type: ignore[arg-type]
        if field == "_fetcher":
            self._verifier._fetcher = object()
        else:
            setattr(self, field, object())

    monkeypatch.setattr(CernOidcNativeCodeExchange, "__init__", tampered)
    with pytest.raises(OidcNativeBootstrapError):
        CernOidcNativeUntrustedBootstrap(registration()).build()


def test_wrapped_native_composition_failure_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    install_fetch(monkeypatch, discovery())
    marker = "synthetic-client-secret"

    def broken(self: CernOidcNativeCodeExchange, *args: object, **kwargs: object) -> None:
        del self, args, kwargs
        raise ValueError(marker)

    monkeypatch.setattr(CernOidcNativeCodeExchange, "__init__", broken)
    with pytest.raises(OidcNativeBootstrapError) as exc:
        CernOidcNativeUntrustedBootstrap(registration()).build()
    assert marker not in str(exc.value)


def test_mismatched_preflight_config_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    install_fetch(monkeypatch, discovery())
    true_builder = bootstrap_module.build_cern_client_configuration

    def bad_builder(*args: object, **kwargs: object) -> object:
        original = true_builder(*args, **kwargs)  # type: ignore[arg-type]
        return replace(original, client_id="forged-client")

    monkeypatch.setattr(bootstrap_module, "build_cern_client_configuration", bad_builder)
    with pytest.raises(OidcNativeBootstrapError):
        CernOidcNativeUntrustedBootstrap(registration()).build()


def test_forged_status_is_not_an_identity_or_provenance() -> None:
    status = NativeOidcIsolationStatus()
    object.__setattr__(status, "login", "available")
    # Python dataclasses are forgeable even when frozen: never use as authority.
    assert status.login == "available"
    assert not hasattr(status, "session")
    assert not hasattr(status, "verified_identity")


def test_no_bootstrap_access_to_web_bff_client_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fetch(monkeypatch, discovery())
    flow = CernOidcNativeUntrustedBootstrap(registration()).build()
    assert flow._registration.mode is OidcClientMode.NATIVE_LOOPBACK
    assert flow._registration.redirect_uri.startswith("http://127.0.0.1:")
    assert not hasattr(flow, "client_secret")
    assert not hasattr(flow, "authenticated_session")


def test_no_unverified_public_metadata_can_create_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fetch(monkeypatch, discovery())
    flow = CernOidcNativeUntrustedBootstrap(registration()).build()
    assert not hasattr(flow, "login")
    assert not hasattr(flow, "identity")
    assert not hasattr(flow, "roles")
    assert not hasattr(flow, "permissions")
    assert not hasattr(flow, "session")


def test_no_web_fallback_when_native_registration_fails() -> None:
    web = OidcClientRegistration(
        client_id=CLIENT,
        redirect_uri="https://asca.example.invalid/callback",
        mode=OidcClientMode.WEB_BFF,
    )
    with pytest.raises(OidcNativeBootstrapError):
        CernOidcNativeUntrustedBootstrap(web)


@pytest.mark.parametrize(
    "field,value",
    [
        ("client_id", "other-valid-client"),
        ("redirect_uri", "http://127.0.0.1:8001/oidc/callback"),
        ("mode", "native_loopback"),
        ("scopes", ("openid", "email")),
    ],
)
def test_mutation_of_private_registration_after_init_blocks_discovery(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    urls = install_fetch(monkeypatch, discovery())
    bootstrap = CernOidcNativeUntrustedBootstrap(registration())
    object.__setattr__(bootstrap._registration, field, value)
    with pytest.raises(OidcNativeBootstrapError):
        bootstrap.build()
    assert urls == []


def test_mutation_during_discovery_blocks_native_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bootstrap = CernOidcNativeUntrustedBootstrap(registration())

    def mutate(_self: HttpsOidcMetadataFetcher, _url: str) -> object:
        object.__setattr__(bootstrap._registration, "client_id", "another-valid-client")
        return discovery()

    monkeypatch.setattr(HttpsOidcMetadataFetcher, "fetch", mutate)
    with pytest.raises(OidcNativeBootstrapError):
        bootstrap.build()


def test_unexpected_internal_registration_shape_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    urls = install_fetch(monkeypatch, discovery())
    bootstrap = CernOidcNativeUntrustedBootstrap(registration())
    bootstrap._registration = object()  # type: ignore[assignment]
    with pytest.raises(OidcNativeBootstrapError):
        bootstrap.build()
    assert urls == []
