"""Adversarial, no-network checks of native public token request preparation."""

from dataclasses import replace

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER, OidcDiscoveryPolicy
from asca.application.oidc_token_request import prepare_cern_native_token_request
from asca.domain.identity import AuthorizationCodeGrant
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_request import OidcTokenRequestError

REDIRECT = "http://127.0.0.1:8765/callback"
VERIFIER = "V" * 64
NONCE = "n" * 43


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id="example-not-registered",
        redirect_uri=REDIRECT,
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )


def provider() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("ES256",),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def grant() -> AuthorizationCodeGrant:
    return AuthorizationCodeGrant(
        code="sensitive-code-for-test",
        nonce=NONCE,
        code_verifier=VERIFIER,
        redirect_uri=REDIRECT,
    )


def test_web_bff_cannot_bypass_unsupported_confidential_client_auth() -> None:
    web = OidcClientRegistration(
        client_id="example-not-registered",
        redirect_uri="https://asca.example.org/callback",
        mode=OidcClientMode.WEB_BFF,
    )
    with pytest.raises(OidcTokenRequestError, match="native registration"):
        prepare_cern_native_token_request(grant(), web, provider())


@pytest.mark.parametrize(
    "changed_redirect",
    [
        "http://127.0.0.1:8765/other",
        "http://127.0.0.1:9876/callback",
        "https://127.0.0.1:8765/callback",
        "http://127.0.0.1:8765/callback?",
        "https://evil.example.org/callback",
    ],
)
def test_grant_redirect_must_match_declaration_exactly(changed_redirect: str) -> None:
    with pytest.raises(OidcTokenRequestError, match="redirect URI"):
        prepare_cern_native_token_request(
            replace(grant(), redirect_uri=changed_redirect), registration(), provider()
        )


@pytest.mark.parametrize(
    "verifier",
    ["", "v" * 42, "V" * 129, "bad space" + "V" * 35, "v/" + "V" * 42, "é" * 43, None],
)
def test_reject_untrusted_pkce_verifier(verifier: object) -> None:
    with pytest.raises(OidcTokenRequestError, match="PKCE"):
        prepare_cern_native_token_request(
            replace(grant(), code_verifier=verifier),  # type: ignore[arg-type]
            registration(),
            provider(),
        )


@pytest.mark.parametrize(
    "nonce", ["", "a" * 42, "a" * 129, "x/" + "z" * 42, "a\nb" + "z" * 40, None]
)
def test_invalid_nonce_rejected(nonce: object) -> None:
    with pytest.raises(OidcTokenRequestError, match="nonce"):
        prepare_cern_native_token_request(
            replace(grant(), nonce=nonce),  # type: ignore[arg-type]
            registration(),
            provider(),
        )


@pytest.mark.parametrize(
    "changed_metadata",
    [
        replace(provider(), issuer="https://evil.example.org"),
        replace(provider(), token_endpoint="https://evil.example.org/token"),
        replace(provider(), token_endpoint="http://auth.cern.ch/auth/realms/cern/token"),
        replace(provider(), token_endpoint=CERN_OIDC_ISSUER + "/token?"),
        replace(provider(), token_endpoint=CERN_OIDC_ISSUER + "/token#"),
        replace(provider(), token_endpoint="https://user:pass@auth.cern.ch/token"),
        replace(provider(), token_endpoint="https://auth.cern.ch:0/token"),
        replace(provider(), supports_pkce_s256=False),
        replace(provider(), supports_authorization_code=False),
        replace(provider(), approved_id_token_algorithms=("HS256",)),
        replace(provider(), approved_id_token_algorithms=()),
    ],
)
def test_untrusted_provider_metadata_cannot_select_token_destination(
    changed_metadata: OidcProviderMetadata,
) -> None:
    with pytest.raises(OidcTokenRequestError, match="Untrusted"):
        prepare_cern_native_token_request(grant(), registration(), changed_metadata)


def test_alternate_issuer_policy_rejected() -> None:
    with pytest.raises(OidcTokenRequestError, match="Untrusted"):
        prepare_cern_native_token_request(
            grant(),
            registration(),
            provider(),
            policy=OidcDiscoveryPolicy(
                expected_issuer="https://evil.example.org/realm",
                discovery_url="https://evil.example.org/realm/.well-known/openid-configuration",
            ),
        )


def test_no_network_calls_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """The builder must not use sockets, DNS, HTTP libraries or browsers."""
    import socket

    def blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("Network access was attempted")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    result = prepare_cern_native_token_request(grant(), registration(), provider())
    assert result.form_body
    assert result.method == "POST"


def test_wrong_input_types_fail_closed() -> None:
    for args in (
        (None, registration(), provider()),
        (grant(), None, provider()),
        (grant(), registration(), None),
    ):
        with pytest.raises(OidcTokenRequestError):
            prepare_cern_native_token_request(*args)  # type: ignore[arg-type]


def test_no_sensitive_values_in_errors_or_repr() -> None:
    bad = replace(grant(), code="CERN-secret-do-not-log\n")
    with pytest.raises(OidcTokenRequestError) as captured:
        prepare_cern_native_token_request(bad, registration(), provider())
    assert "CERN-secret-do-not-log" not in str(captured.value)
    assert "CERN-secret-do-not-log" not in repr(captured.value)
