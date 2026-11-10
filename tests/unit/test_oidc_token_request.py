"""Deterministic native-public OAuth token-request construction tests."""

from dataclasses import FrozenInstanceError, replace
from urllib.parse import parse_qs

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_token_request import prepare_cern_native_token_request
from asca.domain.identity import AuthorizationCodeGrant, VerifiedIdentity
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_request import OidcTokenRequestError, UnsentOidcTokenRequest

REDIRECT = "http://127.0.0.1:8765/api/v1/identity/callback"
NONCE = "N" * 43
VERIFIER = "v" * 64


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id="example-not-registered",
        redirect_uri=REDIRECT,
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )


def metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("ES256", "RS256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def grant(code: str = "test-code") -> AuthorizationCodeGrant:
    return AuthorizationCodeGrant(
        code=code, nonce=NONCE, code_verifier=VERIFIER, redirect_uri=REDIRECT
    )


def test_request_is_unsent_public_client_post() -> None:
    result = prepare_cern_native_token_request(grant(), registration(), metadata())
    assert isinstance(result, UnsentOidcTokenRequest)
    assert not isinstance(result, VerifiedIdentity)
    assert result.method == "POST"
    assert result.token_endpoint == metadata().token_endpoint
    assert result.headers == (
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Accept", "application/json"),
        ("Cache-Control", "no-store"),
    )
    params = parse_qs(result.form_body.decode("ascii"), strict_parsing=True)
    assert params == {
        "grant_type": ["authorization_code"],
        "code": ["test-code"],
        "redirect_uri": [REDIRECT],
        "client_id": ["example-not-registered"],
        "code_verifier": [VERIFIER],
    }
    assert result.expected_nonce == NONCE
    assert "state" not in params
    assert "nonce" not in params
    assert "client_secret" not in params
    assert "code_challenge" not in params
    assert not hasattr(result, "id_token")
    assert not hasattr(result, "access_token")


def test_sensitive_fields_are_not_in_repr() -> None:
    issued = grant("code-secret-for-test")
    result = prepare_cern_native_token_request(issued, registration(), metadata())
    for secret in (issued.code, issued.nonce, issued.code_verifier, "example-not-registered"):
        assert secret not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.form_body = b"changed"  # type: ignore[misc]


@pytest.mark.parametrize("code", ["abc+def/ghi=", "visible: ~!@#$^&*()", "A" * 2048])
def test_visible_ascii_authorization_codes_are_encoded(code: str) -> None:
    prepared = prepare_cern_native_token_request(grant(code), registration(), metadata())
    assert parse_qs(prepared.form_body.decode("ascii"))["code"] == [code]


@pytest.mark.parametrize(
    "code",
    ["", " ", "\t", "abc\n", "abc\r", "x\x00y", "é", "A" * 2049],
)
def test_invalid_codes_fail_closed_without_echo(code: str) -> None:
    with pytest.raises(OidcTokenRequestError) as captured:
        prepare_cern_native_token_request(grant(code), registration(), metadata())
    assert str(captured.value) == "Invalid OIDC authorization code"


def test_ipv6_native_loopback_is_allowed_when_registered_exactly() -> None:
    redirect = "http://[::1]:8765/callback"
    native = OidcClientRegistration(
        client_id="native-client",
        redirect_uri=redirect,
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )
    issued = replace(grant(), redirect_uri=redirect)
    result = prepare_cern_native_token_request(issued, native, metadata())
    assert parse_qs(result.form_body.decode("ascii"))["redirect_uri"] == [redirect]


def test_a_grant_does_not_create_an_authenticated_identity() -> None:
    result = prepare_cern_native_token_request(grant(), registration(), metadata())
    assert not hasattr(result, "authenticated_identity")
    assert not hasattr(result, "session_id")
