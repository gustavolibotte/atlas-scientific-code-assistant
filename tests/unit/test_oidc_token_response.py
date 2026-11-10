"""Offline tests of strict but non-authenticating OIDC token-response parsing."""

import json
from dataclasses import FrozenInstanceError

import pytest

from asca.application.oidc_token_response import parse_unverified_oidc_token_response
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_response import (
    OidcTokenResponseError,
    ParsedUnverifiedOidcTokenResponse,
)

ID_TOKEN = "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl"
ACCESS_TOKEN = "opaque-token._~+/-=="
REFRESH_TOKEN = "refresh-token_123=="


def token_response(**changes: object) -> UnverifiedOidcTokenHttpResponse:
    document: dict[str, object] = {
        "access_token": ACCESS_TOKEN,
        "id_token": ID_TOKEN,
        "token_type": "Bearer",
        "expires_in": 300,
    }
    document.update(changes)
    return UnverifiedOidcTokenHttpResponse(body=json.dumps(document).encode("utf-8"))


def test_valid_response_is_parsed_but_not_authenticated() -> None:
    result = parse_unverified_oidc_token_response(token_response())
    assert isinstance(result, ParsedUnverifiedOidcTokenResponse)
    assert not isinstance(result, VerifiedIdentity)
    assert result.access_token == ACCESS_TOKEN
    assert result.id_token == ID_TOKEN
    assert result.token_type == "Bearer"
    assert result.expires_in == 300
    assert result.refresh_token is None
    assert result.scope is None
    assert not hasattr(result, "verified_identity")
    assert not hasattr(result, "session_id")
    assert not hasattr(result, "authenticated_identity")


def test_optional_fields_are_parsed_and_hidden() -> None:
    parsed = parse_unverified_oidc_token_response(
        token_response(refresh_token=REFRESH_TOKEN, scope="openid profile email")
    )
    assert parsed.refresh_token == REFRESH_TOKEN
    assert parsed.scope == ("openid", "profile", "email")
    for value in (ACCESS_TOKEN, ID_TOKEN, REFRESH_TOKEN, "openid", "Bearer", "300"):
        assert value not in repr(parsed)
    with pytest.raises(FrozenInstanceError):
        parsed.id_token = ID_TOKEN  # type: ignore[misc]


def test_expiry_is_optional_under_oauth2() -> None:
    source = json.loads(token_response().body)
    del source["expires_in"]
    result = parse_unverified_oidc_token_response(
        UnverifiedOidcTokenHttpResponse(body=json.dumps(source).encode("ascii"))
    )
    assert result.expires_in is None


@pytest.mark.parametrize("case", ["bearer", "BEARER", "BeArEr", "Bearer"])
def test_bearer_token_type_is_case_insensitive(case: str) -> None:
    assert parse_unverified_oidc_token_response(token_response(token_type=case)).token_type == (
        "Bearer"
    )


@pytest.mark.parametrize("expiry", [1, 3600, 604800])
def test_bounded_expiry_is_accepted(expiry: int) -> None:
    assert parse_unverified_oidc_token_response(token_response(expires_in=expiry)).expires_in == (
        expiry
    )


def test_unknown_provider_extensions_are_ignored_not_trusted() -> None:
    parsed = parse_unverified_oidc_token_response(
        token_response(
            session_state="test-provider-session",
            refresh_expires_in=1800,
            **{"not-before-policy": 0, "nested_extension": {"anything": [True, 1]}},
        )
    )
    assert parsed.access_token == ACCESS_TOKEN
    assert not hasattr(parsed, "session_state")
    assert not hasattr(parsed, "nested_extension")
    assert not hasattr(parsed, "refresh_expires_in")


def test_valid_utf8_unknown_extension_is_ignored() -> None:
    parsed = parse_unverified_oidc_token_response(token_response(provider_hint="électricité"))
    assert parsed.id_token == ID_TOKEN


@pytest.mark.parametrize("body", [b"{}", b"[]", b'"hello"', b"null", b"12", b"true"])
def test_non_success_or_non_object_payload_rejected(body: bytes) -> None:
    with pytest.raises(OidcTokenResponseError):
        parse_unverified_oidc_token_response(UnverifiedOidcTokenHttpResponse(body=body))


def test_response_with_only_an_access_token_is_not_oidc() -> None:
    with pytest.raises(OidcTokenResponseError, match="ID-token"):
        parse_unverified_oidc_token_response(
            UnverifiedOidcTokenHttpResponse(body=b'{"access_token":"abc", "token_type":"Bearer"}')
        )
