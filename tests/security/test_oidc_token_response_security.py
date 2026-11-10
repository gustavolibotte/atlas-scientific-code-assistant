"""Adversarial offline checks; never exchange, decode, or authenticate live tokens."""

import json
import socket

import pytest

from asca.application.oidc_token_response import parse_unverified_oidc_token_response
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_response import OidcTokenResponseError

ID_TOKEN = "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl"
BODY = json.dumps(
    {"access_token": "synthetic-access-token", "id_token": ID_TOKEN, "token_type": "Bearer"}
).encode("ascii")


def response_with_raw(raw: bytes) -> UnverifiedOidcTokenHttpResponse:
    return UnverifiedOidcTokenHttpResponse(body=raw)


def response_with(**fields: object) -> UnverifiedOidcTokenHttpResponse:
    document: dict[str, object] = json.loads(BODY)
    document.update(fields)
    return response_with_raw(json.dumps(document).encode("utf-8"))


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b"{",
        b"[] trailing",
        b"null",
        b'{"access_token":"a",}',
        b'{"access_token": "a"} {"access_token": "b"}',
        b"\xef\xbb\xbf" + BODY,
        b"\xff" + BODY,
        b"\x00" + BODY,
        b'{"number":NaN}',
        b'{"number":Infinity}',
        b'{"number":-Infinity}',
        b'{"access_token":"line\nbreak"}',
        b"[" * 250 + b"0" + b"]" * 250,
    ],
)
def test_malformed_utf8_or_json_rejected(raw: bytes) -> None:
    with pytest.raises(OidcTokenResponseError):
        parse_unverified_oidc_token_response(response_with_raw(raw))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"access_token":"a", "access_token":"b"}',
        BODY[:-1] + b', "access_token":"second"}',
        BODY[:-1] + b', "opaque":{"x":1,"x":2}}',
        BODY[:-1] + b', "opaque":[{"a":1,"a":2}]}',
        BODY[:-1] + b', "refresh_expires_in":3, "refresh_expires_in":4}',
    ],
)
def test_duplicate_json_members_at_any_depth_rejected(raw: bytes) -> None:
    with pytest.raises(OidcTokenResponseError, match="Duplicate"):
        parse_unverified_oidc_token_response(response_with_raw(raw))


@pytest.mark.parametrize(
    "field, value",
    [
        ("access_token", ""),
        ("access_token", "short token"),
        ("access_token", "nonasciié"),
        ("access_token", "a\r\nb"),
        ("access_token", "a\x00b"),
        ("access_token", "a" * 32769),
        ("access_token", None),
        ("access_token", 123),
        ("access_token", ["a"]),
        ("id_token", ""),
        ("id_token", "not-a-jws"),
        ("id_token", "x.y"),
        ("id_token", "x.y.z.w"),
        ("id_token", "x..z"),
        ("id_token", "x.y."),
        ("id_token", "x.y.z="),
        ("id_token", "é.y.z"),
        ("id_token", "a" * 32769),
        ("id_token", None),
        ("id_token", False),
        ("token_type", "basic"),
        ("token_type", "Bearer "),
        ("token_type", None),
        ("token_type", 12),
        ("token_type", True),
        ("expires_in", 0),
        ("expires_in", -1),
        ("expires_in", 604801),
        ("expires_in", "300"),
        ("expires_in", 3.0),
        ("expires_in", False),
        ("expires_in", True),
        ("expires_in", None),
        ("refresh_token", ""),
        ("refresh_token", "bad refresh"),
        ("refresh_token", 42),
        ("refresh_token", None),
        ("scope", ""),
        ("scope", "openid  profile"),
        ("scope", "open\tid"),
        ("scope", "openid openid"),
        ("scope", "openid\\profile"),
        ("scope", 'openid"profile'),
        ("scope", "é"),
        ("scope", "openid\nprofile"),
        ("scope", None),
        ("scope", 12),
        ("scope", "a" * 1025),
    ],
)
def test_malformed_known_fields_rejected(field: str, value: object) -> None:
    with pytest.raises(OidcTokenResponseError):
        parse_unverified_oidc_token_response(response_with(**{field: value}))


@pytest.mark.parametrize(
    "error_fields",
    [
        {"error": "invalid_grant"},
        {"error": "access_denied", "error_description": "secret"},
        {"error_description": "secret"},
        {"error_uri": "https://example.org/secret"},
        {"code": "unexpected-code"},
        {"state": "unexpected-state"},
    ],
)
def test_error_or_auth_code_fields_are_not_accepted_as_success(
    error_fields: dict[str, str],
) -> None:
    with pytest.raises(OidcTokenResponseError):
        parse_unverified_oidc_token_response(response_with(**error_fields))


def test_invalid_response_input_types_fail_closed() -> None:
    for value in (None, 42, BODY, object()):
        with pytest.raises(OidcTokenResponseError):
            parse_unverified_oidc_token_response(value)  # type: ignore[arg-type]


def test_forged_empty_or_oversized_response_rejected() -> None:
    for raw in (b"", b"x" * 65537):
        forged = object.__new__(UnverifiedOidcTokenHttpResponse)
        object.__setattr__(forged, "body", raw)
        object.__setattr__(forged, "status_code", 200)
        with pytest.raises(OidcTokenResponseError):
            parse_unverified_oidc_token_response(forged)
    forged_status = object.__new__(UnverifiedOidcTokenHttpResponse)
    object.__setattr__(forged_status, "body", BODY)
    object.__setattr__(forged_status, "status_code", 201)
    with pytest.raises(OidcTokenResponseError):
        parse_unverified_oidc_token_response(forged_status)


def test_sensitive_tokens_are_not_disclosed_by_errors_or_repr() -> None:
    secret = "CERN-test-private-credential"
    response = response_with(access_token=secret + " invalid space")
    with pytest.raises(OidcTokenResponseError) as captured:
        parse_unverified_oidc_token_response(response)
    assert secret not in str(captured.value)
    assert secret not in repr(captured.value)

    parsed = parse_unverified_oidc_token_response(response_with(access_token=secret))
    assert secret not in repr(parsed)
    assert ID_TOKEN not in repr(parsed)


def test_parser_never_calls_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("OIDC parser attempted network access")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    result = parse_unverified_oidc_token_response(response_with_raw(BODY))
    assert result.id_token == ID_TOKEN


def test_untrusted_extensions_never_become_identity_or_permissions() -> None:
    result = parse_unverified_oidc_token_response(
        response_with(
            role="administrator",
            verified=True,
            is_admin=True,
            authorization={"groups": ["cern-admin"]},
        )
    )
    assert not hasattr(result, "role")
    assert not hasattr(result, "authorization")
    assert not hasattr(result, "verified")
    assert not hasattr(result, "is_admin")
    assert not hasattr(result, "permissions")
