"""CERN Keycloak loopback callback extension: offline contract regression tests.

The session_state parameter is metadata only and must never grant authority.
"""

from __future__ import annotations

from urllib.parse import quote

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_native_callback import NativeLoopbackHttpRequest
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.infrastructure.oidc_native_callback import CernNativeLoopbackCallbackPolicy

STATE = "S" * 43
SESSION = "a7e6a4b2-9721-4dd0-89d2-42e875a0bc62"
CODE = "synthetic-code"


def _policy() -> CernNativeLoopbackCallbackPolicy:
    registration = OidcClientRegistration(
        client_id="synthetic-client",
        redirect_uri="http://127.0.0.1:59044/oidc/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )
    return CernNativeLoopbackCallbackPolicy(registration)


def _request(query: str) -> NativeLoopbackHttpRequest:
    return NativeLoopbackHttpRequest(
        method="GET",
        request_target=f"/oidc/callback?{query}",
        http_version="HTTP/1.1",
        headers=(("Host", "127.0.0.1:59044"), ("Accept", "text/html")),
        peer_ip="127.0.0.1",
        local_ip="127.0.0.1",
        local_port=59044,
    )


def _issuer() -> str:
    return quote(CERN_OIDC_ISSUER, safe="")


def test_cern_observed_four_parameter_shape_succeeds_without_exposing_session_state() -> None:
    parsed = _policy().parse(
        _request(f"state={STATE}&session_state={SESSION}&iss={_issuer()}&code={CODE}")
    )
    assert parsed.state == STATE
    assert parsed.code == CODE
    assert parsed.response_issuer == CERN_OIDC_ISSUER
    assert parsed.error is None
    assert not hasattr(parsed, "session_state")
    assert SESSION not in repr(parsed)


@pytest.mark.parametrize(
    "query",
    [
        f"state={STATE}&code={CODE}&session_state={SESSION}&iss={_issuer()}",
        f"code={CODE}&iss={_issuer()}&state={STATE}&session_state={SESSION}",
        f"session_state={SESSION}&code={CODE}&state={STATE}&iss={_issuer()}",
        f"iss={_issuer()}&state={STATE}&session_state={SESSION}&code={CODE}",
    ],
)
def test_order_of_known_callback_fields_does_not_change_validation(query: str) -> None:
    result = _policy().parse(_request(query))
    assert result.code == CODE
    assert result.state == STATE


@pytest.mark.parametrize(
    "query",
    [
        f"state={STATE}&code={CODE}",
        f"state={STATE}&code={CODE}&iss={_issuer()}",
        f"state={STATE}&code={CODE}&session_state={SESSION}",
        f"state={STATE}&error=access_denied&session_state={SESSION}&iss={_issuer()}",
    ],
)
def test_optional_fields_preserve_legacy_and_denial_semantics(query: str) -> None:
    result = _policy().parse(_request(query))
    assert result.state == STATE
    assert (result.code is None) != (result.error is None)
    assert not hasattr(result, "session_state")


def test_session_state_is_never_used_as_a_binding_or_identity() -> None:
    first = _policy().parse(_request(f"state={STATE}&code={CODE}&session_state=first"))
    second = _policy().parse(_request(f"state={STATE}&code={CODE}&session_state=second"))
    assert first == second
    assert not hasattr(first, "authenticated")
    assert not hasattr(first, "verified_identity")
    assert not hasattr(first, "browser_binding")
