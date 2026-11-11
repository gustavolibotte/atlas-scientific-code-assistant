"""Offline RFC 8252 native-loopback request parsing contract tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from urllib.parse import quote

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_native_callback import (
    NativeLoopbackHttpRequest,
    OidcNativeCallbackError,
    ParsedUntrustedNativeCallback,
)
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.infrastructure.oidc_native_callback import CernNativeLoopbackCallbackPolicy

STATE = "S" * 43
CODE = "test-native-code"


def registration(host: str = "127.0.0.1", port: int = 49321) -> OidcClientRegistration:
    authority = f"[{host}]" if ":" in host else host
    return OidcClientRegistration(
        client_id="offline-native-client",
        redirect_uri=f"http://{authority}:{port}/oidc/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )


def envelope(
    host: str = "127.0.0.1", port: int = 49321, **changes: object
) -> NativeLoopbackHttpRequest:
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    data: dict[str, object] = {
        "method": "GET",
        "request_target": f"/oidc/callback?state={STATE}&code={CODE}",
        "http_version": "HTTP/1.1",
        "headers": (("Host", authority), ("Accept", "text/html")),
        "peer_ip": host,
        "local_ip": host,
        "local_port": port,
        "body": b"",
    }
    data.update(changes)
    return NativeLoopbackHttpRequest(**data)  # type: ignore[arg-type]


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_accepts_exact_literal_loopback_host_and_port(host: str) -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration(host))
    parsed = policy.parse(envelope(host))
    assert isinstance(parsed, ParsedUntrustedNativeCallback)
    assert parsed.state == STATE
    assert parsed.code == CODE
    assert parsed.error is None
    assert parsed.response_issuer is None
    assert not isinstance(parsed, VerifiedIdentity)
    for secret in (STATE, CODE):
        assert secret not in repr(parsed)
    assert not hasattr(parsed, "browser_binding")
    assert not hasattr(parsed, "session")
    assert not hasattr(parsed, "verified_identity")
    with pytest.raises(FrozenInstanceError):
        parsed.code = "forged"  # type: ignore[misc]


def test_optional_issuer_must_match_exact_cern_issuer() -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration())
    target = f"/oidc/callback?code={CODE}&iss={quote(CERN_OIDC_ISSUER, safe='')}&state={STATE}"
    parsed = policy.parse(envelope(request_target=target))
    assert parsed.response_issuer == CERN_OIDC_ISSUER
    assert parsed.code == CODE


def test_oauth_error_is_parsed_but_not_accepted_as_code() -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration())
    result = policy.parse(
        envelope(request_target=f"/oidc/callback?state={STATE}&error=access_denied")
    )
    assert result.state == STATE
    assert result.error == "access_denied"
    assert result.code is None
    assert not hasattr(result, "authenticated")


def test_result_is_not_assumed_to_consume_pending_attempt() -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration())
    first = policy.parse(envelope())
    second = policy.parse(envelope())
    assert first == second
    assert first is not second
    assert not hasattr(policy, "consume")
    assert not hasattr(policy, "open_listener")
    assert not hasattr(policy, "exchange_callback")


@pytest.mark.parametrize("code", ["a", "a.b-c_d=", "special%20escaped", "A" * 2048])
def test_visible_ascii_codes_are_preserved_without_a_second_decode(code: str) -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration())
    encoded = quote(code, safe="")
    parsed = policy.parse(envelope(request_target=f"/oidc/callback?state={STATE}&code={encoded}"))
    assert parsed.code == code


@pytest.mark.parametrize("port", [49152, 49321, 65535])
def test_explicit_registered_port_is_required(port: int) -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration(port=port))
    assert policy.parse(envelope(port=port)).code == CODE
    with pytest.raises(OidcNativeCallbackError):
        policy.parse(envelope(port=port + 1))


def test_callback_request_headers_are_case_insensitive_only_for_names() -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration())
    assert policy.parse(envelope(headers=(("hOsT", "127.0.0.1:49321"),))).state == STATE
    with pytest.raises(OidcNativeCallbackError):
        policy.parse(envelope(headers=(("Host", "LOCALHOST:49321"),)))


@pytest.mark.parametrize(
    "headers",
    [
        (("Host", "127.0.0.1:49321"), ("User-Agent", "ASCA-Test")),
        (("HOST", "127.0.0.1:49321"), ("Sec-Fetch-Site", "cross-site")),
        (("Host", "127.0.0.1:49321"), ("Accept-Language", "en-US,en;q=0.9")),
    ],
)
def test_non_authoritative_browser_headers_are_allowed(
    headers: tuple[tuple[str, str], ...],
) -> None:
    assert (
        CernNativeLoopbackCallbackPolicy(registration()).parse(envelope(headers=headers)).code
        == CODE
    )


def test_accepts_url_encoding_of_issuer_and_encoded_code() -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration())
    parsed = policy.parse(
        envelope(
            request_target=(
                f"/oidc/callback?state={STATE}"
                f"&iss={quote(CERN_OIDC_ISSUER, safe='')}"
                "&code=A%2BB%2FC%3DD"
            )
        )
    )
    assert parsed.code == "A+B/C=D"
    assert parsed.response_issuer == CERN_OIDC_ISSUER


def test_native_status_type_is_immutable_but_forgeable() -> None:
    request = envelope()
    with pytest.raises(FrozenInstanceError):
        request.local_ip = "8.8.8.8"  # type: ignore[misc]
    forged = replace(request, peer_ip="8.8.8.8")
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(registration()).parse(forged)
