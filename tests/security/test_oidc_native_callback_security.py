"""Adversarial, offline native loopback HTTP callback policy regression tests."""

from __future__ import annotations

from dataclasses import replace
from urllib.parse import quote

import pytest

from asca.domain.oidc_native_callback import NativeLoopbackHttpRequest, OidcNativeCallbackError
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.infrastructure.oidc_native_callback import CernNativeLoopbackCallbackPolicy

STATE = "_" * 43


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id="test-native-client",
        redirect_uri="http://127.0.0.1:51807/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )


def envelope(**changes: object) -> NativeLoopbackHttpRequest:
    values: dict[str, object] = {
        "method": "GET",
        "request_target": f"/callback?state={STATE}&code=mock-code",
        "http_version": "HTTP/1.1",
        "headers": (("Host", "127.0.0.1:51807"),),
        "peer_ip": "127.0.0.1",
        "local_ip": "127.0.0.1",
        "local_port": 51807,
        "body": b"",
    }
    values.update(changes)
    return NativeLoopbackHttpRequest(**values)  # type: ignore[arg-type]


def reject(**changes: object) -> None:
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(registration()).parse(envelope(**changes))


@pytest.mark.parametrize(
    "method",
    [
        "POST",
        "HEAD",
        "PUT",
        "OPTIONS",
        "DELETE",
        "TRACE",
        "CONNECT",
        "get",
        "GET ",
        "",
        None,
        True,
        0,
    ],
)
def test_wrong_http_method_rejected(method: object) -> None:
    reject(method=method)


@pytest.mark.parametrize(
    "version", ["HTTP/1.0", "HTTP/2", "HTTP/2.0", "HTTP/3", "http/1.1", "", None, 1]
)
def test_only_explicit_http_11_is_supported(version: object) -> None:
    reject(http_version=version)


@pytest.mark.parametrize(
    "target",
    [
        "/callback",
        "/callback/",
        "/callback2?state=abc&code=x",
        "/other?state=abc&code=x",
        f"//127.0.0.1:51807/callback?state={STATE}&code=mock-code",
        f"http://127.0.0.1:51807/callback?state={STATE}&code=mock-code",
        f"/callback%2f?state={STATE}&code=mock-code",
        f"/CALLBACK?state={STATE}&code=mock-code",
        f"/callback/?state={STATE}&code=mock-code",
        f"/callback#fragment?state={STATE}&code=mock-code",
        f"/callback?state={STATE}&code=mock-code#fragment",
        f"/callback?state={STATE}&code=mock-code?admin=yes",
        f"/callback?state={STATE}&code=mock-code;admin=yes",
        f"/callback?state={STATE}&code=mock-code\\suffix",
        "/callback?",
        "",
        "x" * 8193,
        None,
        {},
        b"/callback?state=x",
    ],
)
def test_noncanonical_request_targets_rejected(target: object) -> None:
    reject(request_target=target)


@pytest.mark.parametrize(
    "query",
    [
        f"state={STATE}",
        "code=mock-code",
        "",
        "state=",
        "state=short&code=c",
        f"state={STATE}&code=",
        f"state={STATE}&error=",
        f"state={STATE}&error=bad+name",
        f"state={STATE}&code=abc+xyz",
        f"state={STATE}&code=abc%20xyz",
        f"state={STATE}&code=a%0Axyz",
        f"state={STATE}&code=%FF",
        f"state={STATE}&code=%ZZ",
        f"state={STATE}&code=%",
        f"state={STATE}&code=%2",
        f"state={STATE}&code=abc%2g",
        f"state={STATE}&code=abc&code=def",
        f"state={STATE}&state={STATE}&code=x",
        f"state={STATE}&code=x&error=denied",
        f"state={STATE}&code=x&unexpected=1",
        f"state={STATE}&code=x&error=denied&iss=extra",
        f"state={STATE}&code=x&iss=https%3A%2F%2Fevil.invalid",
        f"state={STATE}&code=x&iss=",
        f"state={STATE}&code=x&iss=garbage",
        f"state={STATE}&code=x&iss=%FF",
        f"state={STATE}&code=x&x=%25",
        f"state={STATE}&code=x&code=again",
        f"state={STATE}&code=x&error_description=ignored",
        f"state={STATE}&error=invalid%20request",
        f"state={STATE}&error={'x' * 129}",
        f"state={STATE}&code={'x' * 2049}",
        f"state={STATE}&code=x&iss=x&x=3",
        f"state={STATE}&code=x\nX:y",
        f"state={STATE}&code=x\rX:y",
        f"state={STATE}&code=x\x00",
        f"state={STATE}&code=xé",
    ],
)
def test_malformed_encoded_or_ambiguous_queries_rejected(query: str) -> None:
    reject(request_target="/callback?" + query)


@pytest.mark.parametrize(
    "headers",
    [
        (),
        (("Accept", "text/html"),),
        (("Host", "127.0.0.1:51807"), ("Host", "127.0.0.1:51807")),
        (("host", "127.0.0.1:51807"), ("Host", "127.0.0.1:51807")),
        (("Host", "localhost:51807"),),
        (("Host", "127.0.0.1:80"),),
        (("Host", "127.0.0.1"),),
        (("Host", "127.0.0.1:51807 "),),
        (("Host", "127.0.0.1:51807\r\nX:evil"),),
        (("Host", "127.0.0.1:51807\x7f"),),
        (("Host", "127.0.0.1:51807"), ("Origin", "https://evil.invalid")),
        (("Host", "127.0.0.1:51807"), ("Forwarded", "for=1.2.3.4")),
        (("Host", "127.0.0.1:51807"), ("X-Forwarded-Host", "localhost")),
        (("Host", "127.0.0.1:51807"), ("X-Original-URL", "/callback")),
        (("Host", "127.0.0.1:51807"), ("Authorization", "Bearer evil")),
        (("Host", "127.0.0.1:51807"), ("Proxy-Authorization", "x")),
        (("Host", "127.0.0.1:51807"), ("Transfer-Encoding", "chunked")),
        (("Host", "127.0.0.1:51807"), ("Content-Length", "0")),
        (("Host", "127.0.0.1:51807"), ("Cookie", "session=evil")),
        (("Host", "127.0.0.1:51807"), ("Expect", "100-continue")),
        (("Host", "127.0.0.1:51807"), ("Upgrade", "websocket")),
        (("Host", "127.0.0.1:51807"), ("X-Malformed Header", "x")),
        (("Host", "127.0.0.1:51807"), ("X-Null", "hello\x00world")),
        (("Host", "127.0.0.1:51807"), ("X-Long", "a" * 2049)),
        (("Host", "127.0.0.1:51807"),),
    ],
)
def test_noncanonical_or_forbidden_http_headers_rejected_or_accepted(headers: object) -> None:
    # Last case is the canonical header; the rest must reject.
    if headers == (("Host", "127.0.0.1:51807"),):
        assert (
            CernNativeLoopbackCallbackPolicy(registration()).parse(envelope(headers=headers)).code
            == "mock-code"
        )
    else:
        reject(headers=headers)


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {},
        [],
        "Host:evil",
        ("Host", "127.0.0.1:51807"),
        (("Host", "127.0.0.1:51807"),) * 33,
        (("Host", "127.0.0.1:51807"), None),
        (("Host", "127.0.0.1:51807"), ("bad",)),
        (("Host", "127.0.0.1:51807"), (None, "x")),
        (("Host", "127.0.0.1:51807"), ("X", object())),
        (("Host", "127.0.0.1:51807"), ["X", "value"]),
        (("Host", "127.0.0.1:51807"), ("X", "value", "extra")),
    ],
)
def test_invalid_headers_container_or_entry_rejected(headers: object) -> None:
    reject(headers=headers)


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "127.0.0.2",
        "0.0.0.0",
        "::1",
        "::ffff:127.0.0.1",
        "::",
        "localhost",
        "127.000.000.001",
        "127.0.0.1%lo0",
        "[::1]",
        " 127.0.0.1",
        "127.0.0.1\x00",
        "",
        None,
        42,
        True,
    ],
)
def test_nonexact_socket_peer_is_rejected(address: object) -> None:
    reject(peer_ip=address)


@pytest.mark.parametrize("address", ["8.8.8.8", "::1", "127.0.0.2", "localhost", None, 1])
def test_nonexact_socket_local_bind_is_rejected(address: object) -> None:
    reject(local_ip=address)


@pytest.mark.parametrize("port", [0, 1, 51808, 65535, -1, None, True, "51807", 51807.0])
def test_wrong_listening_port_fails(port: object) -> None:
    reject(local_port=port)


@pytest.mark.parametrize("body", [b"x", b'{"token":"secret"}', None, {}, "", b"\x00"])
def test_request_must_have_exactly_no_body(body: object) -> None:
    reject(body=body)


@pytest.mark.parametrize("mode", [OidcClientMode.WEB_BFF, "native_loopback", None, 0])
def test_cross_mode_or_forged_registration_rejected(mode: object) -> None:
    item = registration()
    object.__setattr__(item, "mode", mode)
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(item)


def test_registration_cannot_use_other_loopback_literals() -> None:
    item = registration()
    object.__setattr__(item, "redirect_uri", "http://127.0.0.2:51807/callback")
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(item)


@pytest.mark.parametrize("value", [None, False, 1, object(), "redirect", {}, []])
def test_wrong_registration_type_is_rejected(value: object) -> None:
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(value)  # type: ignore[arg-type]


def test_rejects_registration_subclass() -> None:
    class Derived(OidcClientRegistration):
        pass

    child = Derived(
        client_id="test-native-client",
        redirect_uri="http://127.0.0.1:51807/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(child)


def test_rejects_forged_invalid_port_registration() -> None:
    value = registration()
    object.__setattr__(value, "redirect_uri", "http://127.0.0.1:garbage/callback")
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(value)


@pytest.mark.parametrize(
    "change",
    [
        {"client_id": "evil client"},
        {"redirect_uri": "https://evil.invalid/callback"},
        {"scopes": ["openid"]},
    ],
)
def test_registration_post_construction_forgery_is_rejected(change: dict[str, object]) -> None:
    item = registration()
    for name, value in change.items():
        object.__setattr__(item, name, value)
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(item)


@pytest.mark.parametrize("value", [None, 42, object(), "HTTP", {}, False])
def test_non_request_objects_rejected(value: object) -> None:
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(registration()).parse(value)  # type: ignore[arg-type]


def test_rejects_request_subclass() -> None:
    class Derived(NativeLoopbackHttpRequest):
        pass

    source = envelope()
    value = Derived(
        **{
            "method": source.method,
            "request_target": source.request_target,
            "http_version": source.http_version,
            "headers": source.headers,
            "peer_ip": source.peer_ip,
            "local_ip": source.local_ip,
            "local_port": source.local_port,
            "body": source.body,
        }
    )
    with pytest.raises(OidcNativeCallbackError):
        CernNativeLoopbackCallbackPolicy(registration()).parse(value)


def test_valid_host_header_is_not_proof_of_genuine_browser_origin() -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration())
    synthetic = envelope()
    assert policy.parse(synthetic).code == "mock-code"
    tampered = replace(synthetic, peer_ip="8.8.8.8")
    with pytest.raises(OidcNativeCallbackError):
        policy.parse(tampered)
    assert not hasattr(policy, "authenticated_identity")
    assert not hasattr(policy, "open_listener")


def test_request_target_does_not_accept_code_in_fragments() -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration())
    fragment = f"/callback?state={STATE}#code=mock-code"
    with pytest.raises(OidcNativeCallbackError):
        policy.parse(envelope(request_target=fragment))


def test_query_is_not_double_decoded_or_reflected_in_errors() -> None:
    policy = CernNativeLoopbackCallbackPolicy(registration())
    sensitive = "very-secret-authorization-code"
    bad = f"/callback?state={STATE}&code={quote(sensitive)}&code=another"
    with pytest.raises(OidcNativeCallbackError) as error:
        policy.parse(envelope(request_target=bad))
    assert sensitive not in str(error.value)
    assert STATE not in str(error.value)
    assert "very-secret" not in repr(error.value)


def test_parsed_native_callback_requires_original_local_binding_and_single_use_state() -> None:
    """Policy output is syntax only; the existing atomic store remains authoritative."""
    from urllib.parse import parse_qs, urlsplit

    from asca.domain.oidc_discovery import OidcProviderMetadata
    from asca.domain.oidc_native_exchange import OidcNativeExchangeError
    from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
    from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
    from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
    from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
    from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

    now = 1_800_000_000

    class OfflineTokenTransport(HttpsOidcTokenTransport):
        def __init__(self) -> None:
            self.count = 0

        def exchange(self, prepared: object, declared: object) -> UnverifiedOidcTokenHttpResponse:
            del prepared, declared
            self.count += 1
            return UnverifiedOidcTokenHttpResponse(
                body=b'{"access_token":"synthetic","id_token":"a.b.c","token_type":"Bearer"}'
            )

    class OfflineVerifier(CernOidcVerificationPipeline):
        def __init__(self) -> None:
            self.count = 0

        def check(
            self,
            tokens: object,
            metadata: object,
            *,
            expected_client_id: str,
            expected_nonce: str,
            now: int,
            clock_skew_seconds: int = 60,
            max_token_lifetime_seconds: int = 3600,
            trusted_additional_audiences: tuple[str, ...] = (),
        ) -> CheckedUntrustedCernOidcToken:
            del tokens, metadata, expected_nonce, clock_skew_seconds
            del max_token_lifetime_seconds, trusted_additional_audiences
            self.count += 1
            return CheckedUntrustedCernOidcToken(
                issuer=CERN_OIDC_ISSUER,
                subject="synthetic-untrusted-subject",
                audiences=(expected_client_id,),
                expires_at=now + 300,
                algorithm="RS256",
                kid="synthetic",
                source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
            )

    from asca.application.oidc_discovery import CERN_OIDC_ISSUER

    metadata = OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("RS256",),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )
    transport = OfflineTokenTransport()
    verifier = OfflineVerifier()
    native = CernOidcNativeCodeExchange(
        registration(), metadata, transport=transport, verifier=verifier, clock=lambda: now
    )
    start = native.begin()
    state = parse_qs(urlsplit(start.authorization_url).query)["state"][0]
    policy = CernNativeLoopbackCallbackPolicy(registration())
    malicious = policy.parse(envelope(request_target=f"/callback?state={'A' * 43}&code=mock-code"))
    assert malicious.code is not None
    with pytest.raises(OidcNativeExchangeError):
        native.exchange_callback(
            browser_binding=start.browser_binding,
            state=malicious.state,
            code=malicious.code,
        )
    assert transport.count == verifier.count == 0
    legitimate = policy.parse(envelope(request_target=f"/callback?state={state}&code=mock-code"))
    assert legitimate.code is not None
    result = native.exchange_callback(
        browser_binding=start.browser_binding,
        state=legitimate.state,
        code=legitimate.code,
    )
    assert result.subject == "synthetic-untrusted-subject"
    assert transport.count == verifier.count == 1
    with pytest.raises(OidcNativeExchangeError):
        native.exchange_callback(
            browser_binding=start.browser_binding,
            state=legitimate.state,
            code=legitimate.code,
        )
    assert transport.count == verifier.count == 1
