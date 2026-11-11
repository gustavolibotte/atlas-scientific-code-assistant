"""Adversarial end-to-end native host tests with synthetic OIDC, real loopback."""

from __future__ import annotations

import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.identity import AuthorizationStart
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_host import OidcNativeHostError
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_native_host import CernNativeOidcHostTransaction
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000.0
CLIENT = "synthetic-host-security-client"


def provider() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("RS256", "PS256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


class NoNetworkTransport(HttpsOidcTokenTransport):
    def __init__(self) -> None:
        self.requests: list[tuple[UnsentOidcTokenRequest, object]] = []
        self.on_exchange = None

    def exchange(
        self, prepared: UnsentOidcTokenRequest, client: object
    ) -> UnverifiedOidcTokenHttpResponse:
        self.requests.append((prepared, client))
        if self.on_exchange is not None:
            self.on_exchange()
        return UnverifiedOidcTokenHttpResponse(
            body=json.dumps(
                {"access_token": "private", "token_type": "Bearer", "id_token": "x.y.z"}
            ).encode("ascii")
        )


class NoNetworkVerifier(CernOidcVerificationPipeline):
    def __init__(self) -> None:
        self.calls = 0

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
        assert tokens is not None and provider is not None and expected_nonce
        self.calls += 1
        return CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="offline-subject",
            audiences=(expected_client_id,),
            expires_at=now + 200,
            algorithm="RS256",
            kid="offline-key",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )


def build(**kwargs: object):
    transport = NoNetworkTransport()
    verifier = NoNetworkVerifier()
    now = [NOW]
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "client_id": CLIENT,
        "metadata": provider(),
        "transport": transport,
        "verifier": verifier,
        "clock": lambda: now[0],
        "timeout_seconds": 0.7,
        "per_connection_seconds": 0.1,
        "max_connections": 3,
    }
    settings.update(kwargs)
    host = CernNativeOidcHostTransaction(**settings)  # type: ignore[arg-type]
    return host, transport, verifier, now


def begin(host: CernNativeOidcHostTransaction) -> str:
    result = host.begin()
    return parse_qs(urlsplit(result.authorization_url).query)["state"][0]


def packet(host: CernNativeOidcHostTransaction, query: str, **kwargs: str) -> bytes:
    parsed = urlsplit(host.binding.redirect_uri)
    method = kwargs.get("method", "GET")
    authority = kwargs.get("authority", parsed.netloc)
    path = kwargs.get("path", parsed.path)
    version = kwargs.get("version", "HTTP/1.1")
    headers = kwargs.get("headers", "")
    return (f"{method} {path}?{query} {version}\r\nHost: {authority}\r\n{headers}\r\n").encode(
        "ascii"
    )


def send(host: CernNativeOidcHostTransaction, content: bytes) -> bytes:
    with socket.create_connection((host.binding.host, host.binding.port), timeout=0.5) as sock:
        sock.settimeout(1.1)
        sock.sendall(content)
        chunks = []
        while True:
            value = sock.recv(4096)
            if not value:
                return b"".join(chunks)
            chunks.append(value)


def complete_with_packet(host: CernNativeOidcHostTransaction, raw: bytes):
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(host.complete)
        response = send(host, raw)
        return future.result(timeout=2), response


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw.replace(b"GET ", b"POST ", 1),
        lambda raw: raw.replace(b"HTTP/1.1", b"HTTP/1.0", 1),
        lambda raw: raw.replace(b"Host:", b"X-Host:", 1),
        lambda raw: raw.replace(b"\r\nHost:", b"\r\nHost: evil.invalid\r\nHost:"),
        lambda raw: raw.replace(b"\r\nHost:", b"\r\nCookie: session=forged\r\nHost:"),
        lambda raw: raw.replace(b"\r\nHost:", b"\r\nAuthorization: Bearer forged\r\nHost:"),
        lambda raw: raw.replace(b"\r\nHost:", b"\r\nX-Forwarded-For: 8.8.8.8\r\nHost:"),
        lambda raw: raw.replace(b"\r\nHost:", b"\r\nTransfer-Encoding: chunked\r\nHost:"),
        lambda raw: raw.replace(b"\r\nHost:", b"\r\nContent-Length: 0\r\nHost:"),
        lambda raw: raw.replace(b"\r\nHost:", b"\r\nOrigin: https://evil.invalid\r\nHost:"),
        lambda raw: raw.replace(b"/oidc/callback?", b"/wrong/callback?"),
        lambda raw: raw.replace(b"state=", b"state=%QQ", 1),
        lambda raw: raw.replace(b"&error=", b"&code=forged&error="),
        lambda raw: raw.replace(b"&error=", b"&state=duplicate&error="),
        lambda raw: raw.replace(b"&error=", b"&iss=https://evil.invalid&error="),
        lambda raw: raw.replace(b"&error=", b"&evil=1&error="),
        lambda raw: raw.replace(b"\r\n", b"\n"),
        lambda raw: raw + b"EXTRA-TRAILING-BYTES",
    ],
)
def test_invalid_http_is_rejected_but_valid_denial_still_consumes(mutation) -> None:
    host, transport, verifier, _ = build()
    with host:
        state = begin(host)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            raw = packet(host, f"state={state}&error=access_denied")
            invalid = send(host, mutation(raw))
            assert invalid.startswith(b"HTTP/1.1 400")
            assert not host.closed and host._exchange._store._pending
            response = send(host, raw)
            assert response.startswith(b"HTTP/1.1 202")
            result = future.result(timeout=2)
            assert result == NativeCallbackDenied()
        assert not transport.requests and verifier.calls == 0
        assert host.closed


@pytest.mark.parametrize(
    "wrong",
    [
        "Z" * 43,
        "A" * 44,
        "_" * 43,
    ],
)
def test_syntax_valid_but_wrong_state_terminates_without_token_request(wrong: str) -> None:
    host, transport, verifier, _ = build()
    with host:
        correct = begin(host)
        assert wrong != correct
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            assert send(host, packet(host, f"state={wrong}&code=forged-code")).startswith(
                b"HTTP/1.1 202"
            )
            with pytest.raises(OidcNativeHostError):
                future.result(timeout=2)
    assert host.closed and host._exchange._store._pending == {}
    assert transport.requests == [] and verifier.calls == 0


def test_cancel_during_blocking_receive_ensures_no_late_token_request() -> None:
    host, transport, verifier, _ = build(timeout_seconds=2)
    with host:
        begin(host)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            time.sleep(0.03)
            host.close()
            with pytest.raises(OidcNativeHostError):
                future.result(timeout=2)
    assert host._exchange._store._pending == {}
    assert transport.requests == [] and verifier.calls == 0


def test_listener_shutdown_precedes_any_token_exchange() -> None:
    host, transport, verifier, _ = build()
    with host:
        state = begin(host)
        observed: list[bool] = []
        transport.on_exchange = lambda: observed.append(host._listener.closed)
        result, response = complete_with_packet(host, packet(host, f"state={state}&code=abc"))
        assert result.subject == "offline-subject"
        assert response.startswith(b"HTTP/1.1 202")
        assert observed == [True] and verifier.calls == 1


def test_wrong_issuer_refuses_success_and_revokes_original() -> None:
    host, transport, verifier, _ = build()
    with host:
        state = begin(host)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            invalid = packet(host, f"state={state}&code=abc&iss=https://evil.invalid")
            assert send(host, invalid).startswith(b"HTTP/1.1 400")
            valid = packet(host, f"state={state}&error=access_denied")
            assert send(host, valid).startswith(b"HTTP/1.1 202")
            assert future.result(timeout=2) == NativeCallbackDenied()
    assert transport.requests == [] and verifier.calls == 0


def test_duplicate_complete_fails_closed_with_no_second_receiver() -> None:
    host, transport, _, _ = build(timeout_seconds=2)
    with host:
        begin(host)
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(host.complete)
            deadline = time.monotonic() + 1.0
            while not host._receiving and time.monotonic() < deadline:
                time.sleep(0.005)
            assert host._receiving
            with pytest.raises(OidcNativeHostError):
                host.complete()
            with pytest.raises(OidcNativeHostError):
                first.result(timeout=2)
    assert host.closed and host._exchange._store._pending == {}
    assert transport.requests == []


def test_expired_attempt_is_revoked_after_syntax_valid_callback() -> None:
    host, transport, verifier, now = build()
    with host:
        state = begin(host)
        now[0] += 500
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            assert send(host, packet(host, f"state={state}&code=abc")).startswith(b"HTTP/1.1 202")
            with pytest.raises(OidcNativeHostError):
                future.result(timeout=2)
    assert host.closed and host._exchange._store._pending == {}
    assert not transport.requests and verifier.calls == 0


def test_valid_denial_cannot_be_replayed_to_a_second_completer() -> None:
    host, transport, _, _ = build()
    with host:
        state = begin(host)
        response, status = complete_with_packet(
            host, packet(host, f"state={state}&error=access_denied")
        )
        assert response == NativeCallbackDenied()
        assert status.startswith(b"HTTP/1.1 202")
        with pytest.raises(OidcNativeHostError):
            host.complete()
        with pytest.raises(OSError):
            socket.create_connection((host.binding.host, host.binding.port), timeout=0.2)
    assert not transport.requests


def test_no_route_identity_session_or_browser_side_effect() -> None:
    host, _, _, _ = build()
    with host:
        assert not hasattr(host, "authenticate")
        assert not hasattr(host, "login")
        assert not hasattr(host, "session")
        assert not hasattr(host, "roles")
        assert not hasattr(host, "open_browser")
        assert not hasattr(host, "verify_membership")
        assert not hasattr(host, "redirect_to_provider")
        assert not hasattr(host, "consume_external_callback")
        with pytest.raises(TypeError):
            host.complete(state="forged", code="forged")  # type: ignore[call-arg]


def test_unexpected_cancellation_after_completion_never_resurrects_attempt() -> None:
    host, transport, verifier, _ = build()
    with host:
        state = begin(host)
        result, _ = complete_with_packet(host, packet(host, f"state={state}&code=abc"))
        assert result.subject == "offline-subject"
    host.close()
    assert len(transport.requests) == verifier.calls == 1
    assert host._exchange._store._pending == {}


def test_syntactically_valid_callback_with_extra_binding_param_rejected() -> None:
    host, transport, verifier, _ = build()
    with host:
        state = begin(host)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            incorrect = packet(host, f"state={state}&error=access_denied&browser_binding=forged")
            assert send(host, incorrect).startswith(b"HTTP/1.1 400")
            correct = packet(host, f"state={state}&error=access_denied")
            assert send(host, correct).startswith(b"HTTP/1.1 202")
            assert future.result(timeout=2) == NativeCallbackDenied()
    assert transport.requests == [] and verifier.calls == 0


@pytest.mark.parametrize(
    "changed",
    [
        "/evil/path",
        "/protocol/openid-connect/token",
        "/protocol/openid-connect/auth/other",
    ],
)
def test_tampered_authorization_url_path_fails_closed(changed: str) -> None:
    host, transport, _, _ = build()
    with host:
        original = host._lifecycle.begin

        def forged():
            started = original()
            return AuthorizationStart(
                authorization_url=started.authorization_url.replace(
                    "/protocol/openid-connect/auth?", f"{changed}?"
                ),
                browser_binding=started.browser_binding,
            )

        with patch.object(host._lifecycle, "begin", forged), pytest.raises(OidcNativeHostError):
            host.begin()
        assert host.closed
        assert not transport.requests


def test_authorization_url_cannot_change_callback_port() -> None:
    host, transport, _, _ = build()
    with host:
        original = host._lifecycle.begin

        def forged():
            started = original()
            url = started.authorization_url.replace("%3A" + str(host.binding.port), "%3A12345")
            assert url != started.authorization_url
            return AuthorizationStart(
                authorization_url=url, browser_binding=started.browser_binding
            )

        with patch.object(host._lifecycle, "begin", forged), pytest.raises(OidcNativeHostError):
            host.begin()
        assert host.closed and not transport.requests


def test_current_socket_binding_and_exchange_registration_must_match() -> None:
    host, _, _, _ = build()
    with host:
        original = host._listener._registration
        from asca.domain.oidc_registration import OidcClientRegistration

        host._listener._registration = OidcClientRegistration(
            client_id=original.client_id,
            redirect_uri=original.redirect_uri.replace("/oidc/callback", "/other/callback"),
            mode=original.mode,
            scopes=original.scopes,
        )
        with pytest.raises(OidcNativeHostError):
            host.begin()
        assert host.closed


def test_transient_invalid_raw_http_does_not_leak_state() -> None:
    host, transport, _, _ = build()
    with host:
        state = begin(host)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            invalid = packet(host, f"state={state}&error=access_denied", method="DELETE")
            response = send(host, invalid)
            assert response.startswith(b"HTTP/1.1 400")
            assert state.encode() not in response
            valid = send(host, packet(host, f"state={state}&error=access_denied"))
            assert valid.startswith(b"HTTP/1.1 202")
            assert state.encode() not in valid
            assert future.result(timeout=2) == NativeCallbackDenied()
    assert transport.requests == []


def test_close_during_verifier_or_token_exchange_cannot_race_consumption() -> None:
    host, transport, verifier, _ = build()
    started = threading.Event()
    release = threading.Event()

    def blocking_exchange() -> None:
        started.set()
        assert release.wait(timeout=2)

    transport.on_exchange = blocking_exchange
    with host:
        state = begin(host)
        with ThreadPoolExecutor(max_workers=3) as pool:
            callback = pool.submit(host.complete)
            assert send(host, packet(host, f"state={state}&code=abc")).startswith(b"HTTP/1.1 202")
            assert started.wait(timeout=1)
            cancel = pool.submit(host.close)
            time.sleep(0.03)
            assert not cancel.done()
            release.set()
            assert callback.result(timeout=2).subject == "offline-subject"
            cancel.result(timeout=2)
    assert host.closed and host._exchange._store._pending == {}
    assert len(transport.requests) == verifier.calls == 1


def test_listener_creation_rejection_is_sanitized_before_binding() -> None:
    with pytest.raises(OidcNativeHostError, match="Invalid native host configuration"):
        build(host="0.0.0.0")


def test_constructor_rejects_mismatching_exchange_registration_and_closes_socket() -> None:
    import asca.infrastructure.oidc_native_host as module

    captured: list[object] = []
    actual_listener = module.CernNativeLoopbackListener

    def capture_listener(**kwargs: object):
        listener = actual_listener(**kwargs)  # type: ignore[arg-type]
        captured.append(listener)
        return listener

    class ForgedExchange:
        callback_registration = "not-the-listener-registration"

    with (
        patch.object(module, "CernNativeLoopbackListener", capture_listener),
        patch.object(module, "CernOidcNativeCodeExchange", return_value=ForgedExchange()),
        patch.object(module, "CernNativeCallbackLifecycle", return_value=object()),
        pytest.raises(OidcNativeHostError),
    ):
        build()
    assert captured and captured[0].closed  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "forgery",
    [
        "invalid-object",
        "invalid-binding",
        "invalid-url-type",
        "very-long-url",
        "url-with-control-character",
        "url-with-fragment",
        "url-with-extra-param",
        "url-without-state",
        "url-with-duplicate-state",
        "url-with-wrong-client-id",
        "url-with-wrong-scope",
        "url-with-non-s256-challenge",
        "url-with-added-browser-binding",
    ],
)
def test_forged_start_result_fails_closed_without_returning_secret(forgery: str) -> None:
    host, transport, _, _ = build()
    with host:
        original_begin = host._lifecycle.begin

        def tamper():
            original = original_begin()
            if forgery == "invalid-object":
                return object()
            if forgery == "invalid-binding":
                return AuthorizationStart(original.authorization_url, "short")
            if forgery == "invalid-url-type":
                return AuthorizationStart(
                    object(),
                    original.browser_binding,  # type: ignore[arg-type]
                )
            if forgery == "very-long-url":
                return AuthorizationStart(
                    original.authorization_url + "X" * 9000, original.browser_binding
                )
            if forgery == "url-with-control-character":
                return AuthorizationStart(
                    original.authorization_url + "\n", original.browser_binding
                )
            url = original.authorization_url
            if forgery == "url-with-fragment":
                url += "#fragment"
            elif forgery == "url-with-extra-param":
                url += "&unexpected=forged"
            elif forgery == "url-without-state":
                url = url.replace("state=", "nostate=", 1)
            elif forgery == "url-with-duplicate-state":
                url += "&state=" + "A" * 43
            elif forgery == "url-with-wrong-client-id":
                url = url.replace(f"client_id={CLIENT}", "client_id=other-client", 1)
            elif forgery == "url-with-wrong-scope":
                url = url.replace("scope=openid", "scope=admin", 1)
            elif forgery == "url-with-non-s256-challenge":
                url = url.replace("code_challenge_method=S256", "code_challenge_method=plain", 1)
            elif forgery == "url-with-added-browser-binding":
                url += "&browser_binding=forged"
            return AuthorizationStart(url, original.browser_binding)

        with patch.object(host._lifecycle, "begin", tamper), pytest.raises(OidcNativeHostError):
            host.begin()
        assert host.closed
        assert not transport.requests
        if forgery not in (
            "invalid-object",
            "invalid-binding",
            "invalid-url-type",
            "very-long-url",
            "url-with-control-character",
            "url-without-state",
            "url-with-duplicate-state",
        ):
            assert host._exchange._store._pending == {}


@pytest.mark.parametrize("kind", ["closed-after-receive", "missing-secret", "changed-registration"])
def test_post_receive_boundary_rejects_races_and_forged_host_state(kind: str) -> None:
    host, transport, verifier, _ = build()
    with host:
        begin(host)

        def altered_receive():
            if kind == "closed-after-receive":
                host.close()
            elif kind == "missing-secret":
                host._browser_binding = None
            elif kind == "changed-registration":
                registration = host._exchange._registration
                from asca.domain.oidc_registration import OidcClientRegistration

                host._exchange._registration = OidcClientRegistration(
                    client_id=registration.client_id,
                    redirect_uri=registration.redirect_uri.replace(
                        "/oidc/callback", "/other/callback"
                    ),
                    mode=registration.mode,
                    scopes=registration.scopes,
                )
            return object()  # No callback may reach the lower layer after these checks.

        with (
            patch.object(host._listener, "receive", altered_receive),
            pytest.raises(OidcNativeHostError),
        ):
            host.complete()
    assert host.closed and not transport.requests and verifier.calls == 0


def test_unexpected_socket_close_failure_does_not_skip_attempt_revocation() -> None:
    host, transport, _, _ = build()
    with host:
        begin(host)
        with patch.object(host._listener, "close", side_effect=OSError("private-close-failure")):
            host.close()
        assert host.closed and host._exchange._store._pending == {}
        assert not transport.requests
