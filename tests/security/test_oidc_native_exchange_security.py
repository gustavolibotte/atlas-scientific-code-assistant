"""Adversarial native code-to-token binding checks with no live CERN network."""

from __future__ import annotations

import base64
import json
import math
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from email.message import Message
from typing import cast
from urllib.parse import parse_qs, urlsplit
from urllib.request import OpenerDirector, Request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_exchange import OidcNativeExchangeError
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_http import OidcTokenHttpError, UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_jwks_http import HttpsCernOidcJwksFetcher
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000.0
CLIENT = "synthetic-native-asca"
REDIRECT = "http://127.0.0.1:8765/callback"


def metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("RS256", "PS256", "ES256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id=CLIENT, redirect_uri=REDIRECT, mode=OidcClientMode.NATIVE_LOOPBACK
    )


def body(token: str = "a.b.c") -> bytes:
    return json.dumps(
        {
            "access_token": "synthetic-access",
            "token_type": "Bearer",
            "id_token": token,
            "expires_in": 300,
        }
    ).encode()


class FakeTransport(HttpsOidcTokenTransport):
    def __init__(self) -> None:
        self.requests: list[UnsentOidcTokenRequest] = []
        self.registrations: list[OidcClientRegistration] = []
        self.response: object = UnverifiedOidcTokenHttpResponse(body=body())
        self.failure = False

    def exchange(
        self, prepared: UnsentOidcTokenRequest, client: OidcClientRegistration
    ) -> UnverifiedOidcTokenHttpResponse:
        self.requests.append(prepared)
        self.registrations.append(client)
        if self.failure:
            raise ValueError("sensitive-synthetic-token-transport-error")
        return self.response  # type: ignore[return-value]


class FakeVerifier(CernOidcVerificationPipeline):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int, str]] = []
        self.failure = False
        self.override: dict[str, object] = {}

    def check(
        self,
        tokens,
        metadata,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        clock_skew_seconds: int = 60,
        max_token_lifetime_seconds: int = 3600,
        trusted_additional_audiences: tuple[str, ...] = (),
    ):  # type: ignore[no-untyped-def]
        from dataclasses import replace

        del metadata, clock_skew_seconds, max_token_lifetime_seconds, trusted_additional_audiences
        self.calls.append((expected_client_id, expected_nonce, now, tokens.id_token))
        if self.failure:
            raise ValueError("synthetic-secret-jws-validation-error")
        result = CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="test-native-subject",
            audiences=(expected_client_id,),
            expires_at=now + 250,
            algorithm="RS256",
            kid="synthetic-key",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )
        return replace(result, **self.override)


def make(
    *,
    transport: FakeTransport | None = None,
    verifier: FakeVerifier | None = None,
    clock=None,
    **kwargs,
):
    token_transport = transport if transport is not None else FakeTransport()
    token_verifier = verifier if verifier is not None else FakeVerifier()
    now = [NOW] if clock is None else clock
    service = CernOidcNativeCodeExchange(
        registration(),
        metadata(),
        transport=token_transport,
        verifier=token_verifier,
        clock=lambda: now[0],
        **kwargs,
    )
    return service, token_transport, token_verifier, now


def begin(service: CernOidcNativeCodeExchange) -> tuple[str, str, str, str]:
    started = service.begin()
    query = parse_qs(urlsplit(started.authorization_url).query)
    return started.browser_binding, query["state"][0], query["nonce"][0], query["code_challenge"][0]


def finish(
    service: CernOidcNativeCodeExchange,
    binding: str,
    state: str,
    *,
    code: str = "synthetic-code",
    **kwargs,
):
    return service.exchange_callback(browser_binding=binding, state=state, code=code, **kwargs)


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        False,
        object(),
        1,
        "client",
        {},
        OidcClientRegistration(
            client_id=CLIENT,
            redirect_uri="https://asca.example.invalid/callback",
            mode=OidcClientMode.WEB_BFF,
        ),
    ],
)
def test_reject_invalid_or_bff_registration(invalid: object) -> None:
    with pytest.raises(OidcNativeExchangeError):
        CernOidcNativeCodeExchange(invalid, metadata())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "https://evil.invalid"},
        {"authorization_endpoint": "https://evil.invalid/authorize"},
        {"token_endpoint": "https://evil.invalid/token"},
        {"jwks_uri": "https://evil.invalid/jwks"},
        {"jwks_uri": CERN_OIDC_ISSUER + "/protocol/openid-connect/certs?other=1"},
        {"supports_authorization_code": False},
        {"supports_pkce_s256": False},
        {"approved_id_token_algorithms": ("HS256",)},
        {"approved_id_token_algorithms": ("RS256", "RS256")},
        {"approved_id_token_algorithms": ()},
        {"approved_id_token_algorithms": (None,)},
        {"approved_id_token_algorithms": []},
    ],
)
def test_forged_provider_metadata_rejected(change: dict[str, object]) -> None:
    with pytest.raises(OidcNativeExchangeError):
        CernOidcNativeCodeExchange(registration(), replace(metadata(), **change))


@pytest.mark.parametrize(
    "settings",
    [
        {"transport": object()},
        {"verifier": object()},
        {"clock": None},
        {"clock": "clock"},
        {"ttl_seconds": 29},
        {"ttl_seconds": 901},
        {"ttl_seconds": True},
        {"ttl_seconds": 33.3},
        {"ttl_seconds": None},
        {"max_pending": 0},
        {"max_pending": True},
        {"max_pending": 10001},
        {"max_pending": "2"},
    ],
)
def test_bad_constructor_policy_rejected(settings: dict[str, object]) -> None:
    with pytest.raises(OidcNativeExchangeError):
        CernOidcNativeCodeExchange(registration(), metadata(), **settings)  # type: ignore[arg-type]


def test_forged_frozen_registration_is_revalidated() -> None:
    forged = registration()
    object.__setattr__(forged, "redirect_uri", "http://attacker.invalid/callback")
    with pytest.raises(OidcNativeExchangeError):
        CernOidcNativeCodeExchange(forged, metadata())


@pytest.mark.parametrize(
    "change",
    [
        {"browser_binding": None},
        {"browser_binding": ""},
        {"browser_binding": 1},
        {"state": None},
        {"state": ""},
        {"state": 123},
        {"code": None},
        {"code": ""},
        {"code": "bad code"},
        {"code": "contains\nline"},
        {"code": "é"},
        {"code": "x" * 2049},
        {"code": True},
        {"response_issuer": 1},
        {"response_issuer": "https://evil.invalid"},
    ],
)
def test_invalid_callback_does_not_consume_valid_attempt(change: dict[str, object]) -> None:
    service, transport, verifier, _ = make()
    browser_binding, state, _, _ = begin(service)
    inputs = {"browser_binding": browser_binding, "state": state, "code": "synthetic-code"}
    inputs.update(change)
    with pytest.raises(OidcNativeExchangeError):
        service.exchange_callback(**inputs)  # type: ignore[arg-type]
    assert not transport.requests and not verifier.calls
    assert finish(service, browser_binding, state).subject == "test-native-subject"


def test_wrong_binding_and_state_cannot_consume_other_attempt() -> None:
    service, transport, _, _ = make()
    a, sa, _, _ = begin(service)
    b, sb, _, _ = begin(service)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, a, sb)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, b, sa)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, "attacker-browser-binding", sa)
    assert not transport.requests
    finish(service, a, sa)
    finish(service, b, sb)
    assert len(transport.requests) == 2


def test_replay_after_success_fails_without_second_post() -> None:
    service, transport, _, _ = make()
    binding, state, _, _ = begin(service)
    finish(service, binding, state)
    for _ in range(4):
        with pytest.raises(OidcNativeExchangeError):
            finish(service, binding, state)
    assert len(transport.requests) == 1


def test_concurrent_redeem_posts_once() -> None:
    service, transport, _, _ = make()
    binding, state, _, _ = begin(service)

    def redeem(_: int) -> bool:
        try:
            finish(service, binding, state)
        except OidcNativeExchangeError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=16) as pool:
        assert sum(pool.map(redeem, range(64))) == 1
    assert len(transport.requests) == 1


def test_expired_callback_is_not_sent() -> None:
    service, transport, _, now = make(ttl_seconds=60)
    binding, state, _, _ = begin(service)
    now[0] += 60
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert not transport.requests


@pytest.mark.parametrize(
    "instant", [None, "wrong", True, False, 0, -1, math.nan, math.inf, -math.inf, 2**53]
)
def test_invalid_clock_fails_before_start(instant: object) -> None:
    service, _, _, now = make()
    now[0] = instant
    with pytest.raises(OidcNativeExchangeError):
        service.begin()


def test_invalid_callback_clock_does_not_post() -> None:
    service, transport, _, now = make()
    binding, state, _, _ = begin(service)
    now[0] = math.nan
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert not transport.requests
    now[0] = NOW
    assert finish(service, binding, state).subject


def test_invalid_clock_after_token_response_rejects_without_replay() -> None:
    clock = [NOW]

    class BreakingTransport(FakeTransport):
        def exchange(self, prepared, registration):  # type: ignore[no-untyped-def]
            result = super().exchange(prepared, registration)
            clock[0] = math.nan
            return result

    transport = BreakingTransport()
    service, _, verifier, _ = make(transport=transport, clock=clock)
    binding, state, _, _ = begin(service)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert not verifier.calls
    clock[0] = NOW
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert len(transport.requests) == 1


def test_transport_failure_consumes_and_sanitizes() -> None:
    transport = FakeTransport()
    transport.failure = True
    service, _, verifier, _ = make(transport=transport)
    binding, state, _, _ = begin(service)
    with pytest.raises(OidcNativeExchangeError) as exc:
        finish(service, binding, state)
    assert "synthetic-secret" not in str(exc.value)
    assert not verifier.calls
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert len(transport.requests) == 1


@pytest.mark.parametrize("invalid", [None, "text", object(), 42, b"bytes", {}])
def test_unrecognized_exchange_response_is_rejected_after_consume(invalid: object) -> None:
    transport = FakeTransport()
    transport.response = invalid
    service, _, verifier, _ = make(transport=transport)
    binding, state, _, _ = begin(service)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert not verifier.calls
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b"not-json",
        b'{"access_token":"secret"}',
        b'{"token_type":"Bearer","id_token":"bad"}',
        b'{"access_token":"synthetic","token_type":"Basic","id_token":"a.b.c"}',
        b'{"access_token":"synthetic","token_type":"Bearer","id_token":"a.b.c","id_token":"d.e.f"}',
    ],
)
def test_bad_token_http_body_consumes_attempt(payload: bytes) -> None:
    transport = FakeTransport()
    transport.response = UnverifiedOidcTokenHttpResponse(body=payload)
    service, _, verifier, _ = make(transport=transport)
    binding, state, _, _ = begin(service)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert not verifier.calls
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)


def test_verifier_failure_consumes_and_sanitizes() -> None:
    verifier = FakeVerifier()
    verifier.failure = True
    service, transport, _, _ = make(verifier=verifier)
    binding, state, _, _ = begin(service)
    with pytest.raises(OidcNativeExchangeError) as exc:
        finish(service, binding, state)
    assert "synthetic-secret" not in str(exc.value)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert len(transport.requests) == 1 and len(verifier.calls) == 1


@pytest.mark.parametrize(
    "corrupt",
    [
        {"issuer": "https://evil.invalid"},
        {"subject": ""},
        {"audiences": ("attacker",)},
        {"audiences": "bad"},
        {"algorithm": "HS256"},
        {"expires_at": 1},
        {"expires_at": True},
    ],
)
def test_forged_verifier_result_rejected(corrupt: dict[str, object]) -> None:
    verifier = FakeVerifier()
    verifier.override = corrupt
    service, transport, _, _ = make(verifier=verifier)
    binding, state, _, _ = begin(service)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert len(transport.requests) == 1
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)


def test_nonce_is_not_derived_from_jwt_or_caller() -> None:
    service, _, verifier, _ = make()
    binding, state, nonce, _ = begin(service)
    with pytest.raises(TypeError):
        service.exchange_callback(
            browser_binding=binding, state=state, code="code", nonce="attacker"
        )  # type: ignore[call-arg]
    finish(service, binding, state)
    assert verifier.calls[0][1] == nonce


def test_request_tampering_detected_by_actual_transport() -> None:
    # The underlying native HTTPS adapter independently validates the form.
    from asca.domain.oidc_token_request import UnsentOidcTokenRequest

    actual = HttpsOidcTokenTransport(opener=cast(OpenerDirector, object()))
    forged = UnsentOidcTokenRequest(
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        form_body=b"grant_type=authorization_code&code=evil&redirect_uri=http%3A%2F%2Fevil.invalid&client_id=evil&code_verifier=a",
        expected_nonce="n" * 44,
    )
    with pytest.raises(OidcTokenHttpError):
        actual.exchange(forged, registration())


class FakeResponse:
    def __init__(self, response: bytes, content_type: str = "application/json", status: int = 200):
        self.body = response
        self.status = status
        self.headers = Message()
        self.headers.add_header("Content-Type", content_type)
        self.closed = False
        self.read_limit = -1

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True

    def read(self, limit: int) -> bytes:
        self.read_limit = limit
        return self.body[:limit]


class FakeOpener:
    def __init__(self, response: bytes, content_type: str = "application/json", status: int = 200):
        self.response = FakeResponse(response, content_type, status)
        self.requests: list[Request] = []

    def open(self, request: Request, *, timeout: float):
        assert timeout == 5.0
        self.requests.append(request)
        return self.response


def test_real_https_token_adapter_uses_post_and_original_code_verifier() -> None:
    opener = FakeOpener(body())
    real_transport = HttpsOidcTokenTransport(opener=cast(OpenerDirector, opener))
    service = CernOidcNativeCodeExchange(
        registration(),
        metadata(),
        transport=real_transport,
        verifier=FakeVerifier(),
        clock=lambda: NOW,
    )
    binding, state, _, challenge = begin(service)
    result = finish(service, binding, state)
    assert result.subject == "test-native-subject"
    assert len(opener.requests) == 1
    request = opener.requests[0]
    assert request.full_url == CERN_OIDC_ISSUER + "/protocol/openid-connect/token"
    assert request.get_method() == "POST"
    params = parse_qs(request.data.decode("ascii"))
    assert params["code"] == ["synthetic-code"]
    assert params["client_id"] == [CLIENT]
    assert params["redirect_uri"] == [REDIRECT]
    from asca.application.identity import pkce_s256_challenge

    assert pkce_s256_challenge(params["code_verifier"][0]) == challenge
    assert opener.response.closed and opener.response.read_limit == 65537
    for sensitive in ("synthetic-code", params["code_verifier"][0]):
        assert sensitive not in repr(result)


@pytest.mark.parametrize("status", [201, 301, 302, 400, 401, 429, 500])
def test_actual_transport_http_errors_consume_without_verification(status: int) -> None:
    opener = FakeOpener(body(), status=status)
    service = CernOidcNativeCodeExchange(
        registration(),
        metadata(),
        transport=HttpsOidcTokenTransport(opener=cast(OpenerDirector, opener)),
        verifier=FakeVerifier(),
        clock=lambda: NOW,
    )
    binding, state, _, _ = begin(service)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert len(opener.requests) == 1
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)


@pytest.mark.parametrize(
    "content_type", ["text/html", "application/octet-stream", "application/json; charset=latin1"]
)
def test_actual_transport_content_type_rejected(content_type: str) -> None:
    opener = FakeOpener(body(), content_type=content_type)
    service = CernOidcNativeCodeExchange(
        registration(),
        metadata(),
        transport=HttpsOidcTokenTransport(opener=cast(OpenerDirector, opener)),
        verifier=FakeVerifier(),
        clock=lambda: NOW,
    )
    binding, state, _, _ = begin(service)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def signed_jws(
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, algorithm: str, nonce: str
) -> tuple[str, bytes]:
    public = private.public_key().public_numbers()
    key: dict[str, object] = {"kid": "integration", "alg": algorithm, "use": "sig"}
    if isinstance(private, rsa.RSAPrivateKey):
        key.update(
            kty="RSA",
            n=b64(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
            e=b64(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")),
        )
    else:
        key.update(
            kty="EC",
            crv="P-256",
            x=b64(public.x.to_bytes(32, "big")),
            y=b64(public.y.to_bytes(32, "big")),
        )
    header = b64(json.dumps({"alg": algorithm, "kid": "integration", "typ": "JWT"}).encode())
    payload = b64(
        json.dumps(
            {
                "iss": CERN_OIDC_ISSUER,
                "sub": "synthetic-native-crypto-subject",
                "aud": CLIENT,
                "nonce": nonce,
                "iat": int(NOW) - 10,
                "exp": int(NOW) + 200,
            }
        ).encode()
    )
    signing = (header + "." + payload).encode("ascii")
    if isinstance(private, rsa.RSAPrivateKey):
        scheme = (
            padding.PKCS1v15()
            if algorithm == "RS256"
            else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        )
        signature = private.sign(signing, scheme, hashes.SHA256())
    else:
        der = private.sign(signing, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing.decode("ascii") + "." + b64(signature), json.dumps({"keys": [key]}).encode()


@pytest.mark.parametrize("alg", ["RS256", "PS256", "ES256"])
def test_real_cryptographic_end_to_end_code_to_token_exchange(alg: str) -> None:
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    private = (
        ec.generate_private_key(ec.SECP256R1())
        if alg == "ES256"
        else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    token_opener = FakeOpener(body())
    keys_opener = FakeOpener(b"{}", content_type="application/jwk-set+json")
    verifier = CernOidcVerificationPipeline(
        fetcher=HttpsCernOidcJwksFetcher(opener=cast(OpenerDirector, keys_opener))
    )
    service = CernOidcNativeCodeExchange(
        registration(),
        metadata(),
        transport=HttpsOidcTokenTransport(opener=cast(OpenerDirector, token_opener)),
        verifier=verifier,
        clock=lambda: NOW,
    )
    binding, state, nonce, challenge = begin(service)
    signed, keys = signed_jws(private, alg, nonce)
    token_opener.response.body = body(signed)
    keys_opener.response.body = keys
    result = finish(service, binding, state)
    assert result.subject == "synthetic-native-crypto-subject"
    assert result.algorithm == alg
    assert len(token_opener.requests) == len(keys_opener.requests) == 1
    assert token_opener.requests[0].full_url.endswith("/token")
    assert keys_opener.requests[0].full_url.endswith("/certs")
    params = parse_qs(token_opener.requests[0].data.decode())
    from asca.application.identity import pkce_s256_challenge

    assert pkce_s256_challenge(params["code_verifier"][0]) == challenge
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert len(token_opener.requests) == len(keys_opener.requests) == 1


def test_no_extra_network_with_injected_test_transports(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected network call")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    service, transport, _, _ = make()
    browser, state, _, _ = begin(service)
    assert finish(service, browser, state).subject
    assert len(transport.requests) == 1


@pytest.mark.parametrize("corrupt", ["type", "code", "redirect"])
def test_forged_internal_code_grant_cannot_proceed(
    monkeypatch: pytest.MonkeyPatch, corrupt: str
) -> None:
    from asca.domain.identity import AuthorizationCodeGrant

    service, transport, verifier, _ = make()
    binding, state, nonce, _ = begin(service)
    forged = AuthorizationCodeGrant(
        code="other-code" if corrupt == "code" else "synthetic-code",
        nonce=nonce,
        code_verifier="a" * 64,
        redirect_uri=("https://evil.invalid/callback" if corrupt == "redirect" else REDIRECT),
    )
    monkeypatch.setattr(
        service._service,
        "finish",
        lambda **_kwargs: object() if corrupt == "type" else forged,
    )
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert not transport.requests and not verifier.calls


def test_forged_prepared_request_cannot_replace_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    from asca.infrastructure import oidc_native_exchange as module

    service, transport, verifier, _ = make()
    binding, state, _, _ = begin(service)
    actual = module.prepare_cern_native_token_request

    def forged(*args: object, **kwargs: object):
        return replace(
            actual(*args, **kwargs), expected_nonce="attacker_nonce_0123456789012345678901234"
        )

    monkeypatch.setattr(module, "prepare_cern_native_token_request", forged)
    with pytest.raises(OidcNativeExchangeError):
        finish(service, binding, state)
    assert not transport.requests and not verifier.calls
