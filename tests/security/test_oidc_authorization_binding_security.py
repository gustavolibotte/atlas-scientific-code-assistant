"""Adversarial offline tests of CERN BFF state, nonce, replay and crypto binding."""

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
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_authorization_binding import OidcAuthorizationBindingError
from asca.domain.oidc_browser_cookie import COOKIE_NAME
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_authorization_binding import CernOidcReplaySafeBffBinding
from asca.infrastructure.oidc_jwks_http import HttpsCernOidcJwksFetcher
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000.0
CLIENT = "synthetic-asca-client"
CERN_JWKS = CERN_OIDC_ISSUER + "/protocol/openid-connect/certs"


def metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_JWKS,
        approved_id_token_algorithms=("RS256", "PS256", "ES256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id=CLIENT,
        redirect_uri="https://asca.example.invalid/oidc/callback",
        mode=OidcClientMode.WEB_BFF,
    )


class FakeVerifier(CernOidcVerificationPipeline):
    """Test-only verifier; never trusted for identity or key provenance."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.reject = False
        self.override: dict[str, object] = {}

    def check(
        self,
        token_data: ParsedUnverifiedOidcTokenResponse,
        provider: OidcProviderMetadata,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        clock_skew_seconds: int = 60,
        max_token_lifetime_seconds: int = 3_600,
        trusted_additional_audiences: tuple[str, ...] = (),
    ) -> CheckedUntrustedCernOidcToken:
        del token_data, provider, clock_skew_seconds, max_token_lifetime_seconds
        del trusted_additional_audiences
        self.calls.append((expected_client_id, expected_nonce))
        if self.reject:
            raise ValueError("synthetic-dangerous-token-secret")
        result = CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="synthetic-subject",
            audiences=(expected_client_id,),
            expires_at=now + 200,
            algorithm="RS256",
            kid="synthetic",
            source_url=CERN_JWKS,
        )
        if self.override:
            result = replace(result, **self.override)
        return result


def tokens(token: str = "synthetic.invalid.signature") -> ParsedUnverifiedOidcTokenResponse:
    return ParsedUnverifiedOidcTokenResponse(
        access_token="synthetic-access",
        id_token=token,
        token_type="Bearer",
        expires_in=300,
        refresh_token=None,
        scope=None,
    )


def make(fake: FakeVerifier | None = None, *, clock=None, **options: object):
    verifier = fake if fake is not None else FakeVerifier()
    instant = [NOW] if clock is None else clock
    service = CernOidcReplaySafeBffBinding(
        registration(),
        metadata(),
        pipeline=verifier,
        clock=lambda: instant[0],
        **options,  # type: ignore[arg-type]
    )
    return service, verifier, instant


def start(service: CernOidcReplaySafeBffBinding) -> tuple[str, str, str]:
    issued = service.begin()
    values = parse_qs(urlsplit(issued.authorization_url).query)
    return (
        issued.cookie.set_cookie_header().split(";", 1)[0],
        values["state"][0],
        values["nonce"][0],
    )


def check(
    service: CernOidcReplaySafeBffBinding,
    cookie: str,
    expected_state: str,
    **overrides: object,
):
    values: dict[str, object] = {
        "cookie_header": cookie,
        "state": expected_state,
        "code": "synthetic-code",
        "tokens": tokens(),
    }
    values.update(overrides)
    return service.check_callback(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad",
    [
        None,
        object(),
        False,
        "not-registered",
        1,
        OidcClientRegistration(
            client_id=CLIENT,
            redirect_uri="http://127.0.0.1:8000/callback",
            mode=OidcClientMode.NATIVE_LOOPBACK,
        ),
    ],
)
def test_unapproved_registration_rejected(bad: object) -> None:
    with pytest.raises(OidcAuthorizationBindingError):
        CernOidcReplaySafeBffBinding(bad, metadata())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "https://evil.invalid"},
        {"authorization_endpoint": CERN_OIDC_ISSUER + "/wrong"},
        {"token_endpoint": "https://evil.invalid/token"},
        {"jwks_uri": CERN_JWKS + "?evil=1"},
        {"supports_pkce_s256": False},
        {"supports_authorization_code": False},
        {"approved_id_token_algorithms": ("none",)},
        {"approved_id_token_algorithms": ("RS256", "RS256")},
        {"approved_id_token_algorithms": ()},
        {"approved_id_token_algorithms": []},
        {"approved_id_token_algorithms": (None,)},
    ],
)
def test_forged_metadata_rejected_before_new_attempt(change: dict[str, object]) -> None:
    with pytest.raises(OidcAuthorizationBindingError):
        CernOidcReplaySafeBffBinding(registration(), replace(metadata(), **change))


@pytest.mark.parametrize(
    "settings",
    [
        {"ttl_seconds": 29},
        {"ttl_seconds": 901},
        {"ttl_seconds": True},
        {"ttl_seconds": 1.0},
        {"ttl_seconds": None},
        {"cookie_lifetime_seconds": 0},
        {"cookie_lifetime_seconds": 29},
        {"cookie_lifetime_seconds": 901},
        {"cookie_lifetime_seconds": True},
        {"cookie_lifetime_seconds": 400},
        {"max_pending": 0},
        {"max_pending": 10001},
        {"max_pending": True},
        {"max_pending": "2"},
        {"clock": None},
        {"clock": "time"},
        {"pipeline": object()},
    ],
)
def test_constructor_policy_rejected(settings: dict[str, object]) -> None:
    args = {"registration": registration(), "metadata": metadata(), **settings}
    with pytest.raises(OidcAuthorizationBindingError):
        CernOidcReplaySafeBffBinding(**args)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "cookie_header",
    [
        None,
        "",
        "not-a-cookie=value",
        "arbitrary-value",
        12,
        f"{COOKIE_NAME}=invalid",
        f"{COOKIE_NAME}={'A' * 43}; {COOKIE_NAME}={'B' * 43}",
        f"{COOKIE_NAME}={'A' * 43}\nX:evil",
        "X" * 8193,
    ],
)
def test_bad_cookie_cannot_consume_legitimate_attempt(cookie_header: object) -> None:
    service, fake, _ = make()
    good_cookie, state, _ = start(service)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, good_cookie, state, cookie_header=cookie_header)
    assert not fake.calls
    check(service, good_cookie, state)
    assert len(fake.calls) == 1


@pytest.mark.parametrize("bad_state", [None, 42, "", "bad", "\x00state", "X" * 300])
def test_invalid_state_does_not_consume_correct_attempt(bad_state: object) -> None:
    service, fake, _ = make()
    cookie, state, _ = start(service)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state, state=bad_state)
    assert not fake.calls
    check(service, cookie, state)


@pytest.mark.parametrize(
    "bad_code",
    [None, "", "\n", "code\nsmuggle", "has space", "é", 13, True, "x" * 2049],
)
def test_invalid_callback_code_rejected_before_consumption(bad_code: object) -> None:
    service, fake, _ = make()
    cookie, state, _ = start(service)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state, code=bad_code)
    assert not fake.calls
    check(service, cookie, state)


@pytest.mark.parametrize("value", ["evil", "", 12, False, "https://evil.invalid"])
def test_invalid_callback_issuer_rejected_without_consuming(value: object) -> None:
    service, fake, _ = make()
    cookie, state, _ = start(service)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state, response_issuer=value)
    assert not fake.calls
    check(service, cookie, state)


@pytest.mark.parametrize("value", [None, object(), "token", {}, 1, b"bytes"])
def test_noncontract_token_response_rejected_before_consumption(value: object) -> None:
    service, fake, _ = make()
    cookie, state, _ = start(service)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state, tokens=value)
    assert not fake.calls
    check(service, cookie, state)


def test_cross_browser_swap_is_rejected() -> None:
    service, fake, _ = make()
    first_cookie, first_state, _ = start(service)
    second_cookie, second_state, _ = start(service)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, first_cookie, second_state)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, second_cookie, first_state)
    assert not fake.calls
    check(service, first_cookie, first_state)
    check(service, second_cookie, second_state)
    assert len(fake.calls) == 2


def test_replay_is_rejected_across_concurrent_callbacks() -> None:
    service, fake, _ = make()
    cookie, state, _ = start(service)

    def redeem(_i: int) -> bool:
        try:
            check(service, cookie, state)
        except OidcAuthorizationBindingError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=16) as pool:
        successes = sum(pool.map(redeem, range(64)))
    assert successes == 1
    assert len(fake.calls) == 1


def test_replay_is_rejected_across_later_callbacks() -> None:
    service, fake, _ = make()
    cookie, state, _ = start(service)
    check(service, cookie, state)
    for _ in range(4):
        with pytest.raises(OidcAuthorizationBindingError):
            check(service, cookie, state)
    assert len(fake.calls) == 1


def test_expired_attempt_is_rejected_even_with_correct_cookie_and_state() -> None:
    service, fake, now = make(ttl_seconds=60, cookie_lifetime_seconds=60)
    cookie, state, _ = start(service)
    now[0] += 60.0
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state)
    assert not fake.calls


@pytest.mark.parametrize(
    "bad_time", [0, -1, True, "bad", None, math.nan, math.inf, -math.inf, 2**53]
)
def test_invalid_clock_cannot_issue_attempt(bad_time: object) -> None:
    service, _, clock = make()
    clock[0] = bad_time  # type: ignore[assignment]
    with pytest.raises(OidcAuthorizationBindingError):
        service.begin()


def test_invalid_clock_at_callback_consumes_no_valid_result() -> None:
    service, fake, clock = make()
    cookie, state, _ = start(service)
    clock[0] = math.nan
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state)
    assert not fake.calls
    clock[0] = NOW
    check(service, cookie, state)


@pytest.mark.parametrize(
    "override",
    [
        {"issuer": "https://evil.invalid"},
        {"audiences": ("other-client",)},
        {"audiences": "not-a-tuple"},
        {"subject": ""},
        {"algorithm": "HS256"},
    ],
)
def test_forged_verifier_result_cannot_be_returned(override: dict[str, object]) -> None:
    fake = FakeVerifier()
    fake.override = override
    service, _, _ = make(fake)
    cookie, state, _ = start(service)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state)
    assert len(fake.calls) == 1


def test_verifier_error_does_not_leak_credentials_or_allow_retry() -> None:
    fake = FakeVerifier()
    fake.reject = True
    service, _, _ = make(fake)
    cookie, state, _ = start(service)
    with pytest.raises(OidcAuthorizationBindingError) as exc:
        check(service, cookie, state)
    assert "synthetic-dangerous-token-secret" not in str(exc.value)
    assert cookie not in str(exc.value)
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state)
    assert len(fake.calls) == 1


@pytest.mark.parametrize("corruption", ["redirect", "code"])
def test_forged_internal_grant_is_rejected(
    monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    from asca.domain.identity import AuthorizationCodeGrant
    from asca.infrastructure import oidc_authorization_binding as binding_module

    service, fake, _ = make()
    cookie, state, _ = start(service)
    grant = AuthorizationCodeGrant(
        code="wrong-code" if corruption == "code" else "synthetic-code",
        nonce="syntheticNonce01234567890123456789012345",
        code_verifier="a" * 64,
        redirect_uri=(
            "https://evil.invalid/callback"
            if corruption == "redirect"
            else registration().redirect_uri
        ),
    )
    monkeypatch.setattr(
        binding_module,
        "finish_web_bff_callback",
        lambda *_args, **_kwargs: grant,
    )
    with pytest.raises(OidcAuthorizationBindingError, match="failed"):
        check(service, cookie, state)
    assert not fake.calls


def test_no_network_or_token_exchange_with_fake_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    service, _, _ = make()
    cookie, state, _ = start(service)

    def blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected network access")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    result = check(service, cookie, state)
    assert not isinstance(result, VerifiedIdentity)
    for name in ("authorization_code", "access_token", "session", "code_verifier"):
        assert not hasattr(result, name)


def test_revalidate_forged_registration_dataclass() -> None:
    fake = registration()
    object.__setattr__(fake, "redirect_uri", "http://attacker.invalid/callback")
    with pytest.raises(OidcAuthorizationBindingError):
        CernOidcReplaySafeBffBinding(fake, metadata())


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class MemoryResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.status = 200
        self.headers = Message()
        self.headers.add_header("Content-Type", "application/jwk-set+json")

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


class MemoryOpener:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.requests: list[Request] = []

    def open(self, request: Request, *, timeout: float) -> MemoryResponse:
        assert timeout == 5.0
        self.requests.append(request)
        return MemoryResponse(self.body)


def signed_token(
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    alg: str,
    nonce: str,
    *,
    subject: str = "real-crypto-synthetic-subject",
) -> tuple[str, bytes]:
    public = private.public_key().public_numbers()
    jwk: dict[str, object] = {"kid": "synthetic-signing-key", "use": "sig", "alg": alg}
    if isinstance(private, rsa.RSAPrivateKey):
        jwk.update(
            kty="RSA",
            n=b64(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
            e=b64(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")),
        )
    else:
        jwk.update(
            kty="EC",
            crv="P-256",
            x=b64(public.x.to_bytes(32, "big")),
            y=b64(public.y.to_bytes(32, "big")),
        )
    claims = {
        "iss": CERN_OIDC_ISSUER,
        "aud": CLIENT,
        "sub": subject,
        "nonce": nonce,
        "iat": int(NOW) - 10,
        "exp": int(NOW) + 200,
    }
    protected = b64(json.dumps({"alg": alg, "kid": "synthetic-signing-key"}).encode())
    payload = b64(json.dumps(claims, separators=(",", ":")).encode())
    signing = (protected + "." + payload).encode("ascii")
    if isinstance(private, rsa.RSAPrivateKey):
        pad = (
            padding.PKCS1v15()
            if alg == "RS256"
            else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        )
        sig = private.sign(signing, pad, hashes.SHA256())
    else:
        der = private.sign(signing, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing.decode("ascii") + "." + b64(sig), json.dumps({"keys": [jwk]}).encode()


@pytest.mark.parametrize("algorithm", ["RS256", "PS256", "ES256"])
def test_real_signatures_are_checked_against_consumed_flow_nonce(algorithm: str) -> None:
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    if algorithm == "ES256":
        private = ec.generate_private_key(ec.SECP256R1())
    else:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Use an initial offline binding to extract the generated nonce, then use
    # the same internally tracked authorization attempt for genuine crypto.
    request_holder = MemoryOpener(b"temporary")
    pipeline = CernOidcVerificationPipeline(
        fetcher=HttpsCernOidcJwksFetcher(opener=cast(OpenerDirector, request_holder))
    )
    service = CernOidcReplaySafeBffBinding(
        registration(), metadata(), pipeline=pipeline, clock=lambda: NOW
    )
    cookie, state, nonce = start(service)
    signed, keys = signed_token(private, algorithm, nonce)
    request_holder.body = keys
    result = check(service, cookie, state, tokens=tokens(signed))
    assert result.subject == "real-crypto-synthetic-subject"
    assert result.issuer == CERN_OIDC_ISSUER
    assert result.algorithm == algorithm
    assert result.audiences == (CLIENT,)
    assert len(request_holder.requests) == 1
    assert request_holder.requests[0].full_url == CERN_JWKS
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state, tokens=tokens(signed))
    assert len(request_holder.requests) == 1


@pytest.mark.parametrize("change", ["nonce", "audience", "subject"])
def test_signed_wrong_claims_fail_and_consume_callback(change: str) -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    opener = MemoryOpener(b"placeholder")
    pipeline = CernOidcVerificationPipeline(
        fetcher=HttpsCernOidcJwksFetcher(opener=cast(OpenerDirector, opener))
    )
    service = CernOidcReplaySafeBffBinding(
        registration(), metadata(), pipeline=pipeline, clock=lambda: NOW
    )
    cookie, state, nonce = start(service)
    alternative_nonce = "wrong_nonce_012345678901234567890123456"
    signed, body = signed_token(
        private,
        "RS256",
        alternative_nonce if change == "nonce" else nonce,
        subject="attack-subject" if change == "subject" else "real-crypto-synthetic-subject",
    )
    opener.body = body
    if change == "audience":
        # Change signed claims without updating the signature: invalid JWS.
        h, _p, s = signed.split(".")
        signed = h + "." + b64(b'{"iss":"https://evil.invalid"}') + "." + s
    if change == "subject":
        # A different, valid subject is not a role or permission grant.
        result = check(service, cookie, state, tokens=tokens(signed))
        assert result.subject == "attack-subject"
    else:
        with pytest.raises(OidcAuthorizationBindingError):
            check(service, cookie, state, tokens=tokens(signed))
    opener.body = body
    with pytest.raises(OidcAuthorizationBindingError):
        check(service, cookie, state, tokens=tokens(signed))
