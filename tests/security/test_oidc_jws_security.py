"""Adversarial, offline JWS signature checks with synthetic ephemeral RSA/EC keys."""

import base64
import json
import socket
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI, parse_cern_public_jwks
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jws import OidcJwsError
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.infrastructure.oidc_jws import verify_untrusted_oidc_jws_signature

_P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def private_rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def synthetic_jwks(private_rsa: rsa.RSAPrivateKey):
    public = private_rsa.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": "synthetic",
        "use": "sig",
        "alg": "RS256",
        "n": b64(public.n.to_bytes(256, "big")),
        "e": b64(public.e.to_bytes(3, "big")),
    }
    meta = OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_JWKS_URI,
        approved_id_token_algorithms=("RS256", "PS256", "ES256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )
    return parse_cern_public_jwks(json.dumps({"keys": [jwk]}).encode(), meta)


def tokens(jws: str) -> ParsedUnverifiedOidcTokenResponse:
    return ParsedUnverifiedOidcTokenResponse(
        access_token="synthetic",
        id_token=jws,
        token_type="Bearer",
        expires_in=1,
        refresh_token=None,
        scope=None,
    )


def compact(
    header: object = None,
    *,
    raw_header: bytes | None = None,
    body: bytes = b"{}",
    signature: bytes = b"x" * 256,
) -> str:
    value = header if header is not None else {"alg": "RS256", "kid": "synthetic"}
    protected = (
        raw_header
        if raw_header is not None
        else json.dumps(value, separators=(",", ":")).encode("utf-8")
    )
    return b64(protected) + "." + b64(body) + "." + b64(signature)


def reject(token: str, keys: object) -> None:
    with pytest.raises(OidcJwsError) as captured:
        verify_untrusted_oidc_jws_signature(tokens(token), keys)
    if len(token) >= 24:
        assert token not in str(captured.value)
    assert "synthetic-access-secret" not in str(captured.value)


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none", "kid": "synthetic"},
        {"alg": "HS256", "kid": "synthetic"},
        {"alg": "RS384", "kid": "synthetic"},
        {"alg": "rs256", "kid": "synthetic"},
        {"alg": "RS256"},
        {"kid": "synthetic"},
        {"alg": 123, "kid": "synthetic"},
        {"alg": True, "kid": "synthetic"},
        {"alg": "RS256", "kid": None},
        {"alg": "RS256", "kid": "../traversal"},
        {"alg": "RS256", "kid": "é"},
        {"alg": "RS256", "kid": "a" * 129},
        {"alg": "RS256", "kid": "synthetic", "jku": "https://evil.invalid/keys"},
        {"alg": "RS256", "kid": "synthetic", "x5u": "https://evil.invalid/x"},
        {"alg": "RS256", "kid": "synthetic", "jwk": {"kty": "RSA"}},
        {"alg": "RS256", "kid": "synthetic", "crit": ["b64"]},
        {"alg": "RS256", "kid": "synthetic", "b64": False},
        {"alg": "RS256", "kid": "synthetic", "zip": "DEF"},
        {"alg": "RS256", "kid": "synthetic", "cty": "JWT"},
        {"alg": "RS256", "kid": "synthetic", "enc": "A256GCM"},
        {"alg": "RS256", "kid": "synthetic", "x5c": ["test"]},
        {"alg": "RS256", "kid": "synthetic", "x5t": "fake"},
        {"alg": "RS256", "kid": "synthetic", "extra": True},
        {"alg": "RS256", "kid": "synthetic", "typ": "JOSE"},
        {"alg": "RS256", "kid": "synthetic", "typ": "jwt"},
        {"alg": "RS256", "kid": "synthetic", "typ": None},
        {"alg": "RS256", "kid": "synthetic", "typ": 42},
    ],
)
def test_disallowed_protected_headers_rejected(header: object, synthetic_jwks: object) -> None:
    reject(compact(header), synthetic_jwks)


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b"{}",
        b"[]",
        b"null",
        b"true",
        b"0",
        b"{",
        b' {"alg":"RS256","kid":"synthetic","alg":"none"}',
        b'{"alg":"RS256","kid":"synthetic","nested":{"a":1,"a":2}}',
        b'{"alg":"RS256","kid":"synthetic","p":NaN}',
        b'{"alg":"RS256","kid":"synthetic","p":Infinity}',
        b'"string"',
        b"\xff",
        b"\xef\xbb\xbf" + b'{"alg":"RS256","kid":"synthetic"}',
        b"[" * 250 + b"0" + b"]" * 250,
    ],
)
def test_malformed_or_ambiguous_header_rejected(raw: bytes, synthetic_jwks: object) -> None:
    reject(compact(raw_header=raw), synthetic_jwks)


@pytest.mark.parametrize(
    "broken",
    [
        "",
        "a",
        ".",
        "..",
        "a.b",
        "a.b.c.d",
        "a.b.c.d.e",
        "x..y",
        "..a",
        "a.b.",
        "a.b.c=",
        "a.b.c%",
        "a.b.+",
        "a.b.c/d",
        "a.b.é",
        "a.b.c\n",
        "a" * 32769,
        "a." + "a" * 20000 + ".c",
        "a" * 4097 + ".a.c",
    ],
)
def test_invalid_compact_format_rejected(broken: str, synthetic_jwks: object) -> None:
    reject(broken, synthetic_jwks)


@pytest.mark.parametrize("raw_signature", [b"", b"a", b"x" * 255, b"x" * 257, b"x" * 1025])
def test_invalid_rsa_signature_length_rejected(
    raw_signature: bytes, synthetic_jwks: object
) -> None:
    reject(compact(signature=raw_signature), synthetic_jwks)


@pytest.mark.parametrize("encoded", ["AAAA=", "A", "AAAA*", "AAA+", "AAAA%", "AQ", "a" * 2048])
def test_invalid_signature_encoding_rejected(encoded: str, synthetic_jwks: object) -> None:
    h, p, _ = compact().split(".")
    reject(h + "." + p + "." + encoded, synthetic_jwks)


def test_wrong_key_identifier_fails_closed(synthetic_jwks: object) -> None:
    reject(compact({"alg": "RS256", "kid": "not-registered"}), synthetic_jwks)


def test_key_algorithm_confusion_rejected(synthetic_jwks: object) -> None:
    reject(compact({"alg": "PS256", "kid": "synthetic"}), synthetic_jwks)
    reject(compact({"alg": "ES256", "kid": "synthetic"}, signature=b"a" * 64), synthetic_jwks)


def test_forged_untrusted_jwks_not_promoted(synthetic_jwks: object) -> None:
    reject(compact(), replace(synthetic_jwks, issuer="https://evil.invalid"))
    reject(compact(), replace(synthetic_jwks, jwks_uri="https://evil.invalid"))


@pytest.mark.parametrize("value", [None, 123, b"raw", object()])
def test_wrong_token_contract_rejected(value: object, synthetic_jwks: object) -> None:
    with pytest.raises(OidcJwsError):
        verify_untrusted_oidc_jws_signature(value, synthetic_jwks)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [None, 123, b"raw", object()])
def test_wrong_jwks_contract_rejected(value: object) -> None:
    with pytest.raises(OidcJwsError):
        verify_untrusted_oidc_jws_signature(tokens(compact()), value)  # type: ignore[arg-type]


def test_forged_id_token_field_rejected(synthetic_jwks: object) -> None:
    with pytest.raises(OidcJwsError):
        verify_untrusted_oidc_jws_signature(
            replace(tokens(compact()), id_token=b"not-string"), synthetic_jwks
        )  # type: ignore[arg-type]


def test_rejects_untrusted_claims_without_parsing_them(synthetic_jwks: object) -> None:
    reject(compact(body=b'{"is_admin":true,"roles":["cern-admin"]}'), synthetic_jwks)


def test_no_network_and_no_credential_leaks(
    monkeypatch: pytest.MonkeyPatch, synthetic_jwks: object
) -> None:
    def blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("JWS signature checker attempted network")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    reject(compact(), synthetic_jwks)


def test_wrong_ecdsa_signature_range_rejected() -> None:
    from asca.infrastructure.oidc_jws import _verify_signature

    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()
    for raw in (
        b"\x00" * 64,
        b"\x00" * 32 + b"\x01" * 32,
        _P256_ORDER.to_bytes(32, "big") + b"\x01" * 32,
        b"\x01" * 32 + _P256_ORDER.to_bytes(32, "big"),
    ):
        with pytest.raises(OidcJwsError, match="format"):
            _verify_signature("ES256", public, raw, b"test")
    with pytest.raises(OidcJwsError, match="format"):
        _verify_signature("ES256", public, b"\x01" * 63, b"test")


def test_ecdsa_der_signature_is_not_raw_jws() -> None:
    from cryptography.hazmat.primitives import hashes

    from asca.infrastructure.oidc_jws import _verify_signature

    private = ec.generate_private_key(ec.SECP256R1())
    der = private.sign(b"signed", ec.ECDSA(hashes.SHA256()))
    with pytest.raises(OidcJwsError):
        _verify_signature("ES256", private.public_key(), der, b"signed")


def test_invalid_alg_to_key_matching_rejected() -> None:
    from asca.infrastructure.oidc_jws import _verify_signature

    private = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(OidcJwsError):
        _verify_signature("RS256", private.public_key(), b"x" * 256, b"a")
    with pytest.raises(OidcJwsError):
        _verify_signature("PS256", private.public_key(), b"x" * 256, b"a")
    with pytest.raises(OidcJwsError):
        _verify_signature("none", private.public_key(), b"x" * 64, b"a")


@pytest.mark.parametrize(
    "override",
    [
        {"algorithm": "PS256"},
        {"kid": "not-the-signed-kid"},
        {"key_type": "oct"},
    ],
)
def test_constructed_key_identity_is_rechecked(
    monkeypatch: pytest.MonkeyPatch,
    private_rsa: rsa.RSAPrivateKey,
    synthetic_jwks: object,
    override: dict[str, str],
) -> None:
    from asca.infrastructure import oidc_jws
    from asca.infrastructure.oidc_crypto_key import ConstructedUnverifiedOidcPublicKey

    original = ConstructedUnverifiedOidcPublicKey(
        kid="synthetic",
        algorithm="RS256",
        key_type="RSA",
        public_key=private_rsa.public_key(),
    )
    monkeypatch.setattr(
        oidc_jws,
        "construct_cern_oidc_public_key",
        lambda *_args, **_kwargs: replace(original, **override),
    )
    reject(compact(), synthetic_jwks)
