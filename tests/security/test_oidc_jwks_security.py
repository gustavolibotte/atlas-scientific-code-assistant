"""Adversarial JWKS parser tests with synthetic public parameters and no CERN network."""

import base64
import json
import socket
from dataclasses import replace

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import (
    CERN_OIDC_JWKS_URI,
    parse_cern_public_jwks,
    select_cern_public_jwk,
)
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks import OidcJwksError


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def rsa_key(*, kid: str = "rsa-key", algorithm: str = "RS256") -> dict[str, object]:
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": algorithm,
        "n": encoded(b"\x80" + b"\x01" * 255),
        "e": encoded(b"\x01\x00\x01"),
    }


def ec_key() -> dict[str, object]:
    return {
        "kty": "EC",
        "kid": "ec-key",
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "x": encoded(b"\x01" * 32),
        "y": encoded(b"\x02" * 32),
    }


def provider() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_JWKS_URI,
        approved_id_token_algorithms=("RS256", "PS256", "ES256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def payload(*keys: dict[str, object]) -> bytes:
    return json.dumps({"keys": keys}, separators=(",", ":")).encode("utf-8")


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"{}",
        b"null",
        b"true",
        b"123",
        b"not-json",
        b'[{"keys":[]}]',
        b'{"keys":null}',
        b'{"keys":{}}',
        b'{"keys":[]}',
        b'{"keys":[], "keys":[]}',
        b'{"keys":[{}]}',
        b'{"keys":[1]}',
        b'{"keys":["x"]}',
        b'{"keys":[], "extra":true}',
        b'{"keys":[], "extra":{"x":1,"x":2}}',
        b"\xef\xbb\xbf" + payload(rsa_key()),
        b"\xff" + payload(rsa_key()),
        b'{"keys":NaN}',
        b'{"keys":Infinity}',
        b'"unterminated',
        b"[" * 200 + b"0" + b"]" * 200,
        b"x" * 262_145,
    ],
)
def test_malformed_or_ambiguous_jwks_documents_fail_closed(raw: bytes) -> None:
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(raw, provider())


@pytest.mark.parametrize(
    "changed",
    [
        {"issuer": "https://evil.example.org"},
        {"jwks_uri": "https://evil.example.org/keys"},
        {"jwks_uri": CERN_OIDC_JWKS_URI + "?next=1"},
        {"jwks_uri": CERN_OIDC_JWKS_URI + "#frag"},
        {"jwks_uri": CERN_OIDC_ISSUER + "/other"},
        {"approved_id_token_algorithms": ()},
        {"approved_id_token_algorithms": ("HS256",)},
        {"approved_id_token_algorithms": ("RS256", "HS256")},
        {"supports_authorization_code": False},
        {"supports_pkce_s256": False},
    ],
)
def test_untrusted_provider_metadata_is_rejected(changed: dict[str, object]) -> None:
    with pytest.raises(OidcJwksError, match="metadata"):
        parse_cern_public_jwks(payload(rsa_key()), replace(provider(), **changed))


def test_wrong_metadata_object_type_is_rejected() -> None:
    for value in (None, {}, "cern", object()):
        with pytest.raises(OidcJwksError):
            parse_cern_public_jwks(payload(rsa_key()), value)  # type: ignore[arg-type]


def test_wrong_document_input_type_is_rejected() -> None:
    for value in (None, {}, "text", bytearray(payload(rsa_key()))):
        with pytest.raises(OidcJwksError):
            parse_cern_public_jwks(value, provider())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "private", ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "x5u", "jku", "jwk"]
)
def test_private_or_remote_reference_key_material_is_rejected(private: str) -> None:
    key = rsa_key()
    key[private] = "secret-do-not-leak"
    with pytest.raises(OidcJwksError) as captured:
        parse_cern_public_jwks(payload(key), provider())
    assert "secret-do-not-leak" not in str(captured.value)
    assert "secret-do-not-leak" not in repr(captured.value)


@pytest.mark.parametrize("private", ["d", "k", "x5u", "jku"])
def test_ignored_encryption_keys_cannot_hide_private_material(private: str) -> None:
    key = rsa_key(kid="enc-key")
    key.update(alg="RSA-OAEP", use="enc")
    key[private] = "private"
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(rsa_key(), key), provider())


@pytest.mark.parametrize(
    "operations", [["sign"], ["sign", "verify"], ["verify", "verify"], [], "verify", [1]]
)
def test_incompatible_key_operations_rejected(operations: object) -> None:
    key = rsa_key()
    key["key_ops"] = operations
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(key), provider())


@pytest.mark.parametrize("field", ["kid", "alg", "kty", "use"])
def test_missing_required_key_declarations_rejected(field: str) -> None:
    key = rsa_key()
    del key[field]
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(key), provider())


@pytest.mark.parametrize("kid", ["", "../path", "space here", "a" * 129, "é", "with\nline"])
def test_invalid_kid_rejected(kid: str) -> None:
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(rsa_key(kid=kid)), provider())


def test_duplicate_kid_rejected_even_for_ignored_key() -> None:
    ignored = rsa_key(kid="rsa-key")
    ignored.update(alg="RSA-OAEP", use="enc")
    with pytest.raises(OidcJwksError, match="ambiguous"):
        parse_cern_public_jwks(payload(rsa_key(), ignored), provider())


def test_duplicate_json_member_inside_key_is_rejected() -> None:
    raw = payload(rsa_key())
    raw = raw.replace(b'"use":"sig"', b'"use":"sig","use":"sig"')
    with pytest.raises(OidcJwksError, match="duplicate"):
        parse_cern_public_jwks(raw, provider())


@pytest.mark.parametrize(
    "modulus",
    [
        "",
        "=",
        "a%20b",
        "++A",
        "é",
        "a",
        "a" * 1400,
        encoded(b"\x01" + b"\x01" * 255),
        encoded(b"\x00" + b"\x80" + b"\x01" * 255),
        encoded(b"\x80" + b"\x01" * 1024),
        encoded(b"\x80" + b"\x01" * 127),
        encoded(b"\x80" + b"\x01" * 255) + "=",
    ],
)
def test_invalid_rsa_modulus_rejected(modulus: str) -> None:
    key = rsa_key()
    key["n"] = modulus
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(key), provider())


@pytest.mark.parametrize(
    "exponent",
    [
        "",
        "@@@",
        encoded(b"\x02"),
        encoded(b"\x01"),
        encoded(b"\x00\x03"),
        encoded(b"\x01\x00\x00\x00\x01"),
        encoded(b"\x00"),
        "AQAB=",
        "AQAF%",
    ],
)
def test_invalid_rsa_exponent_rejected(exponent: str) -> None:
    key = rsa_key()
    key["e"] = exponent
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(key), provider())


@pytest.mark.parametrize(
    "changes",
    [
        {"alg": "ES256"},
        {"kty": "EC"},
        {"alg": "PS256", "kty": "EC"},
        {"kty": "oct", "alg": "RS256"},
    ],
)
def test_key_type_algorithm_confusion_rejected(changes: dict[str, object]) -> None:
    key = rsa_key()
    key.update(changes)
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(key), provider())


@pytest.mark.parametrize(
    "change",
    [
        {"crv": "P-384"},
        {"crv": "secp256k1"},
        {"crv": "P-521"},
        {"x": ""},
        {"x": encoded(b"\x01" * 31)},
        {"y": encoded(b"\x01" * 33)},
        {"y": encoded(b"\x01" * 32) + "="},
        {"x": "not base64"},
    ],
)
def test_invalid_ec_parameters_rejected(change: dict[str, object]) -> None:
    key = ec_key()
    key.update(change)
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(key), provider())


def test_too_many_keys_are_rejected_before_iteration() -> None:
    keys = [rsa_key(kid=f"k-{i}") for i in range(65)]
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(*keys), provider())


@pytest.mark.parametrize(
    "kid,algorithm",
    [("rsa-key", "none"), ("wrong", "RS256"), ("rsa-key", "HS256")],
)
def test_unapproved_key_selection_never_returns_material(kid: str, algorithm: str) -> None:
    jwks = parse_cern_public_jwks(payload(rsa_key()), provider())
    with pytest.raises(OidcJwksError) as error:
        select_cern_public_jwk(jwks, kid=kid, algorithm=algorithm)
    assert "secret" not in str(error.value)


def test_invalid_jwks_container_is_rejected_before_selection() -> None:
    for jwks in (None, "not-jwks", {}):
        with pytest.raises(OidcJwksError):
            select_cern_public_jwk(jwks, kid="rsa-key", algorithm="RS256")  # type: ignore[arg-type]


def test_forged_wrong_jwks_issuer_or_uri_is_rejected() -> None:
    jwks = parse_cern_public_jwks(payload(rsa_key()), provider())
    for modified in (
        replace(jwks, issuer="https://evil.example"),
        replace(jwks, jwks_uri="https://evil.example/keys"),
        replace(jwks, approved_algorithms=("HS256",)),
    ):
        with pytest.raises(OidcJwksError):
            select_cern_public_jwk(modified, kid="rsa-key", algorithm="RS256")


def test_network_calls_are_not_possible_during_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("JWKS parser attempted external network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    jwks = parse_cern_public_jwks(payload(rsa_key()), provider())
    assert select_cern_public_jwk(jwks, kid="rsa-key", algorithm="RS256").key_type == "RSA"


def test_synthetic_ec_key_is_not_claimed_cryptographically_valid() -> None:
    jwks = parse_cern_public_jwks(payload(ec_key()), provider())
    assert not hasattr(jwks, "verified_signature")
    assert not hasattr(jwks.keys[0], "public_key_object")


def test_extra_nested_provider_extensions_never_grant_authority() -> None:
    key = rsa_key()
    key["extension"] = {"is_admin": True, "permissions": ["everything"]}
    jwks = parse_cern_public_jwks(payload(key), provider())
    assert not hasattr(jwks.keys[0], "permissions")
    assert not hasattr(jwks.keys[0], "is_admin")


def test_unknown_top_level_extensions_cannot_grant_authority() -> None:
    document = json.loads(payload(rsa_key()))
    document["is_admin"] = True
    document["permissions"] = ["superuser"]
    jwks = parse_cern_public_jwks(json.dumps(document).encode("ascii"), provider())
    assert len(jwks.keys) == 1
    assert not hasattr(jwks, "is_admin")
    assert not hasattr(jwks, "permissions")


@pytest.mark.parametrize("field", ["crv", "x", "y"])
def test_rsa_key_with_conflicting_ec_parameters_is_rejected(field: str) -> None:
    key = rsa_key()
    key[field] = "fake"
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(key), provider())


@pytest.mark.parametrize("field", ["n", "e"])
def test_ec_key_with_conflicting_rsa_parameters_is_rejected(field: str) -> None:
    key = ec_key()
    key[field] = "fake"
    with pytest.raises(OidcJwksError):
        parse_cern_public_jwks(payload(key), provider())
