"""Adversarial OIDC ID-token claim checks: no live keys, JWTs or CERN network."""

import json
import socket
from dataclasses import replace

import pytest

from asca.application.oidc_claims import validate_untrusted_oidc_id_token_claims
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_claims import OidcClaimsError
from asca.domain.oidc_jws import SignatureCheckedUntrustedOidcPayload

NOW = 1_800_000_000
CLIENT = "test-cern-client"
NONCE = "syntheticNonce0123456789abcdefghij_123456"


def source(**kwargs: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "example-subject",
        "aud": CLIENT,
        "nonce": NONCE,
        "exp": NOW + 300,
        "iat": NOW - 30,
    }
    doc.update(kwargs)
    return doc


def checked(raw: bytes) -> SignatureCheckedUntrustedOidcPayload:
    return SignatureCheckedUntrustedOidcPayload(algorithm="RS256", kid="synthetic", payload=raw)


def validate(doc: object = None, *, raw: bytes | None = None, **opts: object) -> object:
    if raw is None:
        raw = json.dumps(source() if doc is None else doc, separators=(",", ":")).encode()
    options: dict[str, object] = {"expected_client_id": CLIENT, "expected_nonce": NONCE, "now": NOW}
    options.update(opts)
    return validate_untrusted_oidc_id_token_claims(
        checked(raw),
        **options,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not-json",
        b"{",
        b"[]",
        b"null",
        b"true",
        b"123",
        b'"string"',
        b"{} {}",
        b'[{"iss":"x"}]',
        b"\xff",
        b"\xef\xbb\xbf" + b"{}",
        b' {"exp":NaN}',
        b' {"exp":Infinity}',
        b' {"exp":-Infinity}',
        b' {"iss": "x",}',
        b' {"name":"escaped\nnewline"}',
        b"[" * 200 + b"0" + b"]" * 200,
        b"x" * 16_385,
    ],
)
def test_invalid_json_or_bounds_rejected(raw: bytes) -> None:
    with pytest.raises(OidcClaimsError):
        validate(raw=raw)


@pytest.mark.parametrize(
    "extra",
    [
        b'"iss":"https://evil.invalid"',
        b'"nonce":"bad"',
        b'"exp":1234',
        b'"extension":{"x":1,"x":2}',
        b'"extension":[{"a":1,"a":2}]',
    ],
)
def test_duplicate_members_rejected_at_all_depths(extra: bytes) -> None:
    baseline = json.dumps(source(), separators=(",", ":")).encode()
    with pytest.raises(OidcClaimsError, match="Duplicate"):
        validate(raw=baseline[:-1] + b"," + extra + b"}")


@pytest.mark.parametrize(
    "field,value",
    [
        ("iss", "https://evil.invalid"),
        ("iss", "http://auth.cern.ch/auth/realms/cern"),
        ("iss", CERN_OIDC_ISSUER + "/"),
        ("iss", CERN_OIDC_ISSUER.upper()),
        ("iss", "é"),
        ("iss", 12),
        ("iss", None),
        ("sub", ""),
        ("sub", "contains space"),
        ("sub", "line\nbreak"),
        ("sub", "é"),
        ("sub", "x" * 256),
        ("sub", 42),
        ("sub", None),
        ("nonce", ""),
        ("nonce", "changed-nonce-01234567890123456789"),
        ("nonce", "short"),
        ("nonce", "é"),
        ("nonce", None),
        ("nonce", 42),
        ("aud", ""),
        ("aud", "wrong-client"),
        ("aud", []),
        ("aud", [CLIENT, CLIENT]),
        ("aud", [CLIENT, 42]),
        ("aud", [CLIENT, {}]),
        ("aud", 1),
        ("aud", None),
        ("aud", True),
        ("aud", [CLIENT] + [f"c{i}" for i in range(8)]),
        ("azp", "evil-client"),
        ("azp", "é"),
        ("azp", None),
        ("azp", 123),
    ],
)
def test_bad_identity_or_audience_claim_rejected(field: str, value: object) -> None:
    with pytest.raises(OidcClaimsError):
        validate(source(**{field: value}))


def test_multi_audience_needs_azp_even_with_allowlist() -> None:
    with pytest.raises(OidcClaimsError, match="authorized party"):
        validate(source(aud=[CLIENT, "other"]), trusted_additional_audiences=("other",))


@pytest.mark.parametrize(
    "audiences,azp",
    [
        ([CLIENT, "bad"], CLIENT),
        (["bad", "other"], CLIENT),
        ([CLIENT, "other"], "evil"),
        ([CLIENT, "other"], None),
    ],
)
def test_multi_audience_bypass_rejected(audiences: list[str], azp: object) -> None:
    with pytest.raises(OidcClaimsError):
        validate(source(aud=audiences, azp=azp), trusted_additional_audiences=("other",))


@pytest.mark.parametrize(
    "field,value",
    [
        ("exp", 0),
        ("exp", -1),
        ("exp", True),
        ("exp", 1.5),
        ("exp", "1800000300"),
        ("exp", None),
        ("exp", NOW - 500),
        ("exp", NOW + 86402),
        ("exp", 2**53),
        ("iat", 0),
        ("iat", -3),
        ("iat", False),
        ("iat", 1.5),
        ("iat", "1800000000"),
        ("iat", None),
        ("iat", NOW + 121),
        ("iat", NOW - 100_000),
        ("iat", 2**53),
        ("nbf", 0),
        ("nbf", False),
        ("nbf", 1.5),
        ("nbf", "1800000000"),
        ("nbf", None),
        ("nbf", NOW + 121),
        ("nbf", NOW + 350),
        ("auth_time", True),
        ("auth_time", 1.5),
        ("auth_time", -1),
        ("auth_time", None),
        ("auth_time", NOW + 121),
    ],
)
def test_bad_numeric_date_rejected(field: str, value: object) -> None:
    with pytest.raises(OidcClaimsError):
        validate(source(**{field: value}))


def test_temporally_inconsistent_order_rejected() -> None:
    for altered in (
        source(iat=NOW + 100, exp=NOW + 20),
        source(iat=NOW + 40, exp=NOW + 40),
        source(nbf=NOW + 300, exp=NOW + 300),
    ):
        with pytest.raises(OidcClaimsError):
            validate(altered)


@pytest.mark.parametrize("hash_claim", ["at_hash", "c_hash", "s_hash"])
def test_unbound_hash_claims_fail_closed(hash_claim: str) -> None:
    with pytest.raises(OidcClaimsError, match="unsupported token-binding"):
        validate(source(**{hash_claim: "synthetic-hash"}))


@pytest.mark.parametrize(
    "change",
    [
        {"expected_client_id": ""},
        {"expected_client_id": "other-client"},
        {"expected_client_id": "bad client"},
        {"expected_client_id": "é"},
        {"expected_client_id": 42},
        {"expected_nonce": ""},
        {"expected_nonce": "wrong_nonce_0123456789012345678"},
        {"expected_nonce": "é"},
        {"expected_nonce": 42},
        {"now": 0},
        {"now": True},
        {"now": 3.5},
        {"now": None},
        {"now": 2**53},
        {"clock_skew_seconds": -1},
        {"clock_skew_seconds": 121},
        {"clock_skew_seconds": True},
        {"clock_skew_seconds": 1.5},
        {"max_token_lifetime_seconds": 0},
        {"max_token_lifetime_seconds": 86401},
        {"max_token_lifetime_seconds": True},
        {"max_token_lifetime_seconds": None},
        {"trusted_additional_audiences": ["service"]},
        {"trusted_additional_audiences": ("service", "service")},
        {"trusted_additional_audiences": (CLIENT,)},
        {"trusted_additional_audiences": ("bad space",)},
        {"trusted_additional_audiences": ("svc",) * 8},
        {"trusted_additional_audiences": (None,)},
        {"trusted_additional_audiences": ({},)},
    ],
)
def test_invalid_or_untrusted_flow_configuration_rejected(change: dict[str, object]) -> None:
    with pytest.raises(OidcClaimsError):
        validate(source(), **change)


@pytest.mark.parametrize("object_value", [None, "raw", b"raw", {}, 3])
def test_untrusted_wrapper_type_rejected(object_value: object) -> None:
    with pytest.raises(OidcClaimsError):
        validate_untrusted_oidc_id_token_claims(
            object_value, expected_client_id=CLIENT, expected_nonce=NONCE, now=NOW
        )  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "change",
    [
        {"algorithm": "none"},
        {"algorithm": "HS256"},
        {"algorithm": "ES384"},
        {"algorithm": None},
        {"kid": ""},
        {"kid": "../path"},
        {"kid": "é"},
        {"kid": 123},
        {"payload": "text-not-bytes"},
        {"payload": None},
    ],
)
def test_forged_signature_container_rejected(change: dict[str, object]) -> None:
    document = json.dumps(source()).encode()
    with pytest.raises(OidcClaimsError):
        validate_untrusted_oidc_id_token_claims(
            replace(checked(document), **change),
            expected_client_id=CLIENT,
            expected_nonce=NONCE,
            now=NOW,
        )


def test_no_network_and_no_secret_error_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("OIDC claims validation attempted network")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    secret = "synthetic_secret_nonce_0123456789012"
    with pytest.raises(OidcClaimsError) as exc:
        validate(source(nonce=secret))
    assert secret not in str(exc.value)
    assert secret not in repr(exc.value)


def test_unknown_extension_cannot_be_promoted_to_permissions() -> None:
    result = validate(source(email="admin@example.invalid", email_verified=True, roles=["admin"]))
    for name in ("email", "email_verified", "roles", "permissions", "identity"):
        assert not hasattr(result, name)
