"""Fail-closed, synthetic at_hash attacks: no tokens, browsers or network."""

from __future__ import annotations

import base64
import hashlib
import json
import socket

import pytest

from asca.application.oidc_claims import validate_untrusted_oidc_id_token_claims
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_claims import OidcClaimsError
from asca.domain.oidc_jws import SignatureCheckedUntrustedOidcPayload

NOW = 1_800_000_000
CLIENT = "synthetic-at-hash-client"
NONCE = "syntheticNonce_01234567890123456789012345"
ACCESS_TOKEN = "synthetic-access-token"
GOOD_HASH = (
    base64.urlsafe_b64encode(hashlib.sha256(ACCESS_TOKEN.encode()).digest()[:16])
    .rstrip(b"=")
    .decode("ascii")
)


def source(**fields: object) -> dict[str, object]:
    data: dict[str, object] = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "synthetic-subject",
        "aud": CLIENT,
        "nonce": NONCE,
        "iat": NOW - 10,
        "exp": NOW + 200,
        "at_hash": GOOD_HASH,
    }
    data.update(fields)
    return data


def validate(
    data: object = None,
    *,
    access_token: object = ACCESS_TOKEN,
    raw: bytes | None = None,
) -> object:
    payload = (
        raw if raw is not None else json.dumps(data if data is not None else source()).encode()
    )
    checked = SignatureCheckedUntrustedOidcPayload(
        algorithm="RS256", kid="synthetic", payload=payload
    )
    return validate_untrusted_oidc_id_token_claims(
        checked,
        expected_client_id=CLIENT,
        expected_nonce=NONCE,
        now=NOW,
        expected_access_token=access_token,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    "bad_hash",
    [
        None,
        False,
        123,
        [],
        {},
        "",
        "A" * 21,
        "A" * 23,
        "A" * 22,
        GOOD_HASH + "=",
        GOOD_HASH.lower(),
        GOOD_HASH + "\n",
        GOOD_HASH[:10] + "+" + GOOD_HASH[11:],
        "é" * 22,
    ],
)
def test_malformed_or_mismatched_signed_at_hash_is_rejected(bad_hash: object) -> None:
    with pytest.raises(OidcClaimsError):
        validate(source(at_hash=bad_hash))


@pytest.mark.parametrize(
    "bad_token",
    [None, "", False, 1, "é", "space in token", "with\nnewline", "a" * 16_385],
)
def test_at_hash_requires_a_bounded_ascii_token_from_the_same_response(
    bad_token: object,
) -> None:
    with pytest.raises(OidcClaimsError):
        validate(source(), access_token=bad_token)


@pytest.mark.parametrize("claim", ["c_hash", "s_hash"])
def test_unimplemented_hash_claims_remain_forbidden(claim: str) -> None:
    with pytest.raises(OidcClaimsError, match="unsupported token-binding"):
        validate(source(**{claim: GOOD_HASH}))


def test_at_hash_key_duplication_fails_closed_even_if_both_values_match() -> None:
    raw = json.dumps(source(), separators=(",", ":")).encode("ascii")
    duplicate = raw[:-1] + b',"at_hash":"' + GOOD_HASH.encode() + b'"}'
    with pytest.raises(OidcClaimsError, match="Duplicate"):
        validate(raw=duplicate)


def test_bound_hash_never_bypasses_issuer_audience_or_nonce_checks() -> None:
    for changes in (
        {"iss": "https://example.invalid"},
        {"aud": "other-client"},
        {"nonce": "wrongNonce_01234567890123456789012345"},
        {"exp": NOW - 1000},
    ):
        with pytest.raises(OidcClaimsError):
            validate(source(**changes))


def test_no_network_or_sensitive_exception_text(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Claims validation attempted an unexpected network call")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    with pytest.raises(OidcClaimsError) as raised:
        validate(source(), access_token="attacker-token-that-must-not-leak")
    assert "attacker-token-that-must-not-leak" not in str(raised.value)
    assert ACCESS_TOKEN not in repr(raised.value)


def test_signed_at_hash_may_not_grant_roles_or_a_principal() -> None:
    result = validate(source(roles=["admin"], cern_roles=["admin"]))
    for attribute in ("roles", "cern_roles", "permissions", "identity", "principal", "session"):
        assert not hasattr(result, attribute)
