"""OIDC Authorization Code at_hash binding using synthetic signed-claim containers."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from asca.application.oidc_claims import validate_untrusted_oidc_id_token_claims
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_claims import ClaimsCheckedUntrustedOidcPayload, OidcClaimsError
from asca.domain.oidc_jws import SignatureCheckedUntrustedOidcPayload

NOW = 1_800_000_000
CLIENT = "synthetic-cern-at-hash-client"
NONCE = "syntheticNonce_01234567890123456789012345"
ACCESS_TOKEN = "synthetic-access-token"


def token_hash(value: str) -> str:
    """Reference OIDC leftmost-half SHA-256 calculation (test-only oracle)."""
    return (
        base64.urlsafe_b64encode(hashlib.sha256(value.encode("ascii")).digest()[:16])
        .rstrip(b"=")
        .decode("ascii")
    )


def claims(**updates: object) -> dict[str, object]:
    data: dict[str, object] = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "synthetic-subject",
        "aud": CLIENT,
        "nonce": NONCE,
        "iat": NOW - 30,
        "exp": NOW + 300,
    }
    data.update(updates)
    return data


def validate(
    data: dict[str, object], *, algorithm: str = "RS256", access_token: str | None = None
) -> ClaimsCheckedUntrustedOidcPayload:
    checked = SignatureCheckedUntrustedOidcPayload(
        algorithm=algorithm,
        kid="synthetic-key",
        payload=json.dumps(data, separators=(",", ":")).encode("ascii"),
    )
    return validate_untrusted_oidc_id_token_claims(
        checked,
        expected_client_id=CLIENT,
        expected_nonce=NONCE,
        now=NOW,
        expected_access_token=access_token,
    )


@pytest.mark.parametrize("algorithm", ["RS256", "PS256", "ES256"])
def test_valid_at_hash_bound_to_access_token_for_all_approved_algs(algorithm: str) -> None:
    result = validate(
        claims(at_hash=token_hash(ACCESS_TOKEN)),
        algorithm=algorithm,
        access_token=ACCESS_TOKEN,
    )
    assert result.subject == "synthetic-subject"
    assert result.algorithm == algorithm
    assert result.audiences == (CLIENT,)
    assert not hasattr(result, "at_hash")
    assert not hasattr(result, "access_token")
    assert not hasattr(result, "identity")
    assert not hasattr(result, "session")
    assert ACCESS_TOKEN not in repr(result)
    assert token_hash(ACCESS_TOKEN) not in repr(result)


def test_hash_absent_remains_compatible_with_existing_strict_claims_check() -> None:
    result = validate(claims())
    assert result.subject == "synthetic-subject"


def test_hash_absent_requires_no_access_token_in_direct_untrusted_claims_check() -> None:
    assert validate(claims(), access_token=None).subject == "synthetic-subject"


def test_correct_token_hash_has_22_unpadded_base64url_chars() -> None:
    assert token_hash(ACCESS_TOKEN) == "F30iRba6HrejUQBwrzD-Rg"
    assert len(token_hash(ACCESS_TOKEN)) == 22
    assert "=" not in token_hash(ACCESS_TOKEN)


def test_at_hash_must_not_be_accepted_without_an_explicit_bound_token() -> None:
    with pytest.raises(OidcClaimsError):
        validate(claims(at_hash=token_hash(ACCESS_TOKEN)))


def test_swapped_token_is_rejected_even_when_id_token_claims_are_valid() -> None:
    with pytest.raises(OidcClaimsError):
        validate(
            claims(at_hash=token_hash(ACCESS_TOKEN)),
            access_token="different-synthetic-access-token",
        )
