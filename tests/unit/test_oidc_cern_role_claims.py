"""Offline CERN application role observation: no identity or session grants."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import FrozenInstanceError

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_role_claims import inspect_untrusted_cern_application_role
from asca.domain.oidc_jws import SignatureCheckedUntrustedOidcPayload
from asca.domain.oidc_role_claims import OidcRoleClaimsError, UntrustedCernRoleObservation

NOW = 1_800_000_000
CLIENT = "asca-glibotte-dev"
ROLE = "asca-developer"
NONCE = "synthetic_nonce_01234567890123456789012"
TOKEN = "synthetic-access-token"  # Never use real tokens or accounts in tests.


def document(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "synthetic-subject",
        "aud": CLIENT,
        "nonce": NONCE,
        "iat": NOW - 30,
        "exp": NOW + 300,
    }
    result.update(changes)
    return result


def checked(claims: object | None = None, *, raw: bytes | None = None):
    payload = raw
    if payload is None:
        payload = json.dumps(claims if claims is not None else document()).encode()
    return SignatureCheckedUntrustedOidcPayload(
        algorithm="RS256", kid="synthetic-kid", payload=payload
    )


def inspect(claims: object | None = None, **changes: object):
    params: dict[str, object] = {
        "expected_client_id": CLIENT,
        "expected_nonce": NONCE,
        "expected_role": ROLE,
        "now": NOW,
    }
    params.update(changes)
    return inspect_untrusted_cern_application_role(
        checked(claims),
        **params,  # type: ignore[arg-type]
    )


def app_roles(*roles: str) -> dict[str, object]:
    return {"resource_access": {CLIENT: {"roles": list(roles)}}}


def test_claimed_role_is_non_authoritative() -> None:
    result = inspect(document(**app_roles(ROLE), cern_roles=[ROLE]))
    assert isinstance(result, UntrustedCernRoleObservation)
    assert result.status == "claimed"
    assert result.authorization == "not_implemented"
    assert result.login == "not_implemented"
    assert not hasattr(result, "principal")
    assert not hasattr(result, "session")
    assert not hasattr(result, "authorized")
    assert not hasattr(result, "permissions")
    assert not hasattr(result, "identity")
    assert ROLE not in repr(result)
    assert CLIENT not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.status = "authorized"  # type: ignore[misc]


def test_missing_app_roles_do_not_imply_authorization() -> None:
    assert inspect().status == "absent"
    assert inspect(document(resource_access={})).status == "absent"
    assert inspect(document(resource_access={CLIENT: {}})).status == "absent"
    assert inspect(document(**app_roles())).status == "absent"


def test_only_exact_application_scoped_role_is_inspected() -> None:
    untrusted = document(
        resource_access={"another-client": {"roles": [ROLE]}},
        realm_access={"roles": [ROLE]},
        groups=[ROLE],
        roles=[ROLE],
        is_admin=True,
        preferred_username=ROLE,
    )
    assert inspect(untrusted).status == "absent"


def test_other_application_role_does_not_replace_required_role() -> None:
    doc = document(resource_access={CLIENT: {"roles": ["admin", "viewer"]}})
    assert inspect(doc).status == "absent"


def test_order_independent_duplicate_claim_list_matches() -> None:
    doc = document(**app_roles("viewer", ROLE), cern_roles=[ROLE, "viewer"])
    assert inspect(doc).status == "claimed"


@pytest.mark.parametrize(
    ("missing_mfa", "missing_loa", "status"),
    [
        (True, False, "mfa_required"),
        (False, True, "loa_required"),
        (True, True, "mfa_and_loa_required"),
    ],
)
def test_cern_missing_role_hints_deny_not_attest(
    missing_mfa: bool, missing_loa: bool, status: str
) -> None:
    doc = document(
        **app_roles("viewer"),
        cern_roles_missing_mfa=[ROLE] if missing_mfa else [],
        cern_roles_missing_loa=[ROLE] if missing_loa else [],
    )
    result = inspect(doc)
    assert result.status == status
    assert result.authorization == "not_implemented"


def test_missing_hint_for_another_role_cannot_override_grant() -> None:
    doc = document(**app_roles(ROLE), cern_roles_missing_mfa=["another-role"])
    assert inspect(doc).status == "claimed"


def test_absent_role_with_unrelated_missing_hints_is_absent() -> None:
    doc = document(cern_roles_missing_mfa=["other-role"])
    assert inspect(doc).status == "absent"


def test_optional_token_binding_is_enforced_before_role_inspection() -> None:
    digest = hashlib.sha256(TOKEN.encode()).digest()
    at_hash = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode("ascii")
    doc = document(**app_roles(ROLE), at_hash=at_hash)
    assert inspect(doc, expected_access_token=TOKEN).status == "claimed"
    with pytest.raises(OidcRoleClaimsError):
        inspect(doc)
    with pytest.raises(OidcRoleClaimsError):
        inspect(doc, expected_access_token="wrong-access-token")


def test_unknown_claims_cannot_grant_permission() -> None:
    doc = document(email="root@example.invalid", groups=[ROLE], permissions=[ROLE])
    result = inspect(doc)
    assert result.status == "absent"
    assert result.authorization == "not_implemented"
