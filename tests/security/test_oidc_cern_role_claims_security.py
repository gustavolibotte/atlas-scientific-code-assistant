"""Adversarial offline CERN role claims checks; never test real credentials."""

from __future__ import annotations

import json
import socket
from dataclasses import replace

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_role_claims import inspect_untrusted_cern_application_role
from asca.domain.oidc_jws import SignatureCheckedUntrustedOidcPayload
from asca.domain.oidc_role_claims import OidcRoleClaimsError

NOW = 1_800_000_000
CLIENT = "asca-glibotte-dev"
ROLE = "asca-developer"
NONCE = "synthetic_nonce_01234567890123456789012"


def document(**changes: object) -> dict[str, object]:
    d: dict[str, object] = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "synthetic-subject",
        "aud": CLIENT,
        "nonce": NONCE,
        "iat": NOW - 10,
        "exp": NOW + 300,
        "resource_access": {CLIENT: {"roles": [ROLE]}},
    }
    d.update(changes)
    return d


def observe(
    data: object | None = None,
    *,
    raw: bytes | None = None,
    **changes: object,
):
    payload = raw
    if payload is None:
        payload = json.dumps(data if data is not None else document()).encode()
    signed = SignatureCheckedUntrustedOidcPayload(
        algorithm="RS256", kid="synthetic-kid", payload=payload
    )
    options: dict[str, object] = {
        "expected_client_id": CLIENT,
        "expected_role": ROLE,
        "expected_nonce": NONCE,
        "now": NOW,
    }
    options.update(changes)
    return inspect_untrusted_cern_application_role(signed, **options)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        [],
        True,
        12,
        {CLIENT: None},
        {CLIENT: []},
        {CLIENT: {"roles": None}},
        {CLIENT: {"roles": "asca-developer"}},
        {CLIENT: {"roles": [ROLE, ROLE]}},
        {CLIENT: {"roles": [ROLE, 3]}},
        {CLIENT: {"roles": [ROLE, True]}},
        {CLIENT: {"roles": [ROLE, "admin permission"]}},
        {CLIENT: {"roles": [ROLE, "a" * 129]}},
        {CLIENT: {"roles": ["x"] * 65}},
    ],
)
def test_malformed_scoped_role_structure_rejected(bad: object) -> None:
    with pytest.raises(OidcRoleClaimsError):
        observe(document(resource_access=bad))


def test_other_client_entries_are_not_promoted_to_authority() -> None:
    data = document(resource_access={CLIENT: {"roles": [ROLE]}, "another-client": 1})
    assert observe(data).status == "claimed"


@pytest.mark.parametrize(
    "field",
    ["cern_roles", "cern_roles_missing_mfa", "cern_roles_missing_loa"],
)
@pytest.mark.parametrize(
    "bad",
    [None, "", ROLE, 1, True, [ROLE, ROLE], [ROLE, None], [ROLE, 7], ["a" * 129]],
)
def test_malformed_extension_role_lists_rejected(field: str, bad: object) -> None:
    with pytest.raises(OidcRoleClaimsError):
        observe(document(**{field: bad}))


@pytest.mark.parametrize("missing", ["cern_roles_missing_mfa", "cern_roles_missing_loa"])
def test_contradictory_granted_and_missing_role_rejected(missing: str) -> None:
    with pytest.raises(OidcRoleClaimsError, match="Conflicting"):
        observe(document(**{missing: [ROLE]}))


def test_cern_roles_duplicate_mismatch_rejected() -> None:
    with pytest.raises(OidcRoleClaimsError, match="Inconsistent"):
        observe(document(cern_roles=["viewer"]))
    with pytest.raises(OidcRoleClaimsError, match="Inconsistent"):
        observe(document(resource_access={}, cern_roles=[ROLE]))


@pytest.mark.parametrize(
    "changes",
    [
        {"expected_client_id": "another-client"},
        {"expected_client_id": ""},
        {"expected_client_id": "other client"},
        {"expected_client_id": False},
        {"expected_role": ""},
        {"expected_role": "root admin"},
        {"expected_role": 12},
        {"expected_nonce": "another-nonce"},
        {"now": 0},
        {"now": "2026"},
    ],
)
def test_wrong_policy_or_oidc_binding_never_grants(changes: dict[str, object]) -> None:
    with pytest.raises(OidcRoleClaimsError):
        observe(document(), **changes)


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://attacker.invalid"},
        {"aud": "other-client"},
        {"nonce": "wrong"},
        {"exp": NOW - 300},
        {"iat": NOW + 300},
        {"at_hash": "malformed"},
        {"c_hash": "unsupported"},
        {"s_hash": "unsupported"},
    ],
)
def test_untrusted_invalid_oidc_claims_are_rejected_first(claims: dict[str, object]) -> None:
    with pytest.raises(OidcRoleClaimsError):
        observe(document(**claims))


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"{",
        b"not-json",
        b'{"iss":"x","iss":"y"}',
        b'{"iss":"x","resource_access":{"a":{"roles":[]},"a":{"roles":[]}}}',
        b'{"iss":"x","cern_roles":["a"],"cern_roles":["b"]}',
    ],
)
def test_invalid_json_and_duplicate_members_fail_closed(raw: bytes) -> None:
    with pytest.raises(OidcRoleClaimsError):
        observe(raw=raw)


def test_forged_signature_wrapper_is_not_a_trusted_source() -> None:
    raw = json.dumps(document()).encode()
    wrapped = SignatureCheckedUntrustedOidcPayload(
        algorithm="RS256", kid="synthetic-kid", payload=raw
    )
    assert observe(raw=raw).status == "claimed"
    with pytest.raises(OidcRoleClaimsError):
        inspect_untrusted_cern_application_role(
            replace(wrapped, algorithm="none"),
            expected_client_id=CLIENT,
            expected_role=ROLE,
            expected_nonce=NONCE,
            now=NOW,
        )
    # A manually constructed RS256 wrapper remains forgeable. Its 'claimed'
    # result is deliberately not a grant of permissions or user identity.
    assert not hasattr(observe(raw=raw), "authenticated")


def test_no_network_or_sensitive_error_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected network access")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    private_marker = "synthetic_secret_marker_12"
    with pytest.raises(OidcRoleClaimsError) as raised:
        observe(document(nonce=private_marker, cern_roles=["viewer"]))
    assert private_marker not in str(raised.value)
    assert private_marker not in repr(raised.value)
