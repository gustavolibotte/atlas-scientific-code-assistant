"""Strict offline inspection of claimed CERN application-specific OIDC roles.

This component reuses the signed-payload and OIDC claims checks, but their
input wrappers, client ID, nonce and clock can be forged by Python callers.
It must never be used to authorize access or issue an ASCA session. A future
reviewed host must integrate the policy *inside* its trusted token pipeline.
"""

from __future__ import annotations

import re

from asca.application.oidc_claims import (
    _parse_claims,
    validate_untrusted_oidc_id_token_claims,
)
from asca.domain.oidc_claims import OidcClaimsError
from asca.domain.oidc_jws import SignatureCheckedUntrustedOidcPayload
from asca.domain.oidc_role_claims import (
    OidcRoleClaimsError,
    RoleClaimStatus,
    UntrustedCernRoleObservation,
)

_CLIENT_ID = re.compile(r"[A-Za-z0-9._~:-]{1,256}\Z", re.ASCII)
_ROLE = re.compile(r"[A-Za-z0-9._~:-]{1,128}\Z", re.ASCII)
_MAX_ROLES = 64


def _role_list(value: object) -> frozenset[str]:
    """Reject ambiguous, malformed or oversized role lists, including duplicates."""
    if (
        not isinstance(value, list)
        or len(value) > _MAX_ROLES
        or any(not isinstance(role, str) or _ROLE.fullmatch(role) is None for role in value)
        or len(set(value)) != len(value)
    ):
        raise OidcRoleClaimsError("Invalid CERN application role-claim structure")
    return frozenset(value)


def _application_roles(document: dict[str, object], client_id: str) -> frozenset[str]:
    resource_access = document.get("resource_access", {})
    if not isinstance(resource_access, dict):
        raise OidcRoleClaimsError("Invalid CERN application role-claim structure")
    scoped = resource_access.get(client_id, {})
    if not isinstance(scoped, dict):
        raise OidcRoleClaimsError("Invalid CERN application role-claim structure")
    scoped_roles = _role_list(scoped.get("roles", []))
    if "cern_roles" in document:
        # CERN documents cern_roles as an exact duplicate of the application's
        # scoped roles; never use it to elevate an absent scoped role.
        duplicate = _role_list(document["cern_roles"])
        if duplicate != scoped_roles:
            raise OidcRoleClaimsError("Inconsistent CERN application role claims")
    return scoped_roles


def inspect_untrusted_cern_application_role(
    checked: SignatureCheckedUntrustedOidcPayload,
    *,
    expected_client_id: str,
    expected_nonce: str,
    expected_role: str,
    now: int,
    expected_access_token: str | None = None,
) -> UntrustedCernRoleObservation:
    """Inspect one explicitly named role, after local OIDC claims validation.

    Roles from other clients, realm roles, groups, user names and free-form
    extensions are never accepted as the target application role. Provider
    MFA/LoA missing-role hints are *denial* signals, not proof that a user met
    those requirements. No credential or personal field leaves this function.

    The result is merely a claim observation, even when status is ``claimed``.
    No principal/session/capability is created; direct callers can forge inputs.
    """
    if (
        type(checked) is not SignatureCheckedUntrustedOidcPayload
        or type(expected_client_id) is not str
        or _CLIENT_ID.fullmatch(expected_client_id) is None
        or type(expected_role) is not str
        or _ROLE.fullmatch(expected_role) is None
    ):
        raise OidcRoleClaimsError("Invalid CERN application role-inspection policy")
    try:
        validate_untrusted_oidc_id_token_claims(
            checked,
            expected_client_id=expected_client_id,
            expected_nonce=expected_nonce,
            now=now,
            expected_access_token=expected_access_token,
        )
        document = _parse_claims(checked.payload)
    except (OidcClaimsError, TypeError, ValueError, AttributeError):
        raise OidcRoleClaimsError("CERN OIDC role claims did not pass validation") from None

    assigned = _application_roles(document, expected_client_id)
    # The documented missing_* claims explain why an assigned role was not
    # granted. They are not independent MFA/LoA attestations.
    needs_mfa = _role_list(document.get("cern_roles_missing_mfa", []))
    needs_loa = _role_list(document.get("cern_roles_missing_loa", []))
    present = expected_role in assigned
    missing_mfa = expected_role in needs_mfa
    missing_loa = expected_role in needs_loa
    if present and (missing_mfa or missing_loa):
        raise OidcRoleClaimsError("Conflicting CERN application role claims")
    status: RoleClaimStatus
    if missing_mfa and missing_loa:
        status = "mfa_and_loa_required"
    elif missing_mfa:
        status = "mfa_required"
    elif missing_loa:
        status = "loa_required"
    else:
        status = "claimed" if present else "absent"
    return UntrustedCernRoleObservation(status=status)
