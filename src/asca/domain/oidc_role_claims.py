"""Non-authoritative observation of CERN application role claims.

This module contains no permissions, verified identities, or login capabilities.
Ordinary Python objects can be forged; a claim observation is never a grant.
"""

from dataclasses import dataclass, field
from typing import Literal

RoleClaimStatus = Literal[
    "claimed",
    "absent",
    "mfa_required",
    "loa_required",
    "mfa_and_loa_required",
]


class OidcRoleClaimsError(ValueError):
    """Sanitized failure of strict, offline CERN role-claims inspection."""


@dataclass(frozen=True, slots=True)
class UntrustedCernRoleObservation:
    """Observed role-claim status without source attestation or authorization.

    ``claimed`` only means that a claim was present in supplied data; it does
    not prove identity, group membership, CERN assurance, or access rights.
    """

    status: RoleClaimStatus
    authorization: Literal["not_implemented"] = field(default="not_implemented", init=False)
    login: Literal["not_implemented"] = field(default="not_implemented", init=False)
