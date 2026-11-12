"""Typed record identifiers: ``<3-letter kind>_<32 lowercase hex>``."""

import re
from enum import StrEnum
from typing import NewType

from asca.domain.provenance.errors import ProvenanceInvariantError


class IdKind(StrEnum):
    PROJECT = "prj"
    SOURCE = "src"
    SOURCE_VERSION = "ver"
    SUPERSESSION = "sup"
    CLAIM = "clm"
    CLAIM_CHECK = "chk"
    DECISION = "dec"
    EVIDENCE_LINK = "evl"
    WORKSPACE_REVISION = "rev"
    SYMBOL = "sym"
    IMPLEMENTATION_LINK = "iml"
    TEST_CASE = "tst"
    VERIFICATION_LINK = "vfl"
    ENVIRONMENT = "env"
    RUN = "run"
    APPROVAL = "apr"


ProjectId = NewType("ProjectId", str)
SourceId = NewType("SourceId", str)
SourceVersionId = NewType("SourceVersionId", str)
SupersessionId = NewType("SupersessionId", str)
ClaimId = NewType("ClaimId", str)
ClaimCheckId = NewType("ClaimCheckId", str)
DecisionId = NewType("DecisionId", str)
EvidenceLinkId = NewType("EvidenceLinkId", str)
RevisionId = NewType("RevisionId", str)
SymbolId = NewType("SymbolId", str)
ImplementationLinkId = NewType("ImplementationLinkId", str)
TestCaseId = NewType("TestCaseId", str)
VerificationLinkId = NewType("VerificationLinkId", str)
EnvironmentId = NewType("EnvironmentId", str)
RunId = NewType("RunId", str)
ApprovalId = NewType("ApprovalId", str)

ID_RE = re.compile(r"(?P<kind>[a-z]{3})_(?P<body>[0-9a-f]{32})")


def require_id(kind: IdKind, value: object, field: str) -> str:
    """Return ``value`` when it is a well-formed identifier of ``kind``."""
    if not isinstance(value, str):
        raise ProvenanceInvariantError("R.id.format", f"{field} must be a string identifier")
    match = ID_RE.fullmatch(value)
    if match is None:
        raise ProvenanceInvariantError(
            "R.id.format", f"{field} must match <kind>_<32 lowercase hex>"
        )
    if match.group("kind") != kind.value:
        raise ProvenanceInvariantError("R.id.kind", f"{field} must be a {kind.value} identifier")
    return value


def optional_id(kind: IdKind, value: object, field: str) -> str | None:
    return None if value is None else require_id(kind, value, field)


def make_id(kind: IdKind, hex32: str) -> str:
    return require_id(kind, f"{kind.value}_{hex32}", "id")


def id_kind(value: str) -> IdKind:
    match = ID_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ProvenanceInvariantError("R.id.format", "value is not an identifier")
    try:
        return IdKind(match.group("kind"))
    except ValueError:
        raise ProvenanceInvariantError("R.id.kind", "identifier has an unknown kind") from None
