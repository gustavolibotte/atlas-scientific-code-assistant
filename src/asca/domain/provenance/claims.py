"""Claims quoted from source versions and their append-only text checks."""

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from asca.domain.provenance.errors import ProvenanceInvariantError
from asca.domain.provenance.ids import (
    ClaimCheckId,
    ClaimId,
    IdKind,
    ProjectId,
    SourceVersionId,
    require_id,
)
from asca.domain.provenance.sources import SourceVersion
from asca.domain.provenance.values import (
    QUOTE_MAX,
    STATEMENT_MAX,
    Locator,
    optional_sha256,
    optional_text,
    require_enum,
    require_int,
    require_text,
    require_utc,
)

QUOTE_NORMALIZATION_VERSION = 1
_WHITESPACE_RE = re.compile(r"\s+")


def normalize_for_match(text: str) -> str:
    """NFKC, drop soft hyphens, collapse whitespace runs to one space, strip."""
    normalized = unicodedata.normalize("NFKC", text).replace("­", "")
    return _WHITESPACE_RE.sub(" ", normalized).strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AssertionOrigin(StrEnum):
    HUMAN = "human"
    AUTOMATED = "automated"


@dataclass(frozen=True, slots=True)
class Claim:
    """A verbatim quote from a source version. The quote is data, never instructions."""

    id: ClaimId
    project_id: ProjectId
    source_version_id: SourceVersionId
    quote: str
    locator: Locator
    statement: str | None
    extracted_by: AssertionOrigin
    recorded_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.CLAIM, self.id, "claim.id")
        require_id(IdKind.PROJECT, self.project_id, "claim.project_id")
        require_id(IdKind.SOURCE_VERSION, self.source_version_id, "claim.source_version_id")
        require_text("claim.quote", self.quote, max_len=QUOTE_MAX, multiline=True)
        if normalize_for_match(self.quote) == "":
            raise ProvenanceInvariantError(
                "R.claim.quote", "claim.quote must not be empty after normalization"
            )
        if not isinstance(self.locator, Locator):
            raise ProvenanceInvariantError("R.claim.locator", "claim.locator must be a Locator")
        optional_text("claim.statement", self.statement, max_len=STATEMENT_MAX, multiline=True)
        require_enum(AssertionOrigin, "claim.extracted_by", self.extracted_by)
        require_utc("claim.recorded_at", self.recorded_at)


class ClaimCheckOutcome(StrEnum):
    SOURCE_TEXT_CHECKED = "source_text_checked"
    MISMATCH = "mismatch"
    UNAVAILABLE = "unavailable"


class ClaimVerificationState(StrEnum):
    """Derived: the latest check's outcome, or NOT_CHECKED when there is no check."""

    NOT_CHECKED = "not_checked"
    SOURCE_TEXT_CHECKED = "source_text_checked"
    MISMATCH = "mismatch"
    UNAVAILABLE = "unavailable"


class CheckMethod(StrEnum):
    NORMALIZED_SUBSTRING = "normalized_substring"
    NOT_PERFORMED = "not_performed"


@dataclass(frozen=True, slots=True)
class ClaimCheck:
    id: ClaimCheckId
    project_id: ProjectId
    claim_id: ClaimId
    sequence: int
    outcome: ClaimCheckOutcome
    method: CheckMethod
    content_sha256: str | None
    detail: str | None
    checked_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.CLAIM_CHECK, self.id, "check.id")
        require_id(IdKind.PROJECT, self.project_id, "check.project_id")
        require_id(IdKind.CLAIM, self.claim_id, "check.claim_id")
        require_int("check.sequence", self.sequence, minimum=1)
        require_enum(ClaimCheckOutcome, "check.outcome", self.outcome)
        require_enum(CheckMethod, "check.method", self.method)
        optional_sha256("check.content_sha256", self.content_sha256)
        optional_text("check.detail", self.detail, max_len=STATEMENT_MAX, multiline=True)
        require_utc("check.checked_at", self.checked_at)
        if self.outcome is ClaimCheckOutcome.UNAVAILABLE:
            legal = (
                self.method is CheckMethod.NOT_PERFORMED
                and self.content_sha256 is None
                and self.detail is not None
            )
        else:
            legal = self.method is CheckMethod.NORMALIZED_SUBSTRING and (
                self.content_sha256 is not None
            )
        if not legal:
            raise ProvenanceInvariantError(
                "R.check.shape",
                f"outcome {self.outcome.value} is incompatible with method {self.method.value}, "
                "content hash or detail",
            )

    @property
    def state(self) -> ClaimVerificationState:
        return ClaimVerificationState(self.outcome.value)


def check_quote(
    claim: Claim,
    version: SourceVersion,
    text: str,
    *,
    check_id: ClaimCheckId,
    sequence: int,
    checked_at: datetime,
) -> ClaimCheck:
    """Check a claim's quote against source text whose hash matches the version."""
    if version.content_sha256 is None:
        raise ProvenanceInvariantError(
            "R.check.no_content", f"version {version.id} has no content hash"
        )
    if not isinstance(text, str) or sha256_text(text) != version.content_sha256:
        raise ProvenanceInvariantError(
            "R.check.content_hash", f"text does not match the content hash of {version.id}"
        )
    if claim.source_version_id != version.id:
        raise ProvenanceInvariantError(
            "R.check.version", f"claim {claim.id} does not quote version {version.id}"
        )
    found = normalize_for_match(claim.quote) in normalize_for_match(text)
    return ClaimCheck(
        id=check_id,
        project_id=claim.project_id,
        claim_id=claim.id,
        sequence=sequence,
        outcome=ClaimCheckOutcome.SOURCE_TEXT_CHECKED if found else ClaimCheckOutcome.MISMATCH,
        method=CheckMethod.NORMALIZED_SUBSTRING,
        content_sha256=version.content_sha256,
        detail=None,
        checked_at=checked_at,
    )


def unavailable_check(
    claim_id: ClaimId,
    *,
    reason: str,
    check_id: ClaimCheckId,
    sequence: int,
    checked_at: datetime,
    project_id: ProjectId,
) -> ClaimCheck:
    return ClaimCheck(
        id=check_id,
        project_id=project_id,
        claim_id=claim_id,
        sequence=sequence,
        outcome=ClaimCheckOutcome.UNAVAILABLE,
        method=CheckMethod.NOT_PERFORMED,
        content_sha256=None,
        detail=reason,
        checked_at=checked_at,
    )
